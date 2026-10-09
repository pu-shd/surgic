"""Pipeline orchestration: ingest -> (analyzer worker) extract + Phase A ->
Phase B (LLM, here) -> (analyzer worker) redact -> (scanner worker) post-scan
-> stage -> release -> signed manifest.

This process never parses a document: it copies bytes, hashes, talks to the
loopback LLM with masked text, and signs. Parsing happens in isolated workers
(see ``worker.py``).

Fail-closed:
* any per-document error quarantines that document;
* any environment/LLM-isolation error aborts the run;
* outputs are staged on the RAM disk and released to the share only after
  every document has been processed, so an aborted run releases nothing. An
  aborted run still writes a signed manifest that says so.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any

from . import netguard
from .audit.manifest import SCHEMA, sha256_file, write_signed
from .audit.signing import Signer
from .detect.contextual import llm_accept
from .llm.guard import tripwire
from .detect.spans import Span
from .extract import SUPPORTED_EXT
from .llm.backend import LLMBackend
from .logging_safe import RunKey, SafeError, log_event
from .paths import is_under
from .worker import DocWorker, InProcessClient, ScanWorker, WorkerClient, WorkerFailure

FATAL_CODES = {
    "llm_unload_unverified", "llm_reset_failed", "llm_port_in_use", "llm_server_exited",
    "llm_start_timeout", "secret_scanner_missing", "gitleaks_failed", "trufflehog_failed",
    "gitleaks_inconsistent", "trufflehog_inconsistent", "output_verify_failed",
    "in_process_egress_attempted", "worker_protocol_error", "worker_bad_op", "sandbox_unavailable",
}
MAX_RESCANS = 2
KINDS = {"pdf", "image", "xlsx", "text"}
_PLACEHOLDER = re.compile(r"\[[A-Z0-9_]+_\d+\]")
_COUNT_KEY = re.compile(r"(?:regex|presidio|llm):[A-Z0-9_]{1,48}")
_RULE_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,96}")
_CHECK_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,96}")


@dataclass
class DocRecord:
    doc_id: str
    kind: str = ""
    input_sha256: str = ""
    input_bytes: int = 0
    input_path: str | None = None
    status: str = "pending"
    reason: str = ""
    output_dir: str = ""   # relative to <share>/<run_id>/; "" until released
    name_mode: str = ""    # "opaque" | "original" | "opaque_fallback" (clean documents)
    outputs: list[dict] = field(default_factory=list)
    phase_a: dict[str, int] = field(default_factory=dict)
    phase_b: dict = field(default_factory=dict)
    token_hmacs: list[str] = field(default_factory=list)
    regions: int = 0
    ocr_pages: int = 0
    rescans: int = 0
    injection_rules: dict[str, int] = field(default_factory=dict)  # tripwire hits by rule id
    needs_review: bool = False
    postscan: dict = field(default_factory=dict)
    staged: list[str] = field(default_factory=list)  # RAM-disk copies awaiting release
    target_dir: str = ""                             # planned output_dir (set when staged)

    def public(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("staged", "target_dir")}
        if d["input_path"] is None:
            d.pop("input_path")
        return d


def span_counts(spans: list[Span]) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in spans:
        k = f"{s.source}:{s.category}"
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def software_versions() -> dict[str, str]:
    out = {"python": platform.python_version(), "platform": platform.platform()}
    for pkg in ("surgic", "pymupdf", "presidio-analyzer", "spacy", "google-re2", "hyperscan",
                "openpyxl", "pdfplumber", "cryptography", "pillow"):
        try:
            out[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            out[pkg] = "absent"
    return out


def enumerate_inputs(root: str) -> list[tuple[Path, str]]:
    """Every entry under ``root`` with a skip reason ("" = process it).
    Nothing is dropped silently: hidden files, hidden directories (not
    descended into, e.g. NAS snapshot trees) and symlinks are listed too."""
    out: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            p = Path(dirpath, d)
            if p.is_symlink():
                out.append((p, "symlink"))
            elif d.startswith("."):
                out.append((p, "hidden_dir"))
            else:
                keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            p = Path(dirpath, f)
            if p.is_symlink():
                out.append((p, "symlink"))
            elif f.startswith("."):
                out.append((p, "hidden_file"))
            elif p.suffix.lower() not in SUPPORTED_EXT:
                out.append((p, "unsupported_extension"))
            else:
                out.append((p, ""))
    return out


def _int(v: Any, lo: int = 0) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < lo:
        raise WorkerFailure("safe", "worker_protocol_error")
    return v


def _counts(d: Any, key_re: re.Pattern) -> dict[str, int]:
    if not isinstance(d, dict) or not all(isinstance(k, str) and key_re.fullmatch(k) for k in d):
        raise WorkerFailure("safe", "worker_protocol_error")
    return {k: _int(v) for k, v in sorted(d.items())}


def _strs(v: Any) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise WorkerFailure("safe", "worker_protocol_error")
    return v


class Pipeline:
    def __init__(self, cfg, backend: LLMBackend, phase_a=None, ocr=None, scanners=None,
                 signer: Signer | None = None, model_sha256: str = "", environment: dict | None = None,
                 analyzer: WorkerClient | None = None, scanner: WorkerClient | None = None,
                 airgap: dict | None = None) -> None:
        self.cfg = cfg
        self.backend = backend
        # In-process workers are a test convenience and need an explicit opt-in.
        self.analyzer = analyzer or InProcessClient(DocWorker(cfg, phase_a, ocr))
        self.scanner = scanner or InProcessClient(ScanWorker(phase_a, ocr, scanners))
        assert signer is not None
        self.signer = signer
        self.model_sha256 = model_sha256
        self.environment = environment or {}
        self.airgap = airgap or {}
        self.info: dict = {}
        self.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]

    # ------------------------------------------------------------------
    def run(self, input_dir: str, output_dir: str, workspace: str) -> tuple[str, dict]:
        started = int(time.time())
        entries = enumerate_inputs(input_dir)
        records: list[DocRecord] = []
        work_root = Path(workspace, self.run_id)
        work_root.mkdir(parents=True, exist_ok=False)
        release_dir = Path(output_dir, self.run_id)
        if release_dir.exists():
            raise SafeError("run_dir_exists")
        aborted = ""
        try:
            self.analyzer.start(str(work_root))
            self.scanner.start(str(work_root))
            self.info = self._info(self.analyzer.call("info"))
            supported = []
            for i, (p, skip) in enumerate(entries):
                if skip:
                    rec = self._new_record(i, p, input_dir, hash_it=skip not in ("symlink", "hidden_dir"))
                    rec.status, rec.reason = "skipped", skip
                    records.append(rec)
                else:
                    supported.append((i, p))
            bs = self.cfg.llm.batch_size
            for b in range(0, len(supported), bs):
                batch = supported[b:b + bs]
                self.backend.start()
                for i, p in batch:
                    rec = self._new_record(i, p, input_dir)
                    records.append(rec)
                    if rec.status == "pending":
                        self._process(rec, p, work_root, p.relative_to(input_dir))
                    self.backend.reset_context()
                self.backend.unload()
                if self.backend.is_loaded():
                    raise SafeError("llm_unload_unverified", backend=self.backend.name)
            if netguard.attempts:
                raise SafeError("in_process_egress_attempted", count=len(netguard.attempts))
            self._release(records, release_dir)
        except SafeError as e:
            aborted = e.code
            raise
        except BaseException as e:
            aborted = "error:" + type(e).__name__
            raise
        finally:
            try:
                if self.backend.is_loaded():
                    self.backend.unload()
            finally:
                for w in (self.analyzer, self.scanner):
                    w.stop()
                shutil.rmtree(work_root, ignore_errors=True)
                if aborted:
                    self._write_aborted(records, started, output_dir, aborted)

        records.sort(key=lambda r: r.doc_id)
        manifest = self._manifest(records, started)
        mpath = self._write_manifest(manifest, output_dir)
        log_event("run_complete", run_id=self.run_id, documents=len(records),
                  clean=manifest["summary"]["clean"], quarantined=manifest["summary"]["quarantined"])
        return mpath, manifest

    def _info(self, info: dict) -> dict:
        sw = info.get("software", {})
        if not (isinstance(info.get("patterns_sha256"), str) and isinstance(info.get("hyperscan_active"), bool)
                and isinstance(info.get("presidio_model"), str) and isinstance(sw, dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in sw.items())):
            raise WorkerFailure("safe", "worker_protocol_error")
        return info

    def _new_record(self, i: int, p: Path, input_dir: str, hash_it: bool = True) -> DocRecord:
        rec = DocRecord(doc_id=f"{i:05d}-unread")
        try:
            if hash_it:
                sha = sha256_file(p)
                rec = DocRecord(doc_id=f"{i:05d}-{sha[:12]}", input_sha256=sha, input_bytes=p.stat().st_size)
            else:
                rec = DocRecord(doc_id=f"{i:05d}-unhashed")
        except OSError:
            rec.status, rec.reason = "quarantined", "input_unreadable"
        if self.cfg.storage.record_input_paths:
            rec.input_path = str(p.relative_to(input_dir))
        return rec

    # ------------------------------------------------------------------
    def _process(self, rec: DocRecord, src: Path, work_root: Path, rel: Path | None = None) -> None:
        wd = work_root / rec.doc_id
        (wd / "in").mkdir(parents=True)
        known: set[str] = set()
        doc_key = RunKey()  # per document: identical values in two documents are not linkable
        try:
            local = wd / "in" / ("input" + src.suffix.lower())
            shutil.copyfile(src, local)
            if sha256_file(local) != rec.input_sha256:
                raise SafeError("input_changed_during_copy")
            a = self.analyzer.call("analyze", doc_id=rec.doc_id, path=str(local), work_dir=str(wd))
            if a.get("kind") not in KINDS or not isinstance(a.get("masked_text"), str):
                raise WorkerFailure("safe", "worker_protocol_error")
            rec.kind, rec.ocr_pages = a["kind"], _int(a.get("ocr_pages"))
            rec.phase_a = _counts(a.get("phase_a"), _COUNT_KEY)

            # Tripwire: text addressed to an AI model, before the model sees it.
            rec.injection_rules = tripwire(a["masked_text"])
            if rec.injection_rules:
                if self.cfg.llm.injection_policy == "quarantine":
                    rec.status, rec.reason = "quarantined", "injection_suspected"
                    return
                rec.needs_review = True
            accepted, stats = llm_accept(a["masked_text"], self.backend, self.cfg.llm.chunk_chars,
                                         self.cfg.llm.chunk_overlap, canaries=self.cfg.llm.canaries,
                                         canary_retries=self.cfg.llm.canary_retries)
            rec.phase_b = {k: v for k, v in stats.__dict__.items()}
            # Accepted strings without placeholders are original text: the
            # post-scan checks them independently of what the analyzer reports.
            own_known = {t for t in accepted if not _PLACEHOLDER.search(t)}

            out_dir = wd / "out"
            extra: list[str] = []
            prev_extra = 0
            passed = False
            for attempt in range(MAX_RESCANS + 1):
                r = self.analyzer.call("render", doc_id=rec.doc_id, accepted=accepted, extra_values=extra,
                                       out_dir=str(out_dir))
                files = self._outputs(r, rec.doc_id, out_dir)
                rec.regions = _int(r.get("regions"))
                extra_spans = _int(r.get("extra_spans"))
                if attempt and extra_spans <= prev_extra:
                    break  # feedback values are not in the source: cannot fix, quarantine
                prev_extra = extra_spans
                known = set(_strs(r.get("known_values"))) | own_known
                rep = self.scanner.call("scan", primary=r["primary"], sidecar=r["sidecar"],
                                        known_values=sorted(known), scratch_dir=str(wd))
                pub = rep.get("public", {})
                if not (isinstance(rep.get("passed"), bool) and isinstance(pub, dict)
                        and pub.get("passed") is rep["passed"]):
                    raise WorkerFailure("safe", "worker_protocol_error")
                rec.postscan = {"passed": rep["passed"], "checks": _counts(pub.get("checks"), _CHECK_KEY),
                                "rules": _counts(pub.get("rules"), _RULE_KEY)}
                passed = rep["passed"]
                if passed:
                    break
                new = [v for v in _strs(rep.get("new_values")) if v.strip() and v not in extra]
                if not new or attempt == MAX_RESCANS:
                    break
                rec.rescans += 1
                extra += new
            rec.token_hmacs = sorted({doc_key.token(v) for v in known})
            if not passed:
                rec.status, rec.reason = "quarantined", "postscan_failed"
                return

            target_dir, names = self._plan_names(rec, rel, files, known)
            stage = work_root / "_release" / rec.doc_id
            stage.mkdir(parents=True)
            rec.target_dir = target_dir
            for f in files:
                target = stage / names[f.name]
                shutil.copyfile(f, target)
                if sha256_file(f) != sha256_file(target):
                    raise SafeError("output_verify_failed")
                rec.staged.append(str(target))
            rec.status = "clean"
        except WorkerFailure as e:
            if e.kind == "safe" and e.code in FATAL_CODES:
                raise SafeError(e.code) from None
            if e.kind in ("crashed", "timeout"):
                self.analyzer.restart()
                self.scanner.restart()
            rec.status, rec.reason = "quarantined", e.code
        except SafeError as e:
            if e.code in FATAL_CODES:
                raise
            rec.status, rec.reason = "quarantined", e.code
        except Exception as e:  # noqa: BLE001
            rec.status, rec.reason = "quarantined", "error:" + type(e).__name__
        finally:
            known.clear()
            doc_key.wipe()
            try:
                self.analyzer.call("forget", doc_id=rec.doc_id)
            except WorkerFailure:
                pass
            shutil.rmtree(wd, ignore_errors=True)
            if rec.status != "clean":
                rec.staged.clear()
            log_event("document", doc_id=rec.doc_id, status=rec.status, reason=rec.reason or None,
                      regions=rec.regions)

    def _plan_names(self, rec: DocRecord, rel: Path | None, files: list[Path],
                    known: set[str]) -> tuple[str, dict[str, str]]:
        """Output directory (relative to the run directory) and released file
        names. Opaque: <doc_id>/<doc_id>.redacted.<ext>. Original: the input's
        folders and name, each component redacted by the analyzer, e.g.
        Clients/REDACTED_VALUE/memo.pdf.redacted.pdf. A name that cannot be
        made safe falls back to the opaque layout for that document."""
        opaque = {f.name: f.name for f in files}
        if self.cfg.storage.output_names != "original" or rel is None:
            rec.name_mode = "opaque"
            return rec.doc_id, opaque
        values = sorted(v for v in known if v.strip())
        parts = []
        for comp in rel.parts:
            r = self.analyzer.call("redact_name", text=comp, values=values)
            name = r.get("name")
            if not self._safe_component(name, values):
                rec.name_mode = "opaque_fallback"
                return rec.doc_id, opaque
            parts.append(name)
        base = parts[-1]
        names = {}
        for f in files:
            ext = f.name.rsplit(".redacted.", 1)[1]
            names[f.name] = f"{base}.redacted.{ext}"
        if len(set(names.values())) != len(names) or any(len(n.encode()) > 255 for n in names.values()):
            rec.name_mode = "opaque_fallback"
            return rec.doc_id, opaque
        rec.name_mode = "original"
        return "/".join(parts[:-1]), names

    @staticmethod
    def _safe_component(name: Any, values: list[str]) -> bool:
        if not isinstance(name, str) or not name or name in (".", "..") or name.startswith("."):
            return False
        if "/" in name or "\x00" in name or len(name.encode()) > 200:
            return False
        low = name.lower()
        return not any(len(v.strip()) >= 4 and v.strip().lower() in low for v in values)

    @staticmethod
    def _outputs(r: dict, doc_id: str, out_dir: Path) -> list[Path]:
        """Worker-reported output paths: must be our own names, regular files,
        inside this document's output directory."""
        names = re.compile(re.escape(doc_id) + r"\.redacted\.(?:pdf|xlsx|txt)")
        files = [Path(f) for f in _strs(r.get("files"))]
        prim, side = r.get("primary"), r.get("sidecar")
        if not files or str(prim) not in map(str, files) or str(side) not in map(str, files):
            raise WorkerFailure("safe", "worker_protocol_error")
        for f in files:
            if (not names.fullmatch(f.name) or f.parent != out_dir or f.is_symlink()
                    or not f.is_file() or not is_under(str(f), str(out_dir))):
                raise WorkerFailure("safe", "worker_protocol_error")
        return files

    def _release(self, records: list[DocRecord], release_dir: Path) -> None:
        """Copy staged outputs to the share and verify every byte arrived."""
        taken: set[str] = set()
        for rec in records:
            if rec.status != "clean":
                continue
            planned = [f"{rec.target_dir}/{Path(f).name}".lstrip("/") for f in rec.staged]
            if rec.name_mode == "original" and any(p in taken for p in planned):
                # Two inputs whose names redact to the same output name.
                rec.name_mode, rec.target_dir = "opaque_fallback", rec.doc_id
                renamed = []
                for f in rec.staged:
                    ext = Path(f).name.rsplit(".redacted.", 1)[1]
                    new = Path(f).with_name(f"{rec.doc_id}.redacted.{ext}")
                    os.replace(f, new)
                    renamed.append(str(new))
                rec.staged = renamed
            rec.output_dir = rec.target_dir
            dest = release_dir / rec.output_dir if rec.output_dir else release_dir
            if rec.name_mode == "original":
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.mkdir(parents=True, exist_ok=False)
            for f in rec.staged:
                target = dest / Path(f).name
                if target.exists() or not is_under(str(target), str(release_dir)):
                    raise SafeError("output_verify_failed")
                taken.add(f"{rec.output_dir}/{target.name}".lstrip("/"))
                shutil.copyfile(f, target)
                h_local, h_remote = sha256_file(f), sha256_file(target)
                if h_local != h_remote:
                    raise SafeError("output_verify_failed")
                rec.outputs.append({"name": target.name, "sha256": h_remote, "bytes": target.stat().st_size})
            rec.staged.clear()

    # ------------------------------------------------------------------
    def _write_manifest(self, manifest: dict, output_dir: str) -> str:
        mdir = Path(output_dir, "manifests")
        mdir.mkdir(parents=True, exist_ok=True)
        mpath, _ = write_signed(manifest, mdir / f"{self.run_id}.manifest.json", self.signer)
        (mdir / "pubkey.pem").write_bytes(self.signer.public_pem())
        return mpath

    def _write_aborted(self, records: list[DocRecord], started: int, output_dir: str, code: str) -> None:
        for r in records:
            if r.status in ("clean", "pending"):
                r.status, r.reason = "withheld", "run_aborted"
        records.sort(key=lambda r: r.doc_id)
        manifest = self._manifest(records, started)
        manifest["aborted"] = code if re.fullmatch(r"(?:error:)?[A-Za-z0-9_]{1,64}", code) else "aborted"
        try:
            self._write_manifest(manifest, output_dir)
        except Exception:  # noqa: BLE001 - never mask the original failure
            log_event("aborted_manifest_unwritten", status="error")

    def _manifest(self, records: list[DocRecord], started: int) -> dict:
        summary = {s: sum(1 for r in records if r.status == s)
                   for s in ("clean", "quarantined", "skipped", "withheld")}
        summary["needs_review"] = sum(1 for r in records if r.status == "clean" and r.needs_review)
        summary["total"] = len(records)
        security = self.cfg.security_flags()
        security["isolation"] = (self.analyzer.isolation if self.analyzer.isolation == self.scanner.isolation
                                 else "mixed")
        security["model_allowlisted"] = bool(self.model_sha256) and self.model_sha256 in set(self.cfg.llm.model_sha256)
        security["in_process_egress_attempts"] = len(netguard.attempts)
        return {
            "schema": SCHEMA,
            "run_id": self.run_id,
            "started_at": started,
            "finished_at": int(time.time()),
            "aborted": "",
            "airgap": self.airgap,
            "host": {"node": platform.node(), "machine": platform.machine(),
                     "os": platform.mac_ver()[0] or platform.system()},
            "software": self.info.get("software", {}),
            "config_sha256": self.cfg.source_sha256,
            "security": security,
            "patterns_sha256": self.info.get("patterns_sha256", ""),
            "hyperscan_active": self.info.get("hyperscan_active", False),
            "presidio_model": self.info.get("presidio_model", ""),
            "llm": {**self.backend.identity(), "model_sha256": self.model_sha256,
                    "batch_size": self.cfg.llm.batch_size, "unloads": self.backend.unload_count,
                    "context_resets": self.backend.reset_count},
            "environment": self.environment,
            "token_hmac": "HMAC-SHA256 with an ephemeral per-document key (destroyed after the document)",
            "documents": [r.public() for r in records],
            "summary": summary,
        }
