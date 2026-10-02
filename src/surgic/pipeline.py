"""Pipeline orchestration: ingest -> extract -> Phase A -> Phase B -> redact ->
post-scan -> release or quarantine -> signed manifest.

Fail-closed: any per-document error quarantines that document (nothing is
written to the destination); any environment/LLM-isolation error aborts the run.
"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import time
import uuid
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

from .audit.manifest import SCHEMA, sha256_file, write_signed
from .audit.postscan import SecretScanners, postscan
from .audit.signing import Signer
from .detect import PhaseA, merge, propagate
from .detect.contextual import contextual_spans
from .detect.mask import build as build_mask
from .detect.spans import Span
from .extract import SUPPORTED_EXT, extract
from .extract.base import UnsupportedDocument
from .extract.ocr import OcrFn
from .llm.backend import LLMBackend
from .logging_safe import RunKey, SafeError, log_event
from .redact import render

FATAL_CODES = {
    "llm_unload_unverified", "llm_reset_failed", "llm_port_in_use", "llm_server_exited",
    "llm_start_timeout", "secret_scanner_missing", "gitleaks_failed", "trufflehog_failed",
    "gitleaks_inconsistent", "trufflehog_inconsistent", "output_verify_failed",
}
MAX_RESCANS = 2


@dataclass
class DocRecord:
    doc_id: str
    kind: str = ""
    input_sha256: str = ""
    input_bytes: int = 0
    input_path: str | None = None
    status: str = "pending"
    reason: str = ""
    outputs: list[dict] = field(default_factory=list)
    phase_a: dict[str, int] = field(default_factory=dict)
    phase_b: dict = field(default_factory=dict)
    token_hmacs: list[str] = field(default_factory=list)
    regions: int = 0
    ocr_pages: int = 0
    rescans: int = 0
    postscan: dict = field(default_factory=dict)
    llm_resets_before: int = 0

    def public(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "llm_resets_before"}
        if d["input_path"] is None:
            d.pop("input_path")
        return d


def _counts(spans: list[Span]) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in spans:
        k = f"{s.source}:{s.category}"
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def _versions() -> dict[str, str]:
    out = {"python": platform.python_version(), "platform": platform.platform()}
    for pkg in ("surgic", "pymupdf", "presidio-analyzer", "spacy", "google-re2", "hyperscan",
                "openpyxl", "pdfplumber", "cryptography"):
        try:
            out[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            out[pkg] = "absent"
    return out


def enumerate_inputs(root: str) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for f in sorted(filenames):
            p = Path(dirpath, f)
            if f.startswith(".") or p.is_symlink():
                continue
            out.append(p)
    return out


class Pipeline:
    def __init__(self, cfg, backend: LLMBackend, phase_a: PhaseA, ocr: OcrFn | None,
                 scanners: SecretScanners | None, signer: Signer, model_sha256: str,
                 environment: dict | None = None) -> None:
        self.cfg = cfg
        self.backend = backend
        self.phase_a = phase_a
        self.ocr = ocr
        self.scanners = scanners
        self.signer = signer
        self.model_sha256 = model_sha256
        self.environment = environment or {}
        self.run_key = RunKey()
        self.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]

    # ------------------------------------------------------------------
    def run(self, input_dir: str, output_dir: str, workspace: str) -> tuple[str, dict]:
        started = int(time.time())
        files = enumerate_inputs(input_dir)
        records: list[DocRecord] = []
        work_root = Path(workspace, self.run_id)
        work_root.mkdir(parents=True, exist_ok=False)
        supported = [(i, p) for i, p in enumerate(files) if p.suffix.lower() in SUPPORTED_EXT]
        for i, p in enumerate(files):
            if p.suffix.lower() not in SUPPORTED_EXT:
                rec = self._new_record(i, p, input_dir)
                rec.status, rec.reason = "skipped", "unsupported_extension"
                records.append(rec)

        bs = self.cfg.llm.batch_size
        try:
            for b in range(0, len(supported), bs):
                batch = supported[b:b + bs]
                self.backend.start()
                for i, p in batch:
                    rec = self._new_record(i, p, input_dir)
                    records.append(rec)
                    self._process(rec, p, output_dir, work_root)
                    self.backend.reset_context()
                self.backend.unload()
                if self.backend.is_loaded():
                    raise SafeError("llm_unload_unverified", backend=self.backend.name)
        finally:
            if self.backend.is_loaded():
                self.backend.unload()
            shutil.rmtree(work_root, ignore_errors=True)
            self.run_key.wipe()

        records.sort(key=lambda r: r.doc_id)
        manifest = self._manifest(records, started)
        mdir = Path(output_dir, "manifests")
        mdir.mkdir(parents=True, exist_ok=True)
        mpath, _ = write_signed(manifest, mdir / f"{self.run_id}.manifest.json", self.signer)
        (mdir / "pubkey.pem").write_bytes(self.signer.public_pem())
        log_event("run_complete", run_id=self.run_id, documents=len(records),
                  clean=manifest["summary"]["clean"], quarantined=manifest["summary"]["quarantined"])
        return mpath, manifest

    def _new_record(self, i: int, p: Path, input_dir: str) -> DocRecord:
        sha = sha256_file(p)
        rec = DocRecord(doc_id=f"{i:05d}-{sha[:12]}", input_sha256=sha, input_bytes=p.stat().st_size)
        if self.cfg.storage.record_input_paths:
            rec.input_path = str(p.relative_to(input_dir))
        return rec

    # ------------------------------------------------------------------
    def _process(self, rec: DocRecord, src: Path, output_dir: str, work_root: Path) -> None:
        wd = work_root / rec.doc_id
        (wd / "in").mkdir(parents=True)
        known: set[str] = set()
        try:
            local = wd / "in" / ("input" + src.suffix.lower())
            shutil.copyfile(src, local)
            if sha256_file(local) != rec.input_sha256:
                raise SafeError("input_changed_during_copy")
            doc = extract(str(local), rec.doc_id, str(wd / "conv"), self.ocr)
            rec.kind, rec.ocr_pages = doc.kind, doc.ocr_pages

            a_spans = self.phase_a.find(doc.text)
            a_spans = propagate(doc.text, a_spans)
            masked = build_mask(doc.text, a_spans)
            b_spans, stats, _ = contextual_spans(masked, self.backend, self.cfg.llm.chunk_chars,
                                                 self.cfg.llm.chunk_overlap)
            rec.phase_b = {k: v for k, v in stats.__dict__.items()}
            spans = merge(propagate(doc.text, a_spans + b_spans))
            rec.phase_a = _counts(a_spans)

            out_dir = wd / "out"
            for attempt in range(MAX_RESCANS + 1):
                known = {doc.text[s.start:s.end] for s in spans}
                result = render(doc, spans, str(out_dir), rec.doc_id)
                rec.regions = result.regions
                if spans and result.regions == 0:
                    raise SafeError("no_regions_redacted")
                report = postscan(result.primary, result.sidecar, known, self.phase_a, self.ocr,
                                  self.scanners, str(wd))
                if report.passed:
                    break
                # Feed newly detected values back if they exist in the source text.
                extra = []
                for v in report.new_values:
                    if v.strip():
                        i = doc.text.find(v)
                        while i != -1:
                            extra.append(Span(i, i + len(v), "POSTSCAN_FEEDBACK", "regex"))
                            i = doc.text.find(v, i + 1)
                if not extra or attempt == MAX_RESCANS:
                    break
                rec.rescans += 1
                spans = merge(spans + extra)
                shutil.rmtree(out_dir, ignore_errors=True)
            rec.postscan = report.public()
            rec.token_hmacs = sorted({self.run_key.token(v) for v in known})
            if not report.passed:
                rec.status, rec.reason = "quarantined", "postscan_failed"
                return

            dest = Path(output_dir, rec.doc_id)
            dest.mkdir(parents=True, exist_ok=False)
            for f in result.files:
                target = dest / Path(f).name
                shutil.copyfile(f, target)
                h_local, h_remote = sha256_file(f), sha256_file(target)
                if h_local != h_remote:
                    raise SafeError("output_verify_failed")
                rec.outputs.append({"name": Path(f).name, "sha256": h_remote,
                                    "bytes": target.stat().st_size})
            rec.status = "clean"
        except SafeError as e:
            if e.code in FATAL_CODES:
                raise
            rec.status, rec.reason = "quarantined", e.code
        except UnsupportedDocument as e:
            rec.status, rec.reason = "quarantined", str(e.args[0]) if e.args else "unsupported"
        except Exception as e:  # noqa: BLE001
            rec.status, rec.reason = "quarantined", "error:" + type(e).__name__
        finally:
            known.clear()
            shutil.rmtree(wd, ignore_errors=True)
            if rec.status == "quarantined":
                shutil.rmtree(Path(output_dir, rec.doc_id), ignore_errors=True)
            log_event("document", doc_id=rec.doc_id, status=rec.status, reason=rec.reason or None,
                      regions=rec.regions)

    # ------------------------------------------------------------------
    def _manifest(self, records: list[DocRecord], started: int) -> dict:
        patterns_sha = hashlib.sha256(
            "\n".join(f"{p.name}\t{p.regex}" for p in self.phase_a.regex.patterns).encode()
        ).hexdigest()
        summary = {s: sum(1 for r in records if r.status == s) for s in ("clean", "quarantined", "skipped")}
        summary["total"] = len(records)
        return {
            "schema": SCHEMA,
            "run_id": self.run_id,
            "started_at": started,
            "finished_at": int(time.time()),
            "host": {"node": platform.node(), "machine": platform.machine(), "os": platform.mac_ver()[0] or platform.system()},
            "software": _versions(),
            "config_sha256": self.cfg.source_sha256,
            "patterns_sha256": patterns_sha,
            "hyperscan_active": self.phase_a.regex.hyperscan_active,
            "presidio_model": getattr(self.phase_a.presidio, "model_name", "none"),
            "llm": {**self.backend.identity(), "model_sha256": self.model_sha256,
                    "batch_size": self.cfg.llm.batch_size, "unloads": self.backend.unload_count,
                    "context_resets": self.backend.reset_count},
            "environment": self.environment,
            "token_hmac": "HMAC-SHA256 with an ephemeral per-run key (destroyed at run end)",
            "documents": [r.public() for r in records],
            "summary": summary,
        }

