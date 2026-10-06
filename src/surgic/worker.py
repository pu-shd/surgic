"""Isolated document workers.

Every parser that reads untrusted bytes (PyMuPDF/MuPDF, Pillow, openpyxl,
LibreOffice, pdfplumber, OCR, spaCy) runs in a worker process, never in the
orchestrator that holds the signing key and the operator's privileges.

* analyzer - extract, deterministic detection, masking; later maps the LLM's
  accepted strings back to the document and renders the redacted output.
* scanner  - re-extracts and scans the *output* only (post-scan). It never
  sees the input, so an input crafted to subvert the analyzer must also
  subvert a second, fresh process through the redacted output alone.

In production each worker runs under ``sandbox-exec`` (macOS) with the
``data/worker.sb`` profile: no network, no Keychain, no sudo/security/
osascript, and file writes confined to the run workspace. It also runs in a
new session, so it has no controlling terminal and cannot reuse the
operator's sudo ticket.

The protocol is one JSON object per line over the worker's stdin/stdout.
Replies carry only the fields listed here; the orchestrator validates every
field before anything reaches the manifest.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from .logging_safe import SafeError

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
CALL_TIMEOUT_S = 3600.0
_ENV_PASS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SURGIC_SOFFICE", "TESSDATA_PREFIX",
             "SURGIC_TEST_SPACY")
OFFLINE_ENV = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1",
               "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1", "PYTHONDONTWRITEBYTECODE": "1"}


class WorkerFailure(Exception):
    """A worker reported an error or died. ``kind`` is safe|unsupported|
    exception|crashed|timeout; ``code`` is a validated, content-free code."""

    def __init__(self, kind: str, code: str) -> None:
        super().__init__(code)
        self.kind, self.code = kind, code


# ---------------------------------------------------------------------------
# Handlers (run inside the worker)
# ---------------------------------------------------------------------------
class DocWorker:
    def __init__(self, cfg, phase_a, ocr) -> None:
        self.cfg, self.phase_a, self.ocr = cfg, phase_a, ocr
        self.docs: dict[str, tuple] = {}

    def info(self) -> dict:
        import hashlib

        from .pipeline import software_versions
        patterns_sha = hashlib.sha256(
            "\n".join(f"{p.name}\t{p.regex}" for p in self.phase_a.regex.patterns).encode()
        ).hexdigest()
        return {"patterns_sha256": patterns_sha, "hyperscan_active": self.phase_a.regex.hyperscan_active,
                "presidio_model": str(getattr(self.phase_a.presidio, "model_name", "none")),
                "software": software_versions()}

    def analyze(self, doc_id: str, path: str, work_dir: str) -> dict:
        from .detect import propagate
        from .detect.mask import build as build_mask
        from .extract import extract
        from .pipeline import span_counts

        doc = extract(path, doc_id, os.path.join(work_dir, "conv"), self.ocr)
        a_spans = propagate(doc.text, self.phase_a.find(doc.text))
        masked = build_mask(doc.text, a_spans)
        self.docs[doc_id] = (doc, a_spans, masked)
        return {"kind": doc.kind, "ocr_pages": doc.ocr_pages, "masked_text": masked.text,
                "phase_a": span_counts(a_spans)}

    def render(self, doc_id: str, accepted: dict[str, str], extra_values: list[str], out_dir: str) -> dict:
        from .detect import merge, propagate
        from .detect.contextual import map_accepted
        from .detect.spans import Span
        from .redact import render

        doc, a_spans, masked = self.docs[doc_id]
        b_spans = map_accepted(masked, accepted)
        extra = []
        for v in extra_values:
            if v.strip():
                i = doc.text.find(v)
                while i != -1:
                    extra.append(Span(i, i + len(v), "POSTSCAN_FEEDBACK", "regex"))
                    i = doc.text.find(v, i + 1)
        spans = merge(propagate(doc.text, a_spans + b_spans) + extra)
        shutil.rmtree(out_dir, ignore_errors=True)
        result = render(doc, spans, out_dir, doc_id)
        if spans and result.regions == 0:
            raise SafeError("no_regions_redacted")
        return {"regions": result.regions, "primary": result.primary, "sidecar": result.sidecar,
                "files": list(result.files), "known_values": sorted({doc.text[s.start:s.end] for s in spans}),
                "extra_spans": len(extra)}

    def forget(self, doc_id: str) -> dict:
        self.docs.pop(doc_id, None)
        return {}


class ScanWorker:
    def __init__(self, phase_a, ocr, scanners) -> None:
        self.phase_a, self.ocr, self.scanners = phase_a, ocr, scanners

    def info(self) -> dict:
        return {}

    def scan(self, primary: str, sidecar: str, known_values: list[str], scratch_dir: str) -> dict:
        from .audit.postscan import postscan
        rep = postscan(primary, sidecar, set(known_values), self.phase_a, self.ocr, self.scanners, scratch_dir)
        return {"passed": rep.passed, "public": rep.public(), "new_values": sorted(rep.new_values)}


_OPS = {"info", "analyze", "render", "forget", "scan"}


def dispatch(handler: Any, req: dict) -> dict:
    from .extract.base import UnsupportedDocument
    op = req.get("op")
    if op not in _OPS or not hasattr(handler, op):
        return {"error": "safe", "code": "worker_bad_op"}
    try:
        return {"ok": getattr(handler, op)(**req.get("args", {}))}
    except SafeError as e:
        return {"error": "safe", "code": e.code}
    except UnsupportedDocument as e:
        return {"error": "unsupported", "code": str(e.args[0]) if e.args else "unsupported"}
    except Exception as e:  # noqa: BLE001 - message may hold content; type name only
        return {"error": "exception", "code": "error:" + type(e).__name__}


def _valid_code(code: Any) -> str:
    import re
    if isinstance(code, str) and re.fullmatch(r"(?:error:)?[A-Za-z][A-Za-z0-9_]{0,63}", code):
        return code
    return "worker_protocol_error"


def _unwrap(reply: Any) -> dict:
    if not isinstance(reply, dict):
        raise WorkerFailure("safe", "worker_protocol_error")
    if "error" in reply:
        kind = reply["error"] if reply["error"] in ("safe", "unsupported", "exception") else "safe"
        raise WorkerFailure(kind, _valid_code(reply.get("code")))
    ok = reply.get("ok")
    if not isinstance(ok, dict):
        raise WorkerFailure("safe", "worker_protocol_error")
    return ok


# ---------------------------------------------------------------------------
# Clients (run in the orchestrator)
# ---------------------------------------------------------------------------
class WorkerClient(Protocol):
    isolation: str

    def start(self, work_root: str) -> None: ...
    def call(self, op: str, **args) -> dict: ...
    def restart(self) -> None: ...
    def stop(self) -> None: ...


class InProcessClient:
    """Tests only: same handlers and JSON round trip, no process boundary."""

    isolation = "inprocess"

    def __init__(self, handler: Any) -> None:
        if os.environ.get("SURGIC_ALLOW_INPROCESS") != "1":
            raise SafeError("inprocess_workers_not_allowed")
        self.handler = handler

    def start(self, work_root: str) -> None:
        pass

    def call(self, op: str, **args) -> dict:
        req = json.loads(json.dumps({"op": op, "args": args}))
        return _unwrap(json.loads(json.dumps(dispatch(self.handler, req))))

    def restart(self) -> None:
        pass

    def stop(self) -> None:
        pass


def sandbox_profile() -> str:
    return str(resources.files("surgic.data").joinpath("worker.sb"))


class SubprocessClient:
    def __init__(self, role: str, config_path: str, ocr: str, sandbox: bool,
                 timeout: float = CALL_TIMEOUT_S) -> None:
        self.role, self.config_path, self.ocr = role, config_path, ocr
        self.sandbox, self.timeout = sandbox, timeout
        self.isolation = "sandbox" if sandbox else "process"
        self.proc: subprocess.Popen | None = None
        self.work_root = ""
        self._q: queue.Queue = queue.Queue()

    def command(self) -> list[str]:
        cmd = [sys.executable, "-m", "surgic.worker", "--role", self.role,
               "--config", self.config_path, "--ocr", self.ocr]
        if self.sandbox:
            if not os.path.exists(SANDBOX_EXEC):
                raise SafeError("sandbox_unavailable")
            home = os.path.realpath(os.path.expanduser("~"))
            cmd = [SANDBOX_EXEC, "-f", sandbox_profile(), "-D", f"WORK={os.path.realpath(self.work_root)}",
                   "-D", f"HOME={home}"] + cmd
        return cmd

    def env(self) -> dict[str, str]:
        env = {k: os.environ[k] for k in _ENV_PASS if k in os.environ}
        tmp = os.path.join(self.work_root, f".tmp-{self.role}")
        os.makedirs(tmp, exist_ok=True)
        env.update(OFFLINE_ENV, HOME=os.path.expanduser("~"), TMPDIR=tmp)
        return env

    def start(self, work_root: str) -> None:
        self.work_root = work_root
        self._spawn()

    def _spawn(self) -> None:
        self._q = queue.Queue()
        # New session: no controlling terminal, so no access to the operator's
        # tty-scoped sudo ticket. stderr is inherited (content-free logging).
        self.proc = subprocess.Popen(self.command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     env=self.env(), cwd=self.work_root, start_new_session=True)
        q, out = self._q, self.proc.stdout

        def pump() -> None:
            for line in out:
                q.put(line)
            q.put(None)

        threading.Thread(target=pump, daemon=True).start()
        _unwrap(self._roundtrip({"op": "info", "args": {}}))  # wait until ready

    def _roundtrip(self, req: dict) -> Any:
        assert self.proc and self.proc.stdin
        try:
            self.proc.stdin.write(json.dumps(req).encode() + b"\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise WorkerFailure("crashed", "worker_crashed")
        try:
            line = self._q.get(timeout=self.timeout)
        except queue.Empty:
            self._kill()
            raise WorkerFailure("timeout", "worker_timeout")
        if line is None:
            raise WorkerFailure("crashed", "worker_crashed")
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            raise WorkerFailure("safe", "worker_protocol_error")

    def call(self, op: str, **args) -> dict:
        return _unwrap(self._roundtrip({"op": op, "args": args}))

    def _kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass

    def restart(self) -> None:
        self._kill()
        self._spawn()

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass
        self._kill()
        self.proc = None


def make_clients(cfg, ocr: str) -> tuple[WorkerClient, WorkerClient]:
    mode = cfg.isolation.mode
    if mode == "inprocess":
        raise SafeError("inprocess_workers_not_allowed")  # tests build InProcessClient directly
    if not cfg.source_path:
        raise SafeError("config_path_unknown")
    sandbox = mode == "sandbox"
    return (SubprocessClient("analyzer", cfg.source_path, ocr, sandbox),
            SubprocessClient("scanner", cfg.source_path, ocr, sandbox))


# ---------------------------------------------------------------------------
# Worker process entry point
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    from . import logging_safe, netguard
    ap = argparse.ArgumentParser(prog="surgic-worker")
    ap.add_argument("--role", choices=["analyzer", "scanner"], required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--ocr", default="auto")
    args = ap.parse_args(argv)

    # The protocol owns the real stdout; anything a library prints goes to stderr.
    proto = os.fdopen(os.dup(1), "w", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    logging_safe.install()
    netguard.install()

    from .audit.postscan import SecretScanners
    from .config import Config
    from .detect import PhaseA
    from .extract.ocr import default_ocr

    cfg = Config.load(args.config)
    phase_a = PhaseA.from_config(cfg.detect)
    ocr = default_ocr(args.ocr)
    if args.role == "analyzer":
        handler: Any = DocWorker(cfg, phase_a, ocr)
    else:
        handler = ScanWorker(phase_a, ocr, SecretScanners(cfg.audit.gitleaks_binary, cfg.audit.trufflehog_binary,
                                                          cfg.audit.require_secret_scanners))
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            reply: dict = {"error": "safe", "code": "worker_bad_request"}
        else:
            reply = dispatch(handler, req)
        proto.write(json.dumps(reply) + "\n")
        proto.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
