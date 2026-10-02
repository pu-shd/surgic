"""Content-free logging.

Document text must never reach a log. Pipeline code logs only through
``log_event`` with structured, allowlisted fields; a root filter drops any
record that carries free-form arguments or exception text from third-party
libraries, which may embed document content.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
from typing import Any

_ALLOWED_TYPES = (int, float, bool, type(None))
_SAFE_STR_KEYS = {
    "event", "doc_id", "category", "source", "backend", "phase", "status",
    "reason", "path_hash", "sha256", "token_hmac", "kind", "step", "run_id",
}
LOGGER_NAME = "surgic"


class RunKey:
    """Ephemeral per-run HMAC key; never persisted."""

    def __init__(self) -> None:
        self._key = os.urandom(32)

    def token(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def wipe(self) -> None:
        self._key = b"\x00" * 32


class ContentFreeFilter(logging.Filter):
    """Allow only records emitted via log_event; scrub everything else."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "surgic_safe", False):
            return True
        # Third-party record: keep logger name/level only.
        record.msg = f"[redacted log from {record.name}]"
        record.args = None
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return record.levelno >= logging.WARNING


def _check(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in fields.items():
        if isinstance(v, _ALLOWED_TYPES):
            out[k] = v
        elif isinstance(v, str) and k in _SAFE_STR_KEYS and len(v) <= 128:
            out[k] = v
        elif isinstance(v, dict) and all(isinstance(x, int) for x in v.values()):
            out[k] = {str(a): b for a, b in v.items()}
        else:
            raise ValueError(f"unsafe log field: {k}")
    return out


def log_event(event: str, level: int = logging.INFO, **fields: Any) -> None:
    payload = _check({"event": event, **fields})
    logging.getLogger(LOGGER_NAME).log(
        level, json.dumps(payload, sort_keys=True), extra={"surgic_safe": True}
    )


def install(level: int = logging.INFO, stream=None) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.addFilter(ContentFreeFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root.addHandler(handler)


class SafeError(Exception):
    """Exception whose message is guaranteed content-free."""

    def __init__(self, code: str, **fields: Any) -> None:
        self.code = code
        self.fields = _check(fields)
        super().__init__(code)
