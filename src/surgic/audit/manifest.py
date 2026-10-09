"""Audit manifest: canonical JSON, Ed25519-signed.

Canonical form: UTF-8, keys sorted, no insignificant whitespace, integers and
strings only (no floats), which coincides with RFC 8785 (JCS) for this data.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "surgic.manifest/v1"
CLOSURE_SCHEMA = "surgic.closure/v1"


def _no_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise TypeError("floats are not permitted in canonical manifests")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError("non-string key")
            _no_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _no_floats(v)


def canonical(obj: Any) -> bytes:
    _no_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_signed(obj: dict, path: str | Path, signer) -> tuple[str, str]:
    """Write <path> (canonical JSON) and <path>.sig (base64 signature). Returns paths."""
    obj = dict(obj)
    obj["signer"] = signer.signer_block()
    data = canonical(obj)
    p = Path(path)
    p.write_bytes(data)
    sig = Path(str(p) + ".sig")
    sig.write_bytes(base64.b64encode(signer.sign(data)) + b"\n")
    return str(p), str(sig)
