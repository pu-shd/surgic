"""Model weight identity (SHA-256) for allowlisting and the manifest."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import httpx

from ..audit.manifest import sha256_file


def dir_sha256(path: str) -> str:
    """Hash of (relative path, file hash) for every file under ``path``."""
    h = hashlib.sha256()
    root = Path(path)
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(f.relative_to(root)).encode() + b"\0" + sha256_file(f).encode() + b"\n")
    return h.hexdigest()


def ollama_digest(tag: str, base_url: str) -> str:
    r = httpx.get(base_url + "/api/tags", timeout=30, trust_env=False)
    r.raise_for_status()
    for m in r.json().get("models", []):
        if m.get("name") == tag or m.get("model") == tag:
            return str(m.get("digest", ""))
    return ""


def model_sha256(cfg) -> str:
    if cfg.backend == "mock":
        return hashlib.sha256(json.dumps({"mock": True}).encode()).hexdigest()
    if cfg.backend == "ollama":
        return ollama_digest(cfg.model_path, f"http://{cfg.host}:{cfg.port}")
    if os.path.isdir(cfg.model_path):
        return dir_sha256(cfg.model_path)
    return sha256_file(cfg.model_path)
