"""Model weight identity (SHA-256) for allowlisting and the manifest."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import httpx

from ..audit.manifest import sha256_file
from ..logging_safe import SafeError


def dir_sha256(path: str) -> str:
    """Hash of (relative path, file hash) for every file under ``path``."""
    h = hashlib.sha256()
    root = Path(path)
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(f.relative_to(root)).encode() + b"\0" + sha256_file(f).encode() + b"\n")
    return h.hexdigest()


def ollama_manifest_path(tag: str, models_dir: str) -> Path:
    """<models>/manifests/<host>/<namespace>/<model>/<tag> for an Ollama name."""
    name, _, version = tag.partition(":")
    parts = name.split("/")
    if len(parts) == 1:
        parts = ["registry.ollama.ai", "library", parts[0]]
    elif len(parts) == 2:
        parts = ["registry.ollama.ai"] + parts
    if len(parts) != 3 or any(p in ("", ".", "..") for p in parts + [version or "latest"]):
        raise SafeError("model_name_invalid")
    return Path(models_dir, "manifests", *parts, version or "latest")


def ollama_identity(tag: str, models_dir: str) -> str:
    """SHA-256 of the model's manifest file - the same value Ollama reports as
    the tag's digest, so allowlist entries are unchanged - after re-hashing
    every blob the manifest references (weights, template, params). A blob
    edited on disk does not change the server-reported digest; it fails here."""
    mp = ollama_manifest_path(tag, models_dir)
    if not mp.is_file():
        raise SafeError("model_manifest_missing")
    raw = mp.read_bytes()
    try:
        man = json.loads(raw)
        layers = [man["config"], *man["layers"]]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise SafeError("model_manifest_invalid") from e
    for layer in layers:
        algo, _, digest = str(layer.get("digest", "")).partition(":")
        if algo != "sha256" or len(digest) != 64:
            raise SafeError("model_manifest_invalid")
        blob = Path(models_dir, "blobs", f"sha256-{digest}")
        if not blob.is_file():
            blob = Path(models_dir, "blobs", f"sha256:{digest}")
        if not blob.is_file():
            raise SafeError("model_blob_missing")
        if sha256_file(blob) != digest:
            raise SafeError("model_blob_tampered")
    return hashlib.sha256(raw).hexdigest()


def ollama_digest(tag: str, base_url: str) -> str:
    """Digest as reported by a running server (cross-check only; not trusted)."""
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
        return ollama_identity(cfg.model_path, cfg.ollama_models_dir)
    if os.path.isdir(cfg.model_path):
        return dir_sha256(cfg.model_path)
    return sha256_file(cfg.model_path)
