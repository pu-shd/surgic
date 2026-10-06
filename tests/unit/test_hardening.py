"""Regression tests for the security audit fixes."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import subprocess
import sys
import warnings
from pathlib import Path

import pytest
from PIL import Image

from surgic import logging_safe, netguard
from surgic.extract import extract
from surgic.extract.base import UnsupportedDocument
from surgic.logging_safe import SafeError

ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------- content sniffing
def _extract(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return extract(str(p), "d", str(tmp_path / "conv"), None)


@pytest.mark.parametrize("name,data,code", [
    ("notes.txt", b"%PDF-1.7\n1 0 obj <</Filter/FlateDecode>> stream\nx\x9c\x01", "content_type_mismatch"),
    ("data.csv", b"PK\x03\x04\x14\x00\x00\x00", "content_type_mismatch"),
    ("page.html", b'<p>hi</p><img src="data:image/png;base64,iVBORw0KGgo=">', "embedded_data_uri"),
    ("blob.json", json.dumps({"attachment": base64.b64encode(os.urandom(600)).decode()}).encode(),
     "embedded_encoded_blob"),
    ("mail.txt", b"Body\n\n" + base64.encodebytes(os.urandom(900)), "embedded_encoded_blob"),
    ("dump.log", b"key " + os.urandom(400).hex().encode(), "embedded_encoded_blob"),
    ("bin.txt", b"hello\x00world", "binary_content"),
    ("memo.pdf", b"just text pretending", "content_type_mismatch"),
    ("sheet.xlsx", b"%PDF-1.7 not a zip", "content_type_mismatch"),
    ("pic.png", b"\xff\xd8\xff\xe0 jpeg bytes", "content_type_mismatch"),
])
def test_untrusted_extension_or_encoded_payload_rejected(tmp_path, name, data, code):
    with pytest.raises(UnsupportedDocument) as e:
        _extract(tmp_path, name, data)
    assert e.value.args[0] == code


def test_ordinary_text_is_accepted(tmp_path):
    prose = ("The quarterly review covers supplier performance, renewal timelines and the "
             "outstanding items from March. ") * 40
    url = "https://intranet.example.com/reports/2026/q1/summary?id=12345"
    doc = _extract(tmp_path, "notes.md", (prose + url + "\nSHA " + hashlib.sha256(b"x").hexdigest()).encode())
    assert doc.kind == "text" and "supplier" in doc.text


def test_multi_frame_image_rejected(tmp_path):
    frames = [Image.new("RGB", (50, 50), c) for c in ("white", "black")]
    buf = io.BytesIO()
    frames[0].save(buf, format="TIFF", save_all=True, append_images=frames[1:])
    with pytest.raises(UnsupportedDocument) as e:
        _extract(tmp_path, "scan.tiff", buf.getvalue())
    assert e.value.args[0] == "multi_frame_image"


# ---------------------------------------------------------------- model identity
def _ollama_tree(root: Path, tag="qwen3.6:27b") -> tuple[Path, bytes]:
    blobs = root / "blobs"
    blobs.mkdir(parents=True)
    layers = []
    for content in (b"GGUF weights", b"{{ template }}"):
        d = hashlib.sha256(content).hexdigest()
        (blobs / f"sha256-{d}").write_bytes(content)
        layers.append({"digest": f"sha256:{d}"})
    cfg = b'{"model_format":"gguf"}'
    cd = hashlib.sha256(cfg).hexdigest()
    (blobs / f"sha256-{cd}").write_bytes(cfg)
    manifest = json.dumps({"config": {"digest": f"sha256:{cd}"}, "layers": layers}).encode()
    name, ver = tag.split(":")
    mdir = root / "manifests" / "registry.ollama.ai" / "library" / name
    mdir.mkdir(parents=True)
    (mdir / ver).write_bytes(manifest)
    return blobs, manifest


def test_ollama_identity_hashes_blobs_from_disk(tmp_path):
    from surgic.llm.identity import ollama_identity, ollama_manifest_path
    blobs, manifest = _ollama_tree(tmp_path)
    assert ollama_identity("qwen3.6:27b", str(tmp_path)) == hashlib.sha256(manifest).hexdigest()
    # Editing a weight file does not change Ollama's reported digest; it fails here.
    weights = next(p for p in blobs.iterdir() if p.read_bytes() == b"GGUF weights")
    weights.write_bytes(b"GGUF backdoor")
    with pytest.raises(SafeError) as e:
        ollama_identity("qwen3.6:27b", str(tmp_path))
    assert e.value.code == "model_blob_tampered"
    assert ollama_manifest_path("ns/m", "/x") == Path("/x/manifests/registry.ollama.ai/ns/m/latest")
    with pytest.raises(SafeError):
        ollama_manifest_path("../../etc:passwd", "/x")


def test_ollama_server_uses_hashed_models_dir():
    from surgic.config import LLMConfig
    from surgic.llm.ollama import OllamaBackend
    env = OllamaBackend(LLMConfig(backend="ollama", ollama_models_dir="/m")).extra_env()
    assert env["OLLAMA_MODELS"] == "/m"


def test_llamacpp_enables_slot_erase():
    from surgic.config import LLMConfig
    from surgic.llm.llamacpp import LlamaCppBackend
    cmd = LlamaCppBackend(LLMConfig(model_path="/m.gguf")).command()
    assert "--slot-save-path" in cmd


# ---------------------------------------------------------------- worker protocol
def test_worker_error_codes_are_sanitized():
    from surgic.worker import WorkerFailure, _unwrap
    with pytest.raises(WorkerFailure) as e:
        _unwrap({"error": "safe", "code": "Margaret Thornbury SSN 219-09-9999"})
    assert e.value.code == "worker_protocol_error"
    with pytest.raises(WorkerFailure) as e:
        _unwrap({"error": "exception", "code": "error:ValueError"})
    assert e.value.code == "error:ValueError"


class _Tamper:
    """Wraps a client and rewrites one op's reply, like a compromised worker."""

    def __init__(self, inner, op, fn):
        self.inner, self.op, self.fn = inner, op, fn
        self.isolation = inner.isolation
        self.restarts = 0

    def start(self, w):
        self.inner.start(w)

    def stop(self):
        self.inner.stop()

    def restart(self):
        self.restarts += 1

    def call(self, op, **args):
        r = self.inner.call(op, **args)
        return self.fn(r, args) if op == self.op else r


def _pipeline(tmp_path, regex_only, key_store, analyzer=None, scanner=None):
    from surgic.audit.signing import Signer
    from surgic.config import AuditConfig, Config, LLMConfig, NetworkConfig
    from surgic.llm.mock import MockBackend
    from surgic.pipeline import Pipeline
    from surgic.worker import DocWorker, InProcessClient, ScanWorker
    cfg = Config(network=NetworkConfig(smb_share_ip="10.0.0.5"), llm=LLMConfig(backend="mock"),
                 audit=AuditConfig(require_secret_scanners=False))
    a = InProcessClient(DocWorker(cfg, regex_only, None))
    s = InProcessClient(ScanWorker(regex_only, None, None))
    p = Pipeline(cfg, MockBackend(cfg.llm), signer=Signer(key_store), model_sha256="f" * 64,
                 analyzer=analyzer(a) if analyzer else a, scanner=scanner(s) if scanner else s)
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "a.txt").write_text("SSN 219-09-9999 for review.\n")
    (tmp_path / "out").mkdir()
    return p


def test_worker_output_outside_its_directory_aborts(tmp_path, regex_only, key_store):
    def escape(r, args):
        return {**r, "files": ["/etc/passwd"], "primary": "/etc/passwd", "sidecar": "/etc/passwd"}
    p = _pipeline(tmp_path, regex_only, key_store, analyzer=lambda a: _Tamper(a, "render", escape))
    with pytest.raises(SafeError) as e:
        p.run(str(tmp_path / "in"), str(tmp_path / "out"), str(tmp_path / "ws"))
    assert e.value.code == "worker_protocol_error"
    assert [x.name for x in (tmp_path / "out").iterdir()] == ["manifests"]


def test_worker_cannot_smuggle_text_into_manifest(tmp_path, regex_only, key_store):
    def smuggle(r, args):
        return {**r, "phase_a": {"regex:US_SSN": 1, "Margaret Thornbury": 1}}
    p = _pipeline(tmp_path, regex_only, key_store, analyzer=lambda a: _Tamper(a, "analyze", smuggle))
    with pytest.raises(SafeError):
        p.run(str(tmp_path / "in"), str(tmp_path / "out"), str(tmp_path / "ws"))
    for m in (tmp_path / "out" / "manifests").glob("*.json"):
        assert "Thornbury" not in m.read_text()


def test_worker_crash_quarantines_and_restarts(tmp_path, regex_only, key_store):
    from surgic.worker import WorkerFailure

    def crash(r, args):
        raise WorkerFailure("crashed", "worker_crashed")
    holder = {}

    def wrap(a):
        holder["t"] = _Tamper(a, "analyze", crash)
        return holder["t"]
    p = _pipeline(tmp_path, regex_only, key_store, analyzer=wrap)
    _, man = p.run(str(tmp_path / "in"), str(tmp_path / "out"), str(tmp_path / "ws"))
    [d] = man["documents"]
    assert d["status"] == "quarantined" and d["reason"] == "worker_crashed"
    assert holder["t"].restarts == 1


def test_scanner_claiming_pass_inconsistently_is_rejected(tmp_path, regex_only, key_store):
    def lie(r, args):
        return {**r, "passed": True, "public": {**r["public"], "passed": False}}
    p = _pipeline(tmp_path, regex_only, key_store, scanner=lambda s: _Tamper(s, "scan", lie))
    with pytest.raises(SafeError) as e:
        p.run(str(tmp_path / "in"), str(tmp_path / "out"), str(tmp_path / "ws"))
    assert e.value.code == "worker_protocol_error"


def test_inprocess_workers_need_opt_in(monkeypatch):
    from surgic.worker import InProcessClient
    monkeypatch.delenv("SURGIC_ALLOW_INPROCESS")
    with pytest.raises(SafeError) as e:
        InProcessClient(object())
    assert e.value.code == "inprocess_workers_not_allowed"


def test_sandbox_mode_requires_sandbox_exec(monkeypatch, tmp_path):
    from surgic import worker
    monkeypatch.setattr(worker, "SANDBOX_EXEC", str(tmp_path / "missing"))
    c = worker.SubprocessClient("analyzer", "/c.toml", "auto", sandbox=True)
    c.work_root = str(tmp_path)
    with pytest.raises(SafeError) as e:
        c.command()
    assert e.value.code == "sandbox_unavailable"


def test_worker_env_is_minimal(monkeypatch, tmp_path):
    from surgic import worker
    monkeypatch.setenv("SURGIC_KEY_FILE", "/secret/seed")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent")
    c = worker.SubprocessClient("analyzer", "/c.toml", "auto", sandbox=False)
    c.work_root = str(tmp_path)
    env = c.env()
    assert "SURGIC_KEY_FILE" not in env and "SSH_AUTH_SOCK" not in env
    assert env["TMPDIR"].startswith(str(tmp_path)) and env["HF_HUB_OFFLINE"] == "1"


# ---------------------------------------------------------------- sandbox (real, macOS)
SANDBOX_PROBE = r"""
import os, socket, subprocess, sys
work = sys.argv[1]
res = {}
try:
    socket.create_connection(("192.0.2.1", 443), timeout=2); res["net"] = "open"
except OSError:
    res["net"] = "blocked"
try:
    open(os.path.expanduser("~/.surgic_sandbox_probe"), "w"); res["write_home"] = "open"
except OSError:
    res["write_home"] = "blocked"
try:
    subprocess.run(["/usr/bin/sudo", "-n", "true"], capture_output=True); res["sudo"] = "ran"
except OSError:
    res["sudo"] = "blocked"
try:
    os.listdir(os.path.expanduser("~/Library/Keychains")); res["keychain"] = "open"
except OSError:
    res["keychain"] = "blocked"
open(os.path.join(work, "ok"), "w").write("x"); res["write_work"] = "ok"
print(res)
"""


@pytest.mark.macos
@pytest.mark.skipif(not os.path.exists("/usr/bin/sandbox-exec"), reason="sandbox-exec unavailable")
def test_worker_sandbox_profile_blocks_escape_paths(tmp_path):
    from surgic.worker import sandbox_profile
    work = tmp_path / "work"
    work.mkdir()
    home = os.path.realpath(os.path.expanduser("~"))
    p = subprocess.run(["/usr/bin/sandbox-exec", "-f", sandbox_profile(), "-D", f"WORK={os.path.realpath(work)}",
                        "-D", f"HOME={home}", sys.executable, "-c", SANDBOX_PROBE, str(work)],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr[-2000:]
    res = eval(p.stdout.strip().splitlines()[-1])  # noqa: S307 - our own probe's dict literal
    assert res == {"net": "blocked", "write_home": "blocked", "sudo": "blocked",
                   "keychain": "blocked", "write_work": "ok"}
    assert not Path(home, ".surgic_sandbox_probe").exists()


@pytest.mark.macos
@pytest.mark.skipif(not os.path.exists("/usr/bin/sandbox-exec"), reason="sandbox-exec unavailable")
def test_sandboxed_analyzer_processes_a_document(tmp_path):
    from surgic.worker import SubprocessClient
    cfgf = tmp_path / "c.toml"
    cfgf.write_text('[network]\nsmb_share_ip = "10.0.0.5"\n[detect]\nspacy_model = "en_core_web_sm"\n'
                    'spacy_fallback = "en_core_web_sm"\nuse_hyperscan = false\n')
    work = tmp_path / "run"
    (work / "d1" / "in").mkdir(parents=True)
    doc = work / "d1" / "in" / "input.txt"
    doc.write_text("SSN 219-09-9999 belongs to the file.\n")
    c = SubprocessClient("analyzer", str(cfgf), "auto", sandbox=True, timeout=300)
    c.start(str(work))
    try:
        a = c.call("analyze", doc_id="d1", path=str(doc), work_dir=str(work / "d1"))
        assert "219-09-9999" not in a["masked_text"] and "[US_SSN_1]" in a["masked_text"]
        r = c.call("render", doc_id="d1", accepted={}, extra_values=[], out_dir=str(work / "d1" / "out"))
        assert "219-09-9999" not in Path(r["primary"]).read_text()
    finally:
        c.stop()


# ---------------------------------------------------------------- netguard / logging
def test_netguard_blocks_legacy_resolvers_and_sendmsg():
    import socket
    before = len(netguard.attempts)
    with pytest.raises(OSError):
        socket.gethostbyname("example.com")
    with pytest.raises(OSError):
        socket.gethostbyname_ex("example.com")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(OSError):
            s.sendmsg([b"x"], [], 0, ("192.0.2.1", 53))
    assert len(netguard.attempts) == before + 3
    del netguard.attempts[before:]
    assert socket.gethostbyname("localhost")


def test_warnings_are_content_filtered():
    buf = io.StringIO()
    logging_safe.install(stream=buf)
    # pytest records warnings itself, so call the hook the warnings module
    # dispatches to (which install() replaced) directly.
    warnings.showwarning("cell value 'Margaret Thornbury' truncated", UserWarning, "lib.py", 1)
    assert "Thornbury" not in buf.getvalue() and "[redacted log from py.warnings]" in buf.getvalue()
    logging.captureWarnings(False)


# ---------------------------------------------------------------- patterns
@pytest.mark.parametrize("text,cat", [
    ("SSN: 219099999", "US_SSN_LABELED"),
    ("social security number 219099999", "US_SSN_LABELED"),
    ("id 219 09 9999 on file", "US_SSN"),
    ("Marked Top Secret by the office", "CLASSIFICATION_MARKING_PHRASE"),
    ("internal use only", "CLASSIFICATION_MARKING_PHRASE"),
])
def test_additional_patterns(regex_only, text, cat):
    assert cat in {s.category for s in regex_only.find(text)}


def test_single_lowercase_marking_words_are_prose(regex_only):
    assert regex_only.find("a confidential conversation about secret recipes") == []


# ---------------------------------------------------------------- scripts
@pytest.mark.parametrize("script", ["run.zsh", "provision.zsh"])
def test_scripts_do_not_interpolate_into_python(script):
    text = (ROOT / "scripts" / script).read_text()
    assert "('$" not in text and "'$CONFIG'" not in text and "'$MODEL'" not in text
    assert "sudo -n true; sleep" not in text  # no sudo keepalive
