from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

from surgic.config import LLMConfig
from surgic.llm.backend import make_backend, port_open
from surgic.llm.llamacpp import LlamaCppBackend
from surgic.llm.mlx import MlxBackend
from surgic.llm.ollama import OllamaBackend
from surgic.logging_safe import SafeError

FAKE = str(Path(__file__).resolve().parents[1] / "fakes" / "fake_llm.py")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fake(cls, kind, mode, tmp_path, **cfg_kw):
    state = tmp_path / f"{kind}.json"
    port = free_port()

    class Fake(cls):
        def command(self):
            return [sys.executable, FAKE, kind, str(port), mode, str(state)]

    cfg = LLMConfig(backend=kind if kind != "llamacpp" else "llamacpp", model_path="fake:70b",
                    port=port, max_retries=1, **cfg_kw)
    return Fake(cfg), state


def read(state: Path) -> dict:
    return json.loads(state.read_text())


@pytest.mark.parametrize("cls,kind", [(LlamaCppBackend, "llamacpp"), (OllamaBackend, "ollama"),
                                      (MlxBackend, "mlx")])
def test_backend_lifecycle_and_findings(cls, kind, tmp_path):
    b, state = fake(cls, kind, "ok", tmp_path)
    b.start()
    assert b.is_loaded() and port_open("127.0.0.1", b.cfg.port)
    fs = b.find("Acme is our client")
    assert [(f.text, f.category) for f in fs] == [("Acme", "CLIENT_RELATIONSHIP")]
    b.reset_context()
    assert b.reset_count == 1
    if kind != "mlx":  # mlx reset restarts the server
        assert b.is_loaded()
    b.unload()
    assert not b.is_loaded() and b.unload_count >= 1
    assert not port_open("127.0.0.1", b.cfg.port)
    reqs = read(state)["requests"] if state.exists() else []
    chat = [r for r in reqs if r["path"] in ("/v1/chat/completions", "/api/chat")]
    assert chat, "no inference request recorded"
    if kind == "llamacpp":
        assert chat[0]["cache_prompt"] is False and chat[0]["has_schema"]
        assert read(state)["erased"] == 1
    if kind == "mlx":
        assert read(state)["starts"] == 2  # reset_context restarted the server
    if kind == "ollama":
        assert chat[0]["has_schema"]
        assert any(r["path"] == "/api/generate" and r["keep_alive"] == 0 for r in reqs)


def test_llamacpp_bad_json_fails_closed(tmp_path):
    b, _ = fake(LlamaCppBackend, "llamacpp", "badjson", tmp_path)
    b.start()
    try:
        with pytest.raises(SafeError) as e:
            b.find("x")
        assert e.value.code == "llm_output_invalid"
    finally:
        b.unload()


def test_llamacpp_reset_failure_is_error(tmp_path):
    b, _ = fake(LlamaCppBackend, "llamacpp", "fail_reset", tmp_path)
    b.start()
    try:
        with pytest.raises(SafeError) as e:
            b.reset_context()
        assert e.value.code == "llm_reset_failed"
    finally:
        b.unload()


def test_ollama_unverified_unload_raises(tmp_path, monkeypatch):
    import surgic.llm.ollama as om
    monkeypatch.setattr(om.time, "sleep", lambda s: None)
    b, _ = fake(OllamaBackend, "ollama", "fail_unload", tmp_path)
    b.start()
    try:
        b.find("Acme")
        with pytest.raises(SafeError) as e:
            b.reset_context()
        assert e.value.code == "llm_unload_unverified"
    finally:
        b.proc.kill()
        b.proc.wait()


def test_port_in_use_refused(tmp_path):
    b, _ = fake(LlamaCppBackend, "llamacpp", "ok", tmp_path)
    with socket.socket() as s:
        s.bind(("127.0.0.1", b.cfg.port))
        s.listen()
        with pytest.raises(SafeError) as e:
            b.start()
        assert e.value.code == "llm_port_in_use"


def test_server_exit_detected(tmp_path):
    b, _ = fake(LlamaCppBackend, "llamacpp", "ok", tmp_path)
    b.command = lambda: [sys.executable, "-c", "raise SystemExit(4)"]
    with pytest.raises(SafeError) as e:
        b.start()
    assert e.value.code == "llm_server_exited"


def test_llamacpp_command_flags():
    cfg = LLMConfig(model_path="/m.gguf", port=9999, n_ctx=8192)
    cmd = LlamaCppBackend(cfg).command()
    for flag in ("--offline", "--no-webui", "-np", "--cache-reuse"):
        assert flag in cmd
    assert cmd[cmd.index("--host") + 1] == "127.0.0.1"
    assert cmd[cmd.index("-c") + 1] == "8192"


def test_config_rejects_non_loopback():
    with pytest.raises(ValueError):
        LLMConfig(host="0.0.0.0")


def test_mock_backend_requires_opt_in(monkeypatch):
    monkeypatch.delenv("SURGIC_ALLOW_MOCK", raising=False)
    with pytest.raises(SafeError):
        make_backend(LLMConfig(backend="mock"))
