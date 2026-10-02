"""Optional: real llama-server with a small GGUF (set SURGIC_TEST_GGUF)."""
from __future__ import annotations

import os
import shutil

import pytest

from surgic.config import LLMConfig
from surgic.llm.llamacpp import LlamaCppBackend

GGUF = os.environ.get("SURGIC_TEST_GGUF", "")
pytestmark = pytest.mark.real_model


@pytest.mark.skipif(not (GGUF and os.path.exists(GGUF) and shutil.which("llama-server")),
                    reason="set SURGIC_TEST_GGUF to a small GGUF and install llama-server")
def test_llamacpp_real_structured_output_and_unload():
    b = LlamaCppBackend(LLMConfig(model_path=GGUF, port=18089, n_ctx=4096, max_retries=2))
    b.start()
    try:
        fs = b.find("Our largest client, Halvorsen Maritime, pays $4.2M per year under contract HM-77.")
        assert isinstance(fs, list)  # schema-valid by construction (grammar + pydantic)
        b.reset_context()
        assert b.reset_count == 1
    finally:
        b.unload()
    assert not b.is_loaded()


OLLAMA_MODEL = os.environ.get("SURGIC_TEST_OLLAMA_MODEL", "")


@pytest.mark.skipif(not (OLLAMA_MODEL and shutil.which("ollama")),
                    reason="set SURGIC_TEST_OLLAMA_MODEL to a locally pulled model tag")
def test_ollama_real_structured_output_and_verified_unload():
    from surgic.llm.identity import ollama_digest
    from surgic.llm.ollama import OllamaBackend

    b = OllamaBackend(LLMConfig(backend="ollama", model_path=OLLAMA_MODEL, port=18090, n_ctx=4096,
                                max_retries=2))
    b.start()
    try:
        assert ollama_digest(OLLAMA_MODEL, b.base_url)  # identity for the manifest allowlist
        fs = b.find("Our largest client, Halvorsen Maritime, pays $4.2M per year under contract HM-77.")
        chunk = "Our largest client, Halvorsen Maritime, pays $4.2M per year under contract HM-77."
        assert fs, "model returned no findings for an obviously sensitive sentence"
        assert any(f.text in chunk for f in fs)
        assert b.loaded_models(), "model should be resident after inference"
        b.reset_context()  # verified eviction
        assert b.loaded_models() == []
    finally:
        b.unload()
    assert not b.is_loaded()
