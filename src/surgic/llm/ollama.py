"""Ollama adapter. Spawns a private `ollama serve` bound to loopback.

Unload is requested with keep_alive=0 and verified via /api/ps. Ollama keeps
the KV cache of a loaded runner, so reset_context performs a verified unload.
"""
from __future__ import annotations

import shutil
import time

import httpx

from ..logging_safe import SafeError, log_event
from .backend import ServerProcessBackend


class OllamaBackend(ServerProcessBackend):
    name = "ollama"

    def command(self) -> list[str]:
        binary = self.cfg.server_binary or shutil.which("ollama") or "ollama"
        return [binary, "serve"]

    def extra_env(self) -> dict[str, str]:
        return {"OLLAMA_HOST": f"{self.cfg.host}:{self.cfg.port}", "OLLAMA_KEEP_ALIVE": "0",
                "OLLAMA_NUM_PARALLEL": "1", "OLLAMA_NOPRUNE": "1"}

    def health_path(self) -> str:
        return "/api/version"

    def complete_json(self, system: str, user: str) -> str:
        body = {
            "model": self.cfg.model_path,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "format": self.schema,
            # Reasoning models (e.g. Qwen 3.x) otherwise spend the whole output
            # budget "thinking" and return empty content. Thinking text would
            # also be document-derived output the pipeline has no use for.
            "think": False,
            "stream": False,
            "keep_alive": "10m",
            "options": {"temperature": self.cfg.temperature, "num_ctx": self.cfg.n_ctx},
        }
        try:
            r = self.client.post(self.base_url + "/api/chat", json=body)
            r.raise_for_status()
            return r.json()["message"]["content"]
        except (httpx.HTTPError, KeyError, ValueError) as e:
            raise SafeError("llm_request_failed", backend=self.name) from e

    def loaded_models(self) -> list[str]:
        r = self.client.get(self.base_url + "/api/ps")
        r.raise_for_status()
        return [m.get("name", "") for m in r.json().get("models", [])]

    def _evict(self) -> None:
        try:
            self.client.post(self.base_url + "/api/generate",
                             json={"model": self.cfg.model_path, "keep_alive": 0, "prompt": ""})
            for _ in range(120):
                if not self.loaded_models():
                    return
                time.sleep(0.5)
        except httpx.HTTPError as e:
            raise SafeError("llm_unload_unverified", backend=self.name) from e
        raise SafeError("llm_unload_unverified", backend=self.name)

    def reset_context(self) -> None:
        if self.is_loaded():
            self._evict()
        self.reset_count += 1
        log_event("llm_context_reset", backend=self.name)

    def unload(self) -> None:
        if self.is_loaded():
            self._evict()
        super().unload()
