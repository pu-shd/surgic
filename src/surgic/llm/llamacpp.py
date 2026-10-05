"""llama.cpp `llama-server` adapter (Metal), grammar-constrained JSON output."""
from __future__ import annotations

import shutil

import httpx

from ..logging_safe import SafeError
from .backend import ServerProcessBackend


class LlamaCppBackend(ServerProcessBackend):
    name = "llamacpp"

    def command(self) -> list[str]:
        binary = self.cfg.server_binary or shutil.which("llama-server") or "llama-server"
        return [
            binary, "-m", self.cfg.model_path,
            "--host", self.cfg.host, "--port", str(self.cfg.port),
            "-c", str(self.cfg.n_ctx), "-ngl", "999", "-np", "1",
            "--offline", "--no-webui", "--cache-reuse", "0", "--log-disable",
        ]

    def complete_json(self, system: str, user: str) -> str:
        body = {
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.cfg.temperature,
            "cache_prompt": False,
            # Disable reasoning preambles for thinking-capable chat templates (Qwen 3.x).
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "findings", "schema": self.schema, "strict": True}},
        }
        try:
            r = self.client.post(self.base_url + "/v1/chat/completions", json=body)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
            raise SafeError("llm_request_failed", backend=self.name) from e

    def reset_context(self) -> None:
        # Single slot, cache_prompt=false. Additionally erase the slot's KV cache.
        try:
            r = self.client.post(self.base_url + "/slots/0", params={"action": "erase"})
        except httpx.HTTPError as e:
            raise SafeError("llm_reset_failed", backend=self.name) from e
        if r.status_code != 200:
            raise SafeError("llm_reset_failed", backend=self.name, status=r.status_code)
        self.reset_count += 1
