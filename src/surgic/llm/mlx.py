"""mlx-lm `mlx_lm.server` adapter (OpenAI-compatible, Apple MLX).

mlx_lm.server keeps a prompt cache across requests and has no API to purge
it, so reset_context restarts the server process (weights reload from the OS
page cache, typically seconds). Output is not grammar-constrained: the shared
driver validates against the schema and retries.
"""
from __future__ import annotations

import shutil

import httpx

from ..logging_safe import SafeError
from .backend import ServerProcessBackend


class MlxBackend(ServerProcessBackend):
    name = "mlx"

    def command(self) -> list[str]:
        binary = self.cfg.server_binary or shutil.which("mlx_lm.server") or "mlx_lm.server"
        return [binary, "--model", self.cfg.model_path,
                "--host", self.cfg.host, "--port", str(self.cfg.port)]

    def health_path(self) -> str:
        return "/v1/models"

    def complete_json(self, system: str, user: str) -> str:
        body = {
            "messages": [
                {"role": "system", "content": system + "\nRespond with a single JSON object only."},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
            "max_tokens": 4096,
        }
        try:
            r = self.client.post(self.base_url + "/v1/chat/completions", json=body)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
            raise SafeError("llm_request_failed", backend=self.name) from e
        # Tolerate code fences around the JSON object.
        a, b = content.find("{"), content.rfind("}")
        return content[a:b + 1] if a != -1 and b > a else content

    def reset_context(self) -> None:
        self.unload()
        self.start()
        self.reset_count += 1
