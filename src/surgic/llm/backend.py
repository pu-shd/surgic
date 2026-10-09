"""LLM backend protocol, shared process/HTTP plumbing, and the Phase B driver."""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import time
from abc import ABC, abstractmethod

import httpx
from pydantic import ValidationError

from ..logging_safe import SafeError, log_event
from . import guard, prompts
from .schema import Finding, Findings, json_schema

OFFLINE_ENV = {
    "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1", "OLLAMA_NOHISTORY": "1",
}


def port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


class LLMBackend(ABC):
    name: str = "abstract"

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        self.base_url = f"http://{cfg.host}:{cfg.port}"
        self.schema = json_schema()
        self.unload_count = 0
        self.reset_count = 0

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def complete_json(self, system: str, user: str) -> str:
        """Return the raw JSON text produced by the model."""

    @abstractmethod
    def reset_context(self) -> None:
        """Purge any per-request state (KV/prompt cache) between documents."""

    @abstractmethod
    def unload(self) -> None:
        """Release model weights; must raise SafeError if not verifiably unloaded."""

    @abstractmethod
    def is_loaded(self) -> bool: ...

    def identity(self) -> dict:
        return {"backend": self.name, "model": os.path.basename(self.cfg.model_path)}

    # ---- Phase B driver -------------------------------------------------
    def find(self, chunk: str) -> list[Finding]:
        for attempt in range(self.cfg.max_retries + 1):
            # A fresh, unguessable boundary per request: document text cannot close it.
            user = prompts.user_message(chunk, guard.new_boundary(chunk))
            raw = self.complete_json(prompts.SYSTEM, user)
            try:
                return Findings.model_validate(json.loads(raw)).findings
            except (json.JSONDecodeError, ValidationError, TypeError):
                log_event("llm_output_invalid", attempt=attempt, backend=self.name)
        raise SafeError("llm_output_invalid", backend=self.name)


class ServerProcessBackend(LLMBackend):
    """Backend that owns a local server process bound to loopback."""

    def __init__(self, cfg, popen=subprocess.Popen) -> None:
        super().__init__(cfg)
        self._popen = popen
        self.proc: subprocess.Popen | None = None
        self.client = httpx.Client(timeout=cfg.request_timeout_s, trust_env=False)

    @abstractmethod
    def command(self) -> list[str]: ...

    def health_path(self) -> str:
        return "/health"

    def extra_env(self) -> dict[str, str]:
        return {}

    def start(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        if port_open(self.cfg.host, self.cfg.port):
            raise SafeError("llm_port_in_use", backend=self.name)
        env = {**os.environ, **OFFLINE_ENV, **self.extra_env()}
        self.proc = self._popen(self.command(), env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise SafeError("llm_server_exited", backend=self.name)
            try:
                if self.client.get(self.base_url + self.health_path()).status_code == 200:
                    log_event("llm_started", backend=self.name)
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise SafeError("llm_start_timeout", backend=self.name)

    def is_loaded(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def unload(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=30)
        if self.proc.poll() is None or port_open(self.cfg.host, self.cfg.port):
            raise SafeError("llm_unload_unverified", backend=self.name)
        self.proc = None
        self.unload_count += 1
        log_event("llm_unloaded", backend=self.name)


def make_backend(cfg) -> LLMBackend:
    if cfg.backend == "llamacpp":
        from .llamacpp import LlamaCppBackend
        return LlamaCppBackend(cfg)
    if cfg.backend == "ollama":
        from .ollama import OllamaBackend
        return OllamaBackend(cfg)
    if cfg.backend == "mlx":
        from .mlx import MlxBackend
        return MlxBackend(cfg)
    if cfg.backend == "mock":
        if os.environ.get("SURGIC_ALLOW_MOCK") != "1":
            raise SafeError("mock_backend_not_allowed")
        from .mock import MockBackend
        return MockBackend(cfg)
    raise SafeError("unknown_backend")
