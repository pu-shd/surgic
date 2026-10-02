"""Host environment controls (macOS): RAM disk, pf, egress capture, SMB, preflight.

All external commands go through a ``Runner`` so tests can assert the exact
commands issued and inject failures. Privileged commands are prefixed with
``sudo -n`` (non-interactive); the operator primes sudo in run.zsh.
"""
from __future__ import annotations

import subprocess
from typing import Callable, Sequence

from ..logging_safe import SafeError

RunFn = Callable[..., subprocess.CompletedProcess]


class Runner:
    def __init__(self, run: RunFn = subprocess.run, popen=subprocess.Popen, sudo: bool = True) -> None:
        self._run = run
        self._popen = popen
        self.sudo = sudo

    def _cmd(self, cmd: Sequence[str], root: bool) -> list[str]:
        return (["sudo", "-n"] if root and self.sudo else []) + list(cmd)

    def run(self, cmd: Sequence[str], root: bool = False, check: bool = True,
            timeout: float = 600, code: str = "command_failed",
            stdin: bytes | None = None) -> subprocess.CompletedProcess:
        full = self._cmd(cmd, root)
        try:
            p = self._run(full, capture_output=True, timeout=timeout, input=stdin)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SafeError(code, step=str(cmd[0])[:64]) from e
        if check and p.returncode != 0:
            raise SafeError(code, step=str(cmd[0])[:64], status=p.returncode)
        return p

    def out(self, cmd: Sequence[str], root: bool = False, **kw) -> str:
        p = self.run(cmd, root=root, **kw)
        return (p.stdout or b"").decode("utf-8", errors="replace")

    def spawn(self, cmd: Sequence[str], root: bool = False):
        return self._popen(self._cmd(cmd, root), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, start_new_session=True)
