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

# Absolute paths for every command run as root. sudo matches sudoers rules on the
# resolved path, and the Jamf sudoers generator (surgic.jamf) is built from this
# same table, so the allowlist and the commands actually issued cannot drift.
PRIVILEGED = {
    "pfctl": "/sbin/pfctl",
    "ifconfig": "/sbin/ifconfig",
    "tee": "/usr/bin/tee",
    "tcpdump": "/usr/sbin/tcpdump",
    "kill": "/bin/kill",
    "mdutil": "/usr/bin/mdutil",
    "lsof": "/usr/sbin/lsof",
    "profiles": "/usr/bin/profiles",
}


class Runner:
    def __init__(self, run: RunFn = subprocess.run, popen=subprocess.Popen, sudo: bool = True) -> None:
        self._run = run
        self._popen = popen
        self.sudo = sudo

    def _cmd(self, cmd: Sequence[str], root: bool) -> list[str]:
        cmd = list(cmd)
        if root:
            if cmd[0] not in PRIVILEGED:
                raise SafeError("unlisted_privileged_command", step=str(cmd[0])[:64])
            cmd[0] = PRIVILEGED[cmd[0]]
        return (["sudo", "-n"] if root and self.sudo else []) + cmd

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
