"""Fail-closed environment preflight. Any failed check aborts the run."""
from __future__ import annotations

import json
import os
import re
import resource
import shutil
from dataclasses import dataclass
from typing import Callable

from ..logging_safe import SafeError, log_event
from . import Runner, firewall, ramdisk, smb


@dataclass
class Check:
    name: str
    ok: bool
    code: str = ""

    def public(self) -> dict:
        return {"name": self.name, "ok": self.ok, "code": self.code}


_LOOPBACK = re.compile(r"^(127\.\d+\.\d+\.\d+|\[::1\]|localhost):\d+$")


def non_loopback_listeners(lsof_out: str, allowed: list[str]) -> list[str]:
    bad = []
    for line in lsof_out.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 9:
            continue
        cmd, name = cols[0], cols[8]
        if cols[7] == "UDP":
            addr = name
        else:
            addr = name.split("->")[0]
        if _LOOPBACK.match(addr) or cmd in allowed:
            continue
        bad.append(cmd)
    return sorted(set(bad))


def wifi_power_off(r: Runner) -> bool | str:
    p = r.run(["networksetup", "-listallhardwareports"], check=False)
    ports = (p.stdout or b"").decode("utf-8", errors="replace")
    if p.returncode != 0 or "Hardware Port:" not in ports:
        return "networksetup_failed"
    devs = re.findall(r"Hardware Port: (?:Wi-Fi|AirPort)\nDevice: (\S+)", ports)
    for d in devs:
        if "Off" not in r.out(["networksetup", "-getairportpower", d], check=False):
            return False
    return True


def bluetooth_off(r: Runner) -> bool:
    raw = r.out(["system_profiler", "SPBluetoothDataType", "-json"], check=False, timeout=60)
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return False
    for item in data.get("SPBluetoothDataType", []):
        state = str(item.get("controller_properties", {}).get("controller_state", ""))
        if state and state != "attrib_off":
            return False
    return bool(data.get("SPBluetoothDataType"))


def swap_encrypted(r: Runner) -> bool:
    return "(encrypted)" in r.out(["sysctl", "vm.swapusage"], check=False)


def run_preflight(cfg, r: Runner, model_hash: Callable[[], str] | None = None) -> list[Check]:
    st, pf = cfg.storage, cfg.preflight
    checks: list[Check] = []

    def add(name: str, fn: Callable[[], bool | str]) -> None:
        try:
            res = fn()
            ok, code = (res, "") if isinstance(res, bool) else (False, res)
        except SafeError as e:
            ok, code = False, e.code
        except Exception:  # noqa: BLE001 - content-free by construction
            ok, code = False, "check_error"
        checks.append(Check(name, ok, code if not ok else ""))

    def pf_ok():
        problems = firewall.verify(r, cfg.network.smb_share_ip)
        return True if not problems else ",".join(problems)

    add("pf_airgap_ruleset", pf_ok)

    def listeners():
        p = r.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP"], root=True, check=False)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
        # lsof exits 1 with no output and no stderr when nothing matches; any
        # other failure (e.g. sudo refused) must not read as "no listeners".
        if not out.startswith("COMMAND") and not (p.returncode == 1 and not (p.stderr or b"").strip()):
            return "lsof_failed"
        bad = non_loopback_listeners(out, pf.allowed_listeners)
        return True if not bad else "listeners:" + ",".join(bad)[:100]

    add("no_external_listeners", listeners)
    if pf.require_wifi_off:
        add("wifi_off", lambda: wifi_power_off(r))
    if pf.require_bluetooth_off:
        add("bluetooth_off", lambda: bluetooth_off(r))
    add("ramdisk_ram_backed", lambda: ramdisk.ram_backed_device(r, st.ramdisk_mount) is not None)
    add("tmpdir_on_ramdisk",
        lambda: os.path.realpath(os.environ.get("TMPDIR", "/tmp")).startswith(st.ramdisk_mount))
    add("workspace_on_ramdisk",
        lambda: os.path.isdir(st.workspace) and os.path.realpath(st.workspace).startswith(st.ramdisk_mount))
    add("input_share_read_only",
        lambda: os.path.ismount(st.input_mount) and smb.is_read_only(st.input_mount))
    add("input_share_is_smb", lambda: smb.fs_type(r, st.input_mount) == "smbfs")
    add("output_share_is_smb", lambda: smb.fs_type(r, st.output_mount) == "smbfs")
    add("core_dumps_disabled", lambda: resource.getrlimit(resource.RLIMIT_CORE)[0] == 0)
    add("swap_encrypted", lambda: swap_encrypted(r))
    add("llm_loopback_only", lambda: cfg.llm.host in ("127.0.0.1", "::1"))
    if cfg.audit.require_secret_scanners:
        add("gitleaks_present", lambda: shutil.which(cfg.audit.gitleaks_binary) is not None)
        add("trufflehog_present", lambda: shutil.which(cfg.audit.trufflehog_binary) is not None)
    if pf.verify_model_hash and model_hash is not None:
        add("model_hash_allowlisted",
            lambda: model_hash() in set(cfg.llm.model_sha256) or "model_hash_not_allowlisted")

    for c in checks:
        log_event("preflight", ok=c.ok, step=c.name, reason=c.code[:128] or None)
    return checks


def enforce(checks: list[Check]) -> None:
    failed = [c for c in checks if not c.ok]
    if not checks or failed:
        raise SafeError("preflight_failed", count=len(failed))
