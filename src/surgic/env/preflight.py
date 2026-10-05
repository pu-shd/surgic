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
from ..paths import is_under
from . import Runner, firewall, ramdisk, smb

SANDBOX_EXEC = "/usr/bin/sandbox-exec"


@dataclass
class Check:
    name: str
    ok: bool
    code: str = ""

    def public(self) -> dict:
        return {"name": self.name, "ok": self.ok, "code": self.code}


_LOOPBACK = re.compile(r"^(127\.\d+\.\d+\.\d+|\[::1\]|localhost):\d+$")


def non_loopback_listeners(lsof_f: str, allowed: list[str]) -> list[str]:
    """Parse ``lsof -F pcPn`` output (full command names may contain spaces,
    so the column format cannot be split reliably)."""
    bad, cmd = [], ""
    for line in lsof_f.splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            cmd = ""
        elif tag == "c":
            cmd = val
        elif tag == "n":
            addr = val.split("->")[0]
            if _LOOPBACK.match(addr) or cmd in allowed:
                continue
            bad.append(cmd or "?")
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


def installed_profile_ids(r: Runner) -> set[str] | str:
    """Device-level configuration profile identifiers (requires root)."""
    p = r.run(["profiles", "show", "-type", "configuration"], root=True, check=False)
    out = (p.stdout or b"").decode("utf-8", errors="replace")
    if p.returncode != 0:
        return "profiles_failed"
    return set(re.findall(r"profileIdentifier:\s*(\S+)", out))


def profiles_present(r: Runner, required: list[str]) -> bool | str:
    ids = installed_profile_ids(r)
    if isinstance(ids, str):
        return ids
    missing = sorted(set(required) - ids)
    return True if not missing else "missing_profiles:" + ",".join(missing)[:100]


def no_vpn_connected(r: Runner) -> bool | str:
    p = r.run(["scutil", "--nc", "list"], check=False)
    if p.returncode != 0:
        return "scutil_failed"
    out = (p.stdout or b"").decode("utf-8", errors="replace")
    connected = [ln for ln in out.splitlines() if "(Connected)" in ln or "(Connecting)" in ln]
    return True if not connected else f"vpn_connected:{len(connected)}"


def active_network_extensions(sysext_out: str) -> list[str]:
    """Bundle IDs of activated+enabled system extensions in the network category."""
    active, section = [], ""
    for ln in sysext_out.splitlines():
        if ln.startswith("---"):
            # "--- com.apple.system_extension.network_extension (Go to 'System Settings ...')"
            parts = ln.lstrip("- ").split()
            section = parts[0] if parts else ""
            continue
        if section == "com.apple.system_extension.network_extension" and "[activated enabled]" in ln:
            m = re.search(r"\s([A-Za-z0-9][\w.-]+)\s+\(", ln)
            active.append(m.group(1) if m else "unknown")
    return active


def no_network_extensions(r: Runner, allowed: list[str]) -> bool | str:
    p = r.run(["systemextensionsctl", "list"], check=False)
    if p.returncode != 0:
        return "systemextensionsctl_failed"
    bad = [b for b in active_network_extensions((p.stdout or b"").decode("utf-8", errors="replace"))
           if b not in allowed]
    return True if not bad else "network_extensions:" + ",".join(sorted(bad))[:100]


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
        problems = firewall.verify(r, cfg.network.smb_share_ip, cfg.network.smb_interface)
        return True if not problems else ",".join(problems)

    add("pf_airgap_ruleset", pf_ok)
    if cfg.network.pf_rules_managed:
        add("pf_rules_file_managed",
            lambda: (lambda p: True if not p else ",".join(p))(
                firewall.check_managed_file(cfg.network.smb_share_ip, cfg.network.smb_interface)))
    if pf.required_profiles:
        add("managed_profiles_installed", lambda: profiles_present(r, pf.required_profiles))
    if pf.require_no_vpn:
        add("no_vpn_connected", lambda: no_vpn_connected(r))
    if pf.require_no_network_extensions:
        add("no_network_extensions", lambda: no_network_extensions(r, pf.allowed_network_extensions))

    def listeners():
        # +c 0: full command names, so the allowlist is not matched on a
        # 9-character prefix another process could share.
        p = r.run(["lsof", "+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-F", "pcPn"],
                  root=True, check=False)
        out = (p.stdout or b"").decode("utf-8", errors="replace")
        # lsof exits 1 with no output and no stderr when nothing matches; any
        # other failure (e.g. sudo refused) must not read as "no listeners".
        if not out.startswith("p") and not (p.returncode == 1 and not (p.stderr or b"").strip()):
            return "lsof_failed"
        bad = non_loopback_listeners(out, pf.allowed_listeners)
        return True if not bad else "listeners:" + ",".join(bad)[:100]

    add("no_external_listeners", listeners)
    if pf.require_wifi_off:
        add("wifi_off", lambda: wifi_power_off(r))
    if pf.require_bluetooth_off:
        add("bluetooth_off", lambda: bluetooth_off(r))
    add("ramdisk_ram_backed", lambda: ramdisk.ram_backed_device(r, st.ramdisk_mount) is not None)
    add("tmpdir_on_ramdisk", lambda: is_under(os.environ.get("TMPDIR", "/tmp"), st.ramdisk_mount))
    add("workspace_on_ramdisk", lambda: os.path.isdir(st.workspace) and is_under(st.workspace, st.ramdisk_mount))
    add("input_share_read_only",
        lambda: os.path.ismount(st.input_mount) and smb.is_read_only(st.input_mount))
    add("input_share_is_smb", lambda: smb.fs_type(r, st.input_mount) == "smbfs")
    add("output_share_is_smb", lambda: smb.fs_type(r, st.output_mount) == "smbfs")

    def smb_secure():
        for m in (st.input_mount, st.output_mount):
            problem = smb.transport_problem(r, m, cfg.network.smb_require_encryption)
            if problem:
                return problem
        return True

    add("smb_transport_secure", smb_secure)

    def smb_route():
        iface = cfg.network.smb_interface
        if not iface:
            return "smb_interface_not_configured"
        return smb.route_interface(r, cfg.network.smb_share_ip) == iface or "smb_route_wrong_interface"

    add("smb_route_on_interface", smb_route)
    add("worker_sandbox", lambda: (cfg.isolation.mode == "sandbox" and os.path.exists(SANDBOX_EXEC))
        or "worker_sandbox_off")

    def airgap_session():
        from .lifecycle import session
        return bool(session(cfg)) or "no_active_airgap_session"

    add("airgap_session_active", airgap_session)
    add("core_dumps_disabled", lambda: resource.getrlimit(resource.RLIMIT_CORE)[0] == 0)
    add("swap_encrypted", lambda: swap_encrypted(r))
    add("llm_loopback_only", lambda: cfg.llm.host in ("127.0.0.1", "::1"))
    if cfg.audit.require_secret_scanners:
        add("gitleaks_present", lambda: shutil.which(cfg.audit.gitleaks_binary) is not None)
        add("trufflehog_present", lambda: shutil.which(cfg.audit.trufflehog_binary) is not None)
    if pf.verify_model_hash:
        add("model_hash_allowlisted",
            lambda: (model_hash is not None and model_hash() in set(cfg.llm.model_sha256))
            or "model_hash_not_allowlisted")

    for c in checks:
        log_event("preflight", ok=c.ok, step=c.name, reason=c.code[:128] or None)
    return checks


def enforce(checks: list[Check]) -> None:
    failed = [c for c in checks if not c.ok]
    if not checks or failed:
        raise SafeError("preflight_failed", count=len(failed))
