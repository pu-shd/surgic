"""macOS pf airgap: render, load, verify, restore."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from importlib import resources

from ..logging_safe import SafeError
from . import Runner

RULES_PATH = "/etc/pf.anchors/airgap.rules"
SYSTEM_PF_CONF = "/etc/pf.conf"


def _on(iface: str) -> str:
    return f"on {iface} " if iface else ""


def render(smb_ip: str, iface: str = "") -> str:
    tmpl = resources.files("surgic.data").joinpath("airgap.rules.tmpl").read_text()
    return tmpl.replace("{{SMB_SHARE_IP}}", smb_ip).replace("{{ON_IFACE}}", _on(iface))


def rules_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def expected_loaded_rules(smb_ip: str, iface: str = "") -> list[str]:
    """`pfctl -sr` normalized output that the template must produce."""
    return [
        "block drop in log all",
        "block drop out log all",
        f"pass out quick {_on(iface)}inet proto tcp from any to {smb_ip} port = 445 flags S/SA keep state",
    ]


def _normalize(sr: str) -> list[str]:
    lines = []
    for ln in sr.splitlines():
        ln = re.sub(r"\s+", " ", ln.strip())
        if ln and not ln.startswith(("No ALTQ", "ALTQ")):
            lines.append(ln)
    return lines


def pf_enabled(r: Runner) -> bool:
    info = r.out(["pfctl", "-s", "info"], root=True, check=False)
    return "Status: Enabled" in info


def check_managed_file(smb_ip: str, iface: str = "", path: str = RULES_PATH) -> list[str]:
    """Problems with a Jamf-deployed ruleset file (empty == compliant)."""
    try:
        st = os.stat(path)
        content = open(path, encoding="utf-8").read()
    except OSError:
        return ["pf_managed_rules_missing"]
    problems = []
    if st.st_uid != 0:
        problems.append("pf_managed_rules_not_root_owned")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        problems.append("pf_managed_rules_writable")
    if content != render(smb_ip, iface):
        problems.append("pf_managed_rules_mismatch")
    return problems


def load(r: Runner, smb_ip: str, iface: str = "", managed: bool = False) -> dict:
    """Install (or, if Jamf-managed, verify) the rules file, load it as the main
    ruleset, and enable pf (token)."""
    text = render(smb_ip, iface)
    was_enabled = pf_enabled(r)
    if managed:
        problems = check_managed_file(smb_ip, iface)
        if problems:
            raise SafeError(problems[0])
    else:
        # Rule text goes via stdin to tee: no shell interpolation.
        r.run(["tee", RULES_PATH], root=True, stdin=text.encode(), code="pf_write_failed")
    r.run(["ifconfig", "pflog0", "create"], root=True, check=False)
    r.run(["pfctl", "-n", "-f", RULES_PATH], root=True, code="pf_syntax_error")
    r.run(["pfctl", "-f", RULES_PATH], root=True, code="pf_load_failed")
    en = r.run(["pfctl", "-E"], root=True, code="pf_enable_failed")
    m = re.search(rb"Token\s*:\s*(\d+)", (en.stderr or b"") + (en.stdout or b""))
    return {"rules_sha256": rules_sha256(text), "was_enabled": was_enabled,
            "token": m.group(1).decode() if m else "", "managed": managed}


def verify(r: Runner, smb_ip: str, iface: str = "") -> list[str]:
    """Return a list of problems (empty == compliant)."""
    problems = []
    if not pf_enabled(r):
        problems.append("pf_disabled")
    loaded = _normalize(r.out(["pfctl", "-s", "rules"], root=True, check=False))
    expected = expected_loaded_rules(smb_ip, iface)
    if loaded != expected:
        extra_pass = [ln for ln in loaded if ln.startswith("pass") and ln not in expected]
        problems.append("pf_extra_pass_rules" if extra_pass else "pf_ruleset_mismatch")
    if any(ln.startswith("anchor") for ln in loaded):
        problems.append("pf_anchor_present")
    ifaces = r.out(["pfctl", "-s", "Interfaces", "-v"], root=True, check=False)
    if not re.search(r"^lo0\s.*\(skip\)", ifaces, re.M):
        problems.append("pf_lo0_not_skipped")
    return problems


def restore(r: Runner, state: dict) -> list[dict]:
    log = []
    p = r.run(["pfctl", "-f", SYSTEM_PF_CONF], root=True, check=False)
    log.append({"step": "pf_restore_rules", "status": p.returncode})
    if state.get("token"):
        p = r.run(["pfctl", "-X", state["token"]], root=True, check=False)
        log.append({"step": "pf_release_token", "status": p.returncode})
    return log
