"""SMB share mounts (by IP; credentials resolved by mount_smbfs from the Keychain).

After mounting, the negotiated session is checked with ``smbutil statshares``:
SMB 3.x is required, plus encryption (default) or at least signing. An
insecure session is unmounted and the run stops.
"""
from __future__ import annotations

import json
import os
import re

from ..logging_safe import SafeError
from . import Runner


def share_url(template: str, smb_ip: str) -> str:
    return template.replace("SMB_HOST", smb_ip)


def mount(r: Runner, url: str, mountpoint: str, read_only: bool, require_encryption: bool = True) -> None:
    os.makedirs(mountpoint, exist_ok=True)
    opts = "nobrowse,nodev,nosuid" + (",rdonly" if read_only else "")
    r.run(["mount_smbfs", "-o", opts, url, mountpoint], code="smb_mount_failed", timeout=120)
    if read_only and not is_read_only(mountpoint):
        unmount(r, mountpoint)
        raise SafeError("smb_input_not_read_only")
    problem = transport_problem(r, mountpoint, require_encryption)
    if problem:
        unmount(r, mountpoint)
        raise SafeError("smb_transport_insecure", reason=problem)


_OFF = {"", "none", "off", "false", "no", "0", "disabled"}


def _flatten(obj, out: dict[str, str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _flatten(v, out)
            else:
                out[str(k).upper()] = str(v)
    elif isinstance(obj, list):
        for v in obj:
            _flatten(v, out)


def session_attributes(r: Runner, mountpoint: str) -> dict[str, str]:
    raw = r.out(["smbutil", "statshares", "-m", mountpoint, "-f", "json"], check=False)
    attrs: dict[str, str] = {}
    try:
        _flatten(json.loads(raw or "{}"), attrs)
    except json.JSONDecodeError:
        pass
    return attrs


def _on(attrs: dict[str, str], word: str, current_key: str) -> bool:
    cur = attrs.get(current_key)
    if cur is not None and cur.strip().lower() not in _OFF:
        return True
    return any(word in k and "SUPPORTED" not in k and k != current_key and v.strip().lower() in ("true", "yes", "on")
               for k, v in attrs.items())


def transport_problem(r: Runner, mountpoint: str, require_encryption: bool) -> str:
    """"" if the negotiated SMB session meets policy, else a reason code."""
    attrs = session_attributes(r, mountpoint)
    if not attrs:
        return "smb_session_unknown"
    if not re.match(r"SMB_?3", attrs.get("SMB_VERSION", "").upper()):
        return "smb_version_below_3"
    encrypted = _on(attrs, "ENCRYPT", "SMB_CURR_ENCRYPT_ALGORITHM")
    if require_encryption and not encrypted:
        return "smb_not_encrypted"
    if not encrypted and not _on(attrs, "SIGNING", "SMB_CURR_SIGN_ALGORITHM"):
        return "smb_not_signed"
    return ""


def route_interface(r: Runner, ip: str) -> str:
    out = r.out(["route", "-n", "get", ip], check=False)
    m = re.search(r"^\s*interface:\s*(\S+)", out, re.M)
    return m.group(1) if m else ""


def is_read_only(mountpoint: str) -> bool:
    return bool(os.statvfs(mountpoint).f_flag & os.ST_RDONLY)


def fs_type(r: Runner, mountpoint: str) -> str:
    for line in r.out(["mount"], check=False).splitlines():
        # "//user@10.0.0.5/share on /Volumes/x (smbfs, nodev, ...)"
        if f" on {mountpoint} (" in line:
            return line.split(" (", 1)[1].split(",", 1)[0].rstrip(")")
    return ""


def unmount(r: Runner, mountpoint: str) -> int:
    if not os.path.ismount(mountpoint):
        return 0
    return r.run(["diskutil", "unmount", "force", mountpoint], check=False).returncode
