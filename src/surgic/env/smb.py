"""SMB share mounts (by IP; credentials resolved by mount_smbfs from the Keychain)."""
from __future__ import annotations

import os

from ..logging_safe import SafeError
from . import Runner


def share_url(template: str, smb_ip: str) -> str:
    return template.replace("SMB_HOST", smb_ip)


def mount(r: Runner, url: str, mountpoint: str, read_only: bool) -> None:
    os.makedirs(mountpoint, exist_ok=True)
    opts = "nobrowse,nodev,nosuid" + (",rdonly" if read_only else "")
    r.run(["mount_smbfs", "-o", opts, url, mountpoint], code="smb_mount_failed", timeout=120)
    if read_only and not is_read_only(mountpoint):
        unmount(r, mountpoint)
        raise SafeError("smb_input_not_read_only")


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
