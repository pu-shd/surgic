"""Volatile RAM disk lifecycle (hdiutil ram:// device)."""
from __future__ import annotations

import os
import plistlib
import time

from ..logging_safe import SafeError
from . import Runner

SECTOR = 512


def sectors_for(size_gb: int) -> int:
    return size_gb * 1024 * 1024 * 1024 // SECTOR


def create(r: Runner, name: str, size_gb: int) -> str:
    mount = f"/Volumes/{name}"
    if os.path.exists(mount):
        raise SafeError("ramdisk_mount_exists")
    dev = r.out(["hdiutil", "attach", "-nomount", f"ram://{sectors_for(size_gb)}"],
                code="ramdisk_attach_failed").strip().split()[0]
    if not dev.startswith("/dev/disk"):
        raise SafeError("ramdisk_attach_failed")
    r.run(["diskutil", "erasevolume", "HFS+", name, dev], code="ramdisk_format_failed")
    r.run(["mdutil", "-i", "off", mount], root=True, check=False)
    return dev


def ram_backed_device(r: Runner, mount: str) -> str | None:
    """Return the /dev/diskN whose image-path is ram:// and is mounted at ``mount``."""
    info = plistlib.loads(r.run(["hdiutil", "info", "-plist"], code="hdiutil_info_failed").stdout)
    for img in info.get("images", []):
        if not str(img.get("image-path", "")).startswith("ram://"):
            continue
        ents = img.get("system-entities", [])
        if any(e.get("mount-point") == mount for e in ents):
            whole = [e["dev-entry"] for e in ents if "dev-entry" in e]
            return min(whole, key=len) if whole else None
    return None


def ram_devices(r: Runner) -> list[str]:
    info = plistlib.loads(r.run(["hdiutil", "info", "-plist"], code="hdiutil_info_failed").stdout)
    out = []
    for img in info.get("images", []):
        if str(img.get("image-path", "")).startswith("ram://"):
            ents = [e["dev-entry"] for e in img.get("system-entities", []) if "dev-entry" in e]
            if ents:
                out.append(min(ents, key=len))
    return out


def destroy(r: Runner, dev: str, mount: str) -> list[dict]:
    """Unmount, zero-fill the whole device, detach, verify. Returns a step log."""
    log: list[dict] = []

    def step(name: str, cmd: list[str], root: bool = False, check: bool = True) -> None:
        t0 = int(time.time())
        p = r.run(cmd, root=root, check=False, timeout=3600)
        log.append({"step": name, "ts": t0, "status": p.returncode})
        if check and p.returncode != 0:
            raise SafeError("ramdisk_teardown_failed", step=name, status=p.returncode)

    if os.path.ismount(mount):
        step("unmount", ["diskutil", "unmountDisk", "force", dev])
    step("zero_fill", ["diskutil", "zeroDisk", "force", dev])
    step("detach", ["hdiutil", "detach", dev, "-force"])
    still = dev in ram_devices(r)
    log.append({"step": "verify_detached", "ts": int(time.time()), "status": 1 if still else 0})
    if still:
        raise SafeError("ramdisk_still_attached")
    return log
