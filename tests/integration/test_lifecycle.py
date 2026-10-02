"""Airgap up/down orchestration with every macOS facility mocked."""
from __future__ import annotations

import plistlib
import struct

import pytest

from surgic import netguard
from surgic.audit.signing import Signer
from surgic.audit.verify import verify_file
from surgic.config import Config, NetworkConfig, StorageConfig
from surgic.env import Runner, lifecycle
from surgic.logging_safe import SafeError
from unit.test_env import FakeRun, pf_rules


def pcap(n):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i in range(n):
        out += struct.pack("<IIII", i, 0, 4, 4) + b"abcd"
    return out


@pytest.fixture
def env(tmp_path, monkeypatch):
    rd = tmp_path / "ramdisk"
    cfg = Config(network=NetworkConfig(smb_share_ip="10.20.30.40", capture_dir=str(rd / "audit")),
                 storage=StorageConfig(input_mount=str(tmp_path / "mnt/in"), output_mount=str(tmp_path / "mnt/out"),
                                       state_file=str(tmp_path / "state.json")))
    monkeypatch.setattr(type(cfg.storage), "ramdisk_mount", property(lambda s: str(rd)))
    mounted = set()

    def mount_rule(cmd):
        mounted.add(cmd[-1])
        return ""

    devices = {"attached": True}

    def info(cmd):
        imgs = [{"image-path": "ram://1", "system-entities": [{"dev-entry": "/dev/disk9"},
                {"dev-entry": "/dev/disk9s1", "mount-point": str(rd)}]}] if devices["attached"] else []
        return plistlib.dumps({"images": imgs})

    def detach(cmd):
        devices["attached"] = False
        return ""

    fr = FakeRun([(("hdiutil", "attach"), 0, "/dev/disk9\n"), (("hdiutil", "info"), 0, info),
                  (("hdiutil", "detach"), 0, detach), (("mount_smbfs",), 0, mount_rule),
                  (("pfctl", "-E"), 0, "Token : 99")] + pf_rules())

    class P:
        n = 0

        def __init__(self, cmd, **kw):
            P.n += 1
            self.pid = 5000 + P.n
            path = cmd[cmd.index("-w") + 1]
            # egress capture stays empty; pflog sees the blocked probe
            open(path, "wb").write(pcap(0 if "any" in cmd else 1))

        def poll(self):
            return None

    # os.path is one shared module: a single patch covers lifecycle/smb/ramdisk.
    monkeypatch.setattr(lifecycle.os.path, "ismount", lambda p: p in mounted)
    monkeypatch.setattr(lifecycle.smb, "is_read_only", lambda p: True)
    monkeypatch.setattr(lifecycle.egress_audit, "alive", lambda pid: False)

    def unmount(r, m):
        fr.calls.append(["UNMOUNT", m])
        mounted.discard(m)
        return 0

    monkeypatch.setattr(lifecycle.smb, "unmount", unmount)
    (tmp_path / "mnt/out").mkdir(parents=True)
    rd.mkdir()
    return cfg, Runner(fr, popen=P), fr


def test_up_down_produces_verifiable_closure(env, key_store):
    cfg, r, fr = env
    before = len(netguard.attempts)
    st = lifecycle.up(cfg, r)
    del netguard.attempts[before:]  # the probe is an intentional, blocked attempt
    assert st["probe"]["blocked"] and st["pf"]["token"] == "99" and st["mounted"]
    assert fr.find("mount_smbfs")[0][2].endswith("rdonly")
    with pytest.raises(SafeError):
        lifecycle.up(cfg, r)  # already active

    signer = Signer(key_store)
    path = lifecycle.down(cfg, r, signer)
    assert path and path.endswith("closure.json")
    assert verify_file(path, signer.public_pem()) == []
    # teardown order: captures stopped before ramdisk destroyed; pf restored after
    flat = [" ".join(c) for c in fr.calls]
    i_kill = max(i for i, c in enumerate(flat) if "kill -INT" in c)
    i_zero = next(i for i, c in enumerate(flat) if "zeroDisk" in c)
    i_pf = next(i for i, c in enumerate(flat) if "pfctl -f /etc/pf.conf" in c)
    i_unmount_in = flat.index(f"UNMOUNT {cfg.storage.input_mount}")
    i_first_kill = min(i for i, c in enumerate(flat) if "kill -INT" in c)
    assert i_unmount_in < i_first_kill <= i_kill < i_zero < i_pf
    assert lifecycle.down(cfg, r, signer) is None  # idempotent


def test_probe_not_blocked_aborts(env, monkeypatch):
    cfg, r, _ = env
    monkeypatch.setattr(lifecycle, "egress_probe", lambda ip: False)
    with pytest.raises(SafeError) as e:
        lifecycle.up(cfg, r)
    assert e.value.code == "egress_probe_not_blocked"
