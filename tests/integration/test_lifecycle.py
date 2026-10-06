"""Airgap up/down orchestration with every macOS facility mocked."""
from __future__ import annotations

import json
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


PAYLOAD = b"exfil.halvorsen-maritime.example"  # e.g. the QNAME of a blocked DNS query


def pcap(n):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i in range(n):
        pkt = bytes(100) + PAYLOAD  # headers, then payload past every snap length
        out += struct.pack("<IIII", i, 0, len(pkt), len(pkt)) + pkt
    return out


SMB_SECURE = json.dumps({"SMB_VERSION": "SMB_3.1.1", "SMB_CURR_ENCRYPT_ALGORITHM": "AES_128_GCM"})


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
    zero = {"rc": 0}

    def info(cmd):
        imgs = [{"image-path": "ram://1", "system-entities": [{"dev-entry": "/dev/disk9"},
                {"dev-entry": "/dev/disk9s1", "mount-point": str(rd)}]}] if devices["attached"] else []
        return plistlib.dumps({"images": imgs})

    def detach(cmd):
        devices["attached"] = False
        return ""

    fr = FakeRun([(("hdiutil", "attach"), 0, "/dev/disk9\n"), (("hdiutil", "info"), 0, info),
                  (("hdiutil", "detach"), 0, detach), (("mount_smbfs",), 0, mount_rule),
                  (("smbutil", "statshares"), 0, SMB_SECURE), (("pfctl", "-E"), 0, "Token : 99")] + pf_rules())

    class ZeroFill(FakeRun):
        def __call__(self, cmd, **kw):
            p = super().__call__(cmd, **kw)
            if "zeroDisk" in cmd:
                p.returncode = zero["rc"]
            return p

    fr.__class__ = ZeroFill

    class P:
        n = 0

        def __init__(self, cmd, **kw):
            P.n += 1
            self.pid = 5000 + P.n
            path = cmd[cmd.index("-w") + 1]
            # egress capture stays empty; pflog sees the blocked probe
            open(path, "wb").write(pcap(0 if "pktap,all" in cmd else 1))

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
    return cfg, Runner(fr, popen=P), fr, zero


def test_up_down_produces_verifiable_closure(env, key_store):
    cfg, r, fr, _ = env
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
    closure = json.loads(open(path).read())
    assert closure["session_id"] == st["session_id"] and closure["smb_share_ip"] == "10.20.30.40"
    # Only header-only copies leave the RAM disk: the blocked packet's payload does not.
    from pathlib import Path
    for c in closure["captures"]:
        assert PAYLOAD not in (Path(path).parent / c["name"]).read_bytes()
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
    cfg, r, _, _ = env
    monkeypatch.setattr(lifecycle, "egress_probe", lambda ip: False)
    with pytest.raises(SafeError) as e:
        lifecycle.up(cfg, r)
    assert e.value.code == "egress_probe_not_blocked"


def test_teardown_keeps_airgap_when_ramdisk_not_wiped(env, key_store):
    cfg, r, fr, zero = env
    before = len(netguard.attempts)
    lifecycle.up(cfg, r)
    del netguard.attempts[before:]
    zero["rc"] = 1  # zero-fill fails
    signer = Signer(key_store)
    with pytest.raises(SafeError) as e:
        lifecycle.down(cfg, r, signer)
    assert e.value.code == "ramdisk_teardown_failed_airgap_kept"
    assert not fr.find("pfctl", "-f", "/etc/pf.conf"), "pf restored while document data may remain"
    assert lifecycle.load_state(cfg)["active"] is True  # retryable
    # Once the wipe succeeds, a retry restores pf and closes the session.
    zero["rc"] = 0
    path = lifecycle.down(cfg, r, signer)
    assert fr.find("pfctl", "-f", "/etc/pf.conf") and not lifecycle.load_state(cfg)["active"]
    assert verify_file(path, signer.public_pem()) == []


def test_capture_dir_must_be_on_ramdisk(env, tmp_path):
    cfg, r, _, _ = env
    cfg.network.capture_dir = str(tmp_path / "persistent" / "audit")
    with pytest.raises(SafeError) as e:
        lifecycle.up(cfg, r)
    assert e.value.code == "capture_dir_not_on_ramdisk"
