"""Environment controls with all macOS commands mocked."""
from __future__ import annotations

import json
import plistlib
import subprocess

import pytest

from surgic.config import Config, NetworkConfig
from surgic.env import Runner, egress_audit, firewall, preflight, ramdisk, smb
from surgic.logging_safe import SafeError

SMB = "10.20.30.40"


class FakeRun:
    """Scripted subprocess.run: rules are (prefix tuple, returncode, stdout)."""

    def __init__(self, rules=()):
        self.rules = list(rules)
        self.calls: list[list[str]] = []
        self.stdin: list[bytes | None] = []

    def __call__(self, cmd, capture_output=True, timeout=None, input=None):
        self.calls.append(list(cmd))
        self.stdin.append(input)
        bare = cmd[2:] if cmd[:2] == ["sudo", "-n"] else cmd
        for prefix, rc, out in self.rules:
            if tuple(bare[:len(prefix)]) == tuple(prefix):
                o = out(bare) if callable(out) else out
                return subprocess.CompletedProcess(cmd, rc, o if isinstance(o, bytes) else o.encode(), b"")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    def find(self, *prefix):
        return [c for c in self.calls if tuple((c[2:] if c[:2] == ["sudo", "-n"] else c)[:len(prefix)]) == prefix]


def hdiutil_plist(mount="/Volumes/RAMDisk", dev="/dev/disk9", ram=True):
    return plistlib.dumps({"images": [{"image-path": "ram://33554432" if ram else "/x.dmg",
                                       "system-entities": [{"dev-entry": dev},
                                                           {"dev-entry": dev + "s1", "mount-point": mount}]}]})


# ---------------------------------------------------------------- ramdisk
def test_ramdisk_create_commands(monkeypatch):
    monkeypatch.setattr(ramdisk.os.path, "exists", lambda p: False)
    fr = FakeRun([(("hdiutil", "attach"), 0, "/dev/disk9   \n")])
    dev = ramdisk.create(Runner(fr), "RAMDisk", 16)
    assert dev == "/dev/disk9"
    assert fr.calls[0] == ["hdiutil", "attach", "-nomount", "ram://33554432"]
    assert fr.calls[1] == ["diskutil", "erasevolume", "HFS+", "RAMDisk", "/dev/disk9"]
    assert fr.find("mdutil", "-i", "off", "/Volumes/RAMDisk")


def test_ramdisk_attach_failure_raises(monkeypatch):
    monkeypatch.setattr(ramdisk.os.path, "exists", lambda p: False)
    fr = FakeRun([(("hdiutil", "attach"), 1, "")])
    with pytest.raises(SafeError) as e:
        ramdisk.create(Runner(fr), "RAMDisk", 16)
    assert e.value.code == "ramdisk_attach_failed"


def test_ram_backed_detection():
    fr = FakeRun([(("hdiutil", "info"), 0, hdiutil_plist())])
    assert ramdisk.ram_backed_device(Runner(fr), "/Volumes/RAMDisk") == "/dev/disk9"
    fr = FakeRun([(("hdiutil", "info"), 0, hdiutil_plist(ram=False))])
    assert ramdisk.ram_backed_device(Runner(fr), "/Volumes/RAMDisk") is None


def test_ramdisk_destroy_zero_fills_then_verifies(monkeypatch):
    monkeypatch.setattr(ramdisk.os.path, "ismount", lambda p: True)
    gone = plistlib.dumps({"images": []})
    fr = FakeRun([(("hdiutil", "info"), 0, gone)])
    log = ramdisk.destroy(Runner(fr), "/dev/disk9", "/Volumes/RAMDisk")
    assert [s["step"] for s in log] == ["unmount", "zero_fill", "detach", "verify_detached"]
    assert all(s["status"] == 0 for s in log)
    assert fr.find("diskutil", "zeroDisk", "force", "/dev/disk9")


def test_ramdisk_destroy_detects_still_attached(monkeypatch):
    monkeypatch.setattr(ramdisk.os.path, "ismount", lambda p: False)
    fr = FakeRun([(("hdiutil", "info"), 0, hdiutil_plist())])
    with pytest.raises(SafeError) as e:
        ramdisk.destroy(Runner(fr), "/dev/disk9", "/Volumes/RAMDisk")
    assert e.value.code == "ramdisk_still_attached"


def test_ramdisk_zero_fill_failure_raises(monkeypatch):
    monkeypatch.setattr(ramdisk.os.path, "ismount", lambda p: False)
    fr = FakeRun([(("diskutil", "zeroDisk"), 1, "")])
    with pytest.raises(SafeError) as e:
        ramdisk.destroy(Runner(fr), "/dev/disk9", "/Volumes/RAMDisk")
    assert e.value.code == "ramdisk_teardown_failed"


# ---------------------------------------------------------------- pf
GOOD_SR = "\n".join(firewall.expected_loaded_rules(SMB)) + "\n"
SKIP = "lo0 (skip)\nen0\n"


def pf_rules(sr=GOOD_SR, enabled=True, ifaces=SKIP):
    return [(("pfctl", "-s", "info"), 0, "Status: Enabled\n" if enabled else "Status: Disabled\n"),
            (("pfctl", "-s", "rules"), 0, sr), (("pfctl", "-s", "Interfaces"), 0, ifaces),
            (("pfctl", "-E"), 0, "")]


def test_render_has_default_deny_and_only_smb_pass():
    text = firewall.render(SMB)
    assert "block drop in log all" in text and "block drop out log all" in text
    passes = [ln for ln in text.splitlines() if ln.startswith("pass")]
    assert passes == [f"pass out quick inet proto tcp from any to {SMB} port 445 flags S/SA keep state"]
    assert "set skip on lo0" in text


def test_pf_load_sequence():
    fr = FakeRun(pf_rules())
    fr.rules.insert(0, (("pfctl", "-E"), 0, "Token : 12345"))
    st = firewall.load(Runner(fr), SMB)
    assert st["token"] == "12345" and st["was_enabled"] is True
    assert fr.find("tee", firewall.RULES_PATH)
    assert fr.stdin[[i for i, c in enumerate(fr.calls) if "tee" in c][0]] == firewall.render(SMB).encode()
    order = [c[2:4] for c in fr.calls if "pfctl" in c and c[3] in ("-n", "-f", "-E")]
    assert order == [["pfctl", "-n"], ["pfctl", "-f"], ["pfctl", "-E"]]
    assert all(c[:2] == ["sudo", "-n"] for c in fr.find("pfctl"))


def test_pf_syntax_error_aborts():
    fr = FakeRun([(("pfctl", "-n"), 1, "")] + pf_rules())
    with pytest.raises(SafeError) as e:
        firewall.load(Runner(fr), SMB)
    assert e.value.code == "pf_syntax_error"
    assert not fr.find("pfctl", "-E")


@pytest.mark.parametrize("rules,problem", [
    (pf_rules(), None),
    (pf_rules(enabled=False), "pf_disabled"),
    (pf_rules(sr=GOOD_SR + "pass out all flags S/SA keep state\n"), "pf_extra_pass_rules"),
    (pf_rules(sr="block drop in log all\n"), "pf_ruleset_mismatch"),
    (pf_rules(sr=GOOD_SR + 'anchor "com.apple/*" all\n'), "pf_anchor_present"),
    (pf_rules(ifaces="lo0\n"), "pf_lo0_not_skipped"),
])
def test_pf_verify(rules, problem):
    problems = firewall.verify(Runner(FakeRun(rules)), SMB)
    assert (problems == []) if problem is None else (problem in problems)


def test_pf_restore():
    fr = FakeRun()
    log = firewall.restore(Runner(fr), {"token": "77"})
    assert fr.find("pfctl", "-f", "/etc/pf.conf") and fr.find("pfctl", "-X", "77")
    assert [s["status"] for s in log] == [0, 0]


# ---------------------------------------------------------------- capture
def test_egress_filter_excludes_only_smb_and_loopback():
    f = egress_audit.egress_filter(SMB)
    assert f == f"not host {SMB} and not host 127.0.0.1 and not host ::1"


def test_capture_start_and_stop(tmp_path, monkeypatch):
    spawned = []

    class P:
        def __init__(self, cmd, **kw):
            spawned.append(cmd)
            self.pid = 4242 + len(spawned)
            path = cmd[cmd.index("-w") + 1]
            open(path, "wb").write(b"\xd4\xc3\xb2\xa1" + bytes(20))

        def poll(self):
            return None

    r = Runner(FakeRun(), popen=P)
    st = egress_audit.start(r, SMB, str(tmp_path))
    assert spawned[0][:4] == ["sudo", "-n", "tcpdump", "-U"]
    assert spawned[0][-1] == egress_audit.egress_filter(SMB)
    assert "pflog0" in spawned[1]
    monkeypatch.setattr(egress_audit, "alive", lambda pid: False)
    fr = FakeRun()
    log = egress_audit.stop(Runner(fr), st)
    assert len(fr.find("kill", "-INT")) == 2 and all(s["stopped"] for s in log)


def test_capture_exit_detected(tmp_path):
    class P:
        pid = 1

        def __init__(self, cmd, **kw):
            pass

        def poll(self):
            return 1

    with pytest.raises(SafeError) as e:
        egress_audit.start(Runner(FakeRun(), popen=P), SMB, str(tmp_path))
    assert e.value.code == "capture_exited"


# ---------------------------------------------------------------- smb
def test_smb_mount_ro_enforced(tmp_path, monkeypatch):
    fr = FakeRun()
    monkeypatch.setattr(smb, "is_read_only", lambda m: False)
    monkeypatch.setattr(smb.os.path, "ismount", lambda m: True)
    with pytest.raises(SafeError) as e:
        smb.mount(Runner(fr), "//u@10.20.30.40/in", str(tmp_path / "in"), read_only=True)
    assert e.value.code == "smb_input_not_read_only"
    assert fr.find("mount_smbfs")[0][2] == "nobrowse,nodev,nosuid,rdonly"
    assert fr.find("diskutil", "unmount")


def test_share_url_and_fs_type():
    assert smb.share_url("//svc@SMB_HOST/x", SMB) == f"//svc@{SMB}/x"
    fr = FakeRun([(("mount",), 0, f"//svc@{SMB}/x on /mnt/in (smbfs, nodev, read-only)\n")])
    assert smb.fs_type(Runner(fr), "/mnt/in") == "smbfs"
    assert smb.fs_type(Runner(fr), "/other") == ""


# ---------------------------------------------------------------- preflight
LSOF = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
llama-ser 101 u   3u  IPv4 0x1      0t0  TCP 127.0.0.1:8088 (LISTEN)
rapportd  102 u   4u  IPv6 0x2      0t0  TCP *:49152 (LISTEN)
mDNSResp  103 u   5u  IPv4 0x3      0t0  UDP *:5353
"""


def test_listener_parsing():
    assert preflight.non_loopback_listeners(LSOF, []) == ["mDNSResp", "rapportd"]
    assert preflight.non_loopback_listeners(LSOF, ["rapportd", "mDNSResp"]) == []


def _listener_check(fr):
    cfg = Config(network=NetworkConfig(smb_share_ip=SMB))
    checks = preflight.run_preflight(cfg, Runner(fr), model_hash=None)
    return next(c for c in checks if c.name == "no_external_listeners")


def test_listener_check_fails_when_lsof_cannot_run():
    class SudoRefused(FakeRun):
        def __call__(self, cmd, **kw):
            p = super().__call__(cmd, **kw)
            if "lsof" in cmd:
                return subprocess.CompletedProcess(cmd, 1, b"", b"sudo: a password is required\n")
            return p

    c = _listener_check(SudoRefused())
    assert not c.ok and c.code == "lsof_failed"


def test_listener_check_no_matches_is_ok():
    c = _listener_check(FakeRun([(("lsof",), 1, "")]))
    assert c.ok


def test_bluetooth_and_wifi_parsing():
    on = json.dumps({"SPBluetoothDataType": [{"controller_properties": {"controller_state": "attrib_on"}}]})
    off = json.dumps({"SPBluetoothDataType": [{"controller_properties": {"controller_state": "attrib_off"}}]})
    assert not preflight.bluetooth_off(Runner(FakeRun([(("system_profiler",), 0, on)])))
    assert preflight.bluetooth_off(Runner(FakeRun([(("system_profiler",), 0, off)])))
    assert not preflight.bluetooth_off(Runner(FakeRun([(("system_profiler",), 0, "")])))
    ports = "Hardware Port: Wi-Fi\nDevice: en1\n"
    fr = FakeRun([(("networksetup", "-listallhardwareports"), 0, ports),
                  (("networksetup", "-getairportpower"), 0, "Wi-Fi Power (en1): On")])
    assert preflight.wifi_power_off(Runner(fr)) is False
    assert preflight.wifi_power_off(Runner(FakeRun([(("networksetup",), 1, "")]))) == "networksetup_failed"
    wired_only = FakeRun([(("networksetup", "-listallhardwareports"), 0, "Hardware Port: Ethernet\nDevice: en0\n")])
    assert preflight.wifi_power_off(Runner(wired_only)) is True


def _cfg(tmp_path):
    cfg = Config(network=NetworkConfig(smb_share_ip=SMB))
    cfg.audit.require_secret_scanners = True
    cfg.llm.model_sha256 = ["good"]
    return cfg


def test_preflight_all_fail_closed_on_hostile_host(tmp_path):
    fr = FakeRun(pf_rules(enabled=False) + [(("lsof",), 0, LSOF), (("hdiutil", "info"), 0, plistlib.dumps({}))])
    checks = preflight.run_preflight(_cfg(tmp_path), Runner(fr), model_hash=lambda: "bad")
    by = {c.name: c for c in checks}
    for name in ("pf_airgap_ruleset", "no_external_listeners", "ramdisk_ram_backed",
                 "input_share_read_only", "model_hash_allowlisted", "bluetooth_off"):
        assert not by[name].ok, name
    assert by["llm_loopback_only"].ok
    with pytest.raises(SafeError) as e:
        preflight.enforce(checks)
    assert e.value.code == "preflight_failed"


def test_preflight_enforce_empty_is_failure():
    with pytest.raises(SafeError):
        preflight.enforce([])


def test_preflight_passes_when_compliant(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    cfg.audit.require_secret_scanners = False
    rd = "/Volumes/RAMDisk"
    monkeypatch.setenv("TMPDIR", rd)
    monkeypatch.setattr(preflight.os.path, "realpath", lambda p: p)
    monkeypatch.setattr(preflight.os.path, "isdir", lambda p: True)
    monkeypatch.setattr(preflight.os.path, "ismount", lambda p: True)
    monkeypatch.setattr(preflight.smb, "is_read_only", lambda p: True)
    monkeypatch.setattr(preflight.resource, "getrlimit", lambda r: (0, 0))
    mounts = (f"//s@{SMB}/in on {cfg.storage.input_mount} (smbfs, read-only)\n"
              f"//s@{SMB}/out on {cfg.storage.output_mount} (smbfs)\n")
    bt = json.dumps({"SPBluetoothDataType": [{"controller_properties": {"controller_state": "attrib_off"}}]})
    fr = FakeRun(pf_rules() + [
        (("lsof",), 0, LSOF.splitlines()[0] + "\n" + LSOF.splitlines()[1] + "\n"),
        (("hdiutil", "info"), 0, hdiutil_plist(rd)), (("mount",), 0, mounts),
        (("system_profiler",), 0, bt), (("sysctl", "vm.swapusage"), 0, "total = 0M (encrypted)"),
        (("networksetup", "-listallhardwareports"), 0, "Hardware Port: Wi-Fi\nDevice: en1\n"),
        (("networksetup", "-getairportpower"), 0, "Wi-Fi Power (en1): Off")])
    checks = preflight.run_preflight(cfg, Runner(fr), model_hash=lambda: "good")
    failed = [c.name for c in checks if not c.ok]
    assert failed == []
    assert len(checks) >= 14
    preflight.enforce(checks)
