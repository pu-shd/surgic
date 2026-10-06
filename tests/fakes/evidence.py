"""Build a production-shaped signed manifest + closure + output share for
verifier tests (no pipeline run needed)."""
from __future__ import annotations

import struct
from pathlib import Path

from surgic.audit.manifest import CLOSURE_SCHEMA, SCHEMA, sha256_file, write_signed
from surgic.audit.verify import REQUIRED_PREFLIGHT, REQUIRED_SECURITY
from surgic.env.egress_audit import egress_filter
from surgic.env.firewall import render, rules_sha256

SMB = "10.0.0.5"
IFACE = "en7"
SESSION = "a" * 32
RUN = "20260101T000000Z-abcd1234"


def pcap(n: int, size: int = 40) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i in range(n):
        pkt = bytes(size)
        out += struct.pack("<IIII", i, 0, len(pkt), len(pkt)) + pkt
    return out


def build(root: Path, signer, manifest_over: dict | None = None, closure_over: dict | None = None,
          egress_n: int = 0, blocked_n: int = 2, blocked_size: int = 40) -> tuple[str, str, Path]:
    """Returns (manifest path, closure path, share root)."""
    share = root / "share"
    out = share / RUN / "00001-abc"
    out.mkdir(parents=True)
    f = out / "00001-abc.redacted.pdf"
    f.write_bytes(b"clean")
    manifest = {
        "schema": SCHEMA, "run_id": RUN, "started_at": 1000, "finished_at": 2000, "aborted": "",
        "airgap": {"session_id": SESSION, "started_at": 900},
        "security": dict(REQUIRED_SECURITY),
        "llm": {"backend": "ollama", "model_sha256": "m" * 64, "batch_size": 1, "unloads": 2, "context_resets": 2},
        "environment": {"preflight": [{"name": n, "ok": True, "code": ""} for n in sorted(REQUIRED_PREFLIGHT)]},
        "documents": [
            {"doc_id": "00001-abc", "status": "clean", "postscan": {"passed": True},
             "outputs": [{"name": f.name, "sha256": sha256_file(f)}]},
            {"doc_id": "00002-def", "status": "quarantined", "outputs": [], "postscan": {"passed": False}},
            {"doc_id": "00003-ghi", "status": "skipped", "reason": "unsupported_extension"},
        ],
        "summary": {"clean": 1, "quarantined": 1, "skipped": 1, "withheld": 0, "total": 3},
    }
    for k, v in (manifest_over or {}).items():
        manifest[k] = v
    mdir = share / "manifests"
    mdir.mkdir()
    mpath, _ = write_signed(manifest, mdir / f"{RUN}.manifest.json", signer)

    ev = share / "evidence" / "ts"
    ev.mkdir(parents=True)
    (ev / "egress_audit.pcap").write_bytes(pcap(egress_n))
    (ev / "pflog_blocked.pcap").write_bytes(pcap(blocked_n, blocked_size))
    closure = {
        "schema": CLOSURE_SCHEMA, "session_id": SESSION, "started_at": 900, "finished_at": 3000,
        "smb_share_ip": SMB, "smb_interface": IFACE, "capture_filter": egress_filter(SMB),
        "pf": {"rules_sha256": rules_sha256(render(SMB, IFACE)), "restore": []},
        "manifests": [{"name": Path(mpath).name, "sha256": sha256_file(mpath)}],
        "egress_packets": egress_n, "errors": [], "probe": {"blocked": True},
        "ramdisk_devices_remaining": 0,
        "ramdisk": {"teardown": [{"step": "zero_fill", "status": 0}, {"step": "detach", "status": 0}]},
        "captures": [
            {"name": "egress_audit.pcap", "packets": egress_n, "sha256": sha256_file(ev / "egress_audit.pcap")},
            {"name": "pflog_blocked.pcap", "packets": blocked_n, "sha256": sha256_file(ev / "pflog_blocked.pcap")}],
    }
    closure.update(closure_over or {})
    cpath, _ = write_signed(closure, ev / "closure.json", signer)
    return mpath, cpath, share
