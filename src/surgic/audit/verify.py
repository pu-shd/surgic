"""Standalone verifier for manifests and closure records."""
from __future__ import annotations

import base64
import json
from pathlib import Path

from .manifest import CLOSURE_SCHEMA, SCHEMA, canonical, sha256_file
from .pcap import PcapError, count_packets
from .signing import load_public, pubkey_fingerprint, verify_sig


def verify_file(path: str, pubkey_pem: bytes, outputs_dir: str | None = None) -> list[str]:
    """Return a list of failures; empty means verified."""
    p = Path(path)
    data = p.read_bytes()
    failures: list[str] = []
    sig_path = Path(str(p) + ".sig")
    if not sig_path.exists():
        return ["signature_missing"]
    pub = load_public(pubkey_pem)
    if not verify_sig(pub, data, base64.b64decode(sig_path.read_bytes().strip())):
        return ["signature_invalid"]
    obj = json.loads(data)
    if canonical(obj) != data:
        failures.append("not_canonical")
    if obj.get("signer", {}).get("fingerprint") != pubkey_fingerprint(pub):
        failures.append("signer_fingerprint_mismatch")

    schema = obj.get("schema")
    if schema == SCHEMA:
        if outputs_dir:
            for doc in obj.get("documents", []):
                if doc.get("status") != "clean":
                    if Path(outputs_dir, doc["doc_id"]).exists():
                        failures.append(f"quarantined_output_present:{doc['doc_id']}")
                    continue
                if not doc.get("outputs"):
                    failures.append(f"clean_without_outputs:{doc['doc_id']}")
                for o in doc.get("outputs", []):
                    f = Path(outputs_dir, doc["doc_id"], o["name"])
                    if not f.exists():
                        failures.append(f"output_missing:{doc['doc_id']}")
                    elif sha256_file(f) != o["sha256"]:
                        failures.append(f"output_hash_mismatch:{doc['doc_id']}")
                if not doc.get("postscan", {}).get("passed"):
                    failures.append(f"clean_without_postscan:{doc['doc_id']}")
    elif schema == CLOSURE_SCHEMA:
        for c in obj.get("captures", []):
            f = p.parent / c["name"]
            if not f.exists():
                failures.append(f"capture_missing:{c['name']}")
                continue
            if sha256_file(f) != c.get("sha256"):
                failures.append(f"capture_hash_mismatch:{c['name']}")
            try:
                if count_packets(str(f)) != c.get("packets"):
                    failures.append(f"capture_count_mismatch:{c['name']}")
            except PcapError:
                failures.append(f"capture_unreadable:{c['name']}")
        if obj.get("egress_packets") != 0:
            failures.append("egress_detected")
        if not obj.get("probe", {}).get("blocked"):
            failures.append("probe_not_blocked")
        if obj.get("errors"):
            failures.append("closure_errors:" + ",".join(obj["errors"]))
        if obj.get("ramdisk_devices_remaining", 1) != 0:
            failures.append("ramdisk_not_detached")
        rd = obj.get("ramdisk", {})
        steps = {s["step"]: s["status"] for s in rd.get("teardown", [])}
        if steps.get("zero_fill") != 0 or steps.get("detach") != 0:
            failures.append("ramdisk_not_zero_filled")
        blocked = next((c for c in obj.get("captures", []) if c["name"] == "pflog_blocked.pcap"), {})
        if blocked.get("packets", 0) < 1:
            failures.append("no_blocked_packets_observed")
    else:
        failures.append("unknown_schema")
    return failures
