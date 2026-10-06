"""Standalone verifier for manifests and closure records.

A manifest is VERIFIED only together with the closure record of the airgap
session it ran in and the output share it released to. Beyond signatures and
hashes, the verifier rejects runs whose controls were skipped or weakened
(preflight skipped or failed, mock model, unsandboxed parsing, scanners or
model allowlist disabled, ...), aborted runs, files on the share that the
manifest does not list, and manifests the closure does not vouch for.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from .manifest import CLOSURE_SCHEMA, SCHEMA, canonical, sha256_file
from .pcap import PcapError, count_packets, max_caplen
from .signing import load_public, pubkey_fingerprint, verify_sig

REQUIRED_PREFLIGHT = {
    "pf_airgap_ruleset", "no_external_listeners", "wifi_off", "bluetooth_off", "ramdisk_ram_backed",
    "tmpdir_on_ramdisk", "workspace_on_ramdisk", "input_share_read_only", "input_share_is_smb",
    "output_share_is_smb", "smb_transport_secure", "smb_route_on_interface", "core_dumps_disabled",
    "swap_encrypted", "llm_loopback_only", "worker_sandbox", "gitleaks_present", "trufflehog_present",
    "model_hash_allowlisted", "airgap_session_active",
}
REQUIRED_SECURITY = {
    "isolation": "sandbox", "require_secret_scanners": True, "verify_model_hash": True,
    "require_wifi_off": True, "require_bluetooth_off": True, "smb_require_encryption": True,
    "smb_interface_bound": True, "model_allowlisted": True, "in_process_egress_attempts": 0,
}
PRODUCTION_BACKENDS = {"llamacpp", "ollama", "mlx"}
CAPTURE_SNAPLEN = {"egress_audit.pcap": 64, "pflog_blocked.pcap": 96}


def _load_signed(path: str, pubkey_pem: bytes) -> tuple[dict | None, bytes, list[str]]:
    p = Path(path)
    data = p.read_bytes()
    sig_path = Path(str(p) + ".sig")
    if not sig_path.exists():
        return None, data, ["signature_missing"]
    pub = load_public(pubkey_pem)
    if not verify_sig(pub, data, base64.b64decode(sig_path.read_bytes().strip())):
        return None, data, ["signature_invalid"]
    obj = json.loads(data)
    failures = []
    if canonical(obj) != data:
        failures.append("not_canonical")
    if obj.get("signer", {}).get("fingerprint") != pubkey_fingerprint(pub):
        failures.append("signer_fingerprint_mismatch")
    return obj, data, failures


def verify_file(path: str, pubkey_pem: bytes, outputs_dir: str | None = None,
                closure: str | None = None, expect_model: str | None = None) -> list[str]:
    """Return a list of failures; empty means verified."""
    obj, data, failures = _load_signed(path, pubkey_pem)
    if obj is None:
        return failures
    schema = obj.get("schema")
    if schema == SCHEMA:
        failures += _verify_manifest(obj, outputs_dir, expect_model)
        if not closure:
            failures.append("closure_not_provided")
        else:
            failures += _bind(obj, data, closure, pubkey_pem)
    elif schema == CLOSURE_SCHEMA:
        failures += _verify_closure(obj, Path(path).parent)
    else:
        failures.append("unknown_schema")
    return failures


# ---------------------------------------------------------------- manifest
def _verify_manifest(obj: dict, outputs_dir: str | None, expect_model: str | None) -> list[str]:
    failures: list[str] = []
    if obj.get("aborted"):
        failures.append(f"run_aborted:{obj['aborted']}")

    sec = obj.get("security", {})
    for k, want in REQUIRED_SECURITY.items():
        if sec.get(k) != want:
            failures.append(f"weakened_control:{k}")
    llm = obj.get("llm", {})
    if llm.get("backend") not in PRODUCTION_BACKENDS:
        failures.append("non_production_backend")
    if expect_model and llm.get("model_sha256") != expect_model:
        failures.append("model_not_expected")

    pre = obj.get("environment", {}).get("preflight")
    if not isinstance(pre, list):
        failures.append("preflight_not_run")
    else:
        if not all(isinstance(c, dict) and c.get("ok") is True for c in pre):
            failures.append("preflight_not_passed")
        names = {c.get("name") for c in pre if isinstance(c, dict)}
        failures += [f"preflight_missing:{n}" for n in sorted(REQUIRED_PREFLIGHT - names)]

    docs = obj.get("documents", [])
    summary = obj.get("summary", {})
    for s in ("clean", "quarantined", "skipped", "withheld"):
        if summary.get(s, 0) != sum(1 for d in docs if d.get("status") == s):
            failures.append("summary_inconsistent")
            break
    processed = [d for d in docs if d.get("status") != "skipped"]
    batch = max(int(llm.get("batch_size", 1) or 1), 1)
    if processed and (llm.get("context_resets", 0) < len(processed)
                      or llm.get("unloads", 0) < -(-len(processed) // batch)):
        failures.append("llm_isolation_counts_inconsistent")

    if not outputs_dir:
        failures.append("outputs_not_checked")
        return failures
    run_dir = Path(outputs_dir, str(obj.get("run_id", "")))
    clean = {d["doc_id"]: d for d in docs if d.get("status") == "clean"}
    for d in docs:
        if d.get("status") != "clean" and (run_dir / d["doc_id"]).exists():
            failures.append(f"quarantined_output_present:{d['doc_id']}")
    if clean and not run_dir.is_dir():
        failures.append("run_outputs_missing")
    if run_dir.is_dir():
        known_dirs = {d["doc_id"] for d in docs}
        for entry in sorted(run_dir.iterdir()):
            if entry.name not in known_dirs:
                failures.append(f"unlisted_output:{entry.name}")
    for doc_id, d in clean.items():
        if not d.get("outputs"):
            failures.append(f"clean_without_outputs:{doc_id}")
        if not d.get("postscan", {}).get("passed"):
            failures.append(f"clean_without_postscan:{doc_id}")
        listed = {o["name"] for o in d.get("outputs", [])}
        ddir = run_dir / doc_id
        if ddir.is_dir():
            for entry in sorted(ddir.iterdir()):
                if entry.name not in listed:
                    failures.append(f"unlisted_output:{doc_id}/{entry.name}")
        for o in d.get("outputs", []):
            f = ddir / o["name"]
            if not f.is_file() or f.is_symlink():
                failures.append(f"output_missing:{doc_id}")
            elif sha256_file(f) != o["sha256"]:
                failures.append(f"output_hash_mismatch:{doc_id}")
    return failures


def _bind(man: dict, man_bytes: bytes, closure_path: str, pubkey_pem: bytes) -> list[str]:
    cl, _, failures = _load_signed(closure_path, pubkey_pem)
    if cl is None or cl.get("schema") != CLOSURE_SCHEMA:
        return ["closure:" + f for f in (failures or ["unknown_schema"])]
    failures = ["closure:" + f for f in failures + _verify_closure(cl, Path(closure_path).parent)]
    session = man.get("airgap", {}).get("session_id")
    if not session or session != cl.get("session_id"):
        failures.append("airgap_session_mismatch")
    import hashlib
    digest = hashlib.sha256(man_bytes).hexdigest()
    if digest not in {m.get("sha256") for m in cl.get("manifests", [])}:
        failures.append("manifest_not_in_closure")
    if not (cl.get("started_at", 1 << 62) <= man.get("started_at", 0)
            and man.get("finished_at", 1 << 62) <= cl.get("finished_at", 0)):
        failures.append("manifest_outside_airgap_window")
    return failures


# ---------------------------------------------------------------- closure
def _verify_closure(obj: dict, base: Path) -> list[str]:
    from ..env.egress_audit import egress_filter
    from ..env.firewall import render, rules_sha256

    failures: list[str] = []
    if not obj.get("session_id"):
        failures.append("session_id_missing")
    for c in obj.get("captures", []):
        f = base / c["name"]
        if not f.exists():
            failures.append(f"capture_missing:{c['name']}")
            continue
        if sha256_file(f) != c.get("sha256"):
            failures.append(f"capture_hash_mismatch:{c['name']}")
        try:
            if count_packets(str(f)) != c.get("packets"):
                failures.append(f"capture_count_mismatch:{c['name']}")
            limit = CAPTURE_SNAPLEN.get(c["name"])
            if limit is not None and max_caplen(str(f)) > limit:
                failures.append(f"capture_payload_not_truncated:{c['name']}")
        except PcapError:
            failures.append(f"capture_unreadable:{c['name']}")
    names = {c.get("name") for c in obj.get("captures", [])}
    for required in CAPTURE_SNAPLEN:
        if required not in names:
            failures.append(f"capture_not_recorded:{required}")
    smb_ip = obj.get("smb_share_ip", "")
    if not smb_ip or obj.get("capture_filter") != egress_filter(smb_ip):
        failures.append("capture_filter_unexpected")
    elif obj.get("pf", {}).get("rules_sha256") != rules_sha256(render(smb_ip, obj.get("smb_interface", ""))):
        failures.append("pf_rules_unexpected")
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
    return failures
