"""Airgap bring-up and teardown, producing a signed closure record.

up:   RAM disk -> pf airgap -> captures -> egress probe -> SMB mounts
down: unmount input -> stop captures -> copy header-only pcaps to output share ->
      zero-fill + detach RAM disk -> restore pf -> signed closure -> unmount output

Fail closed: if the RAM disk cannot be verifiably wiped and detached, pf is
NOT restored (the airgap stays up), the closure records why, and the session
stays active so `surgic down` can be retried.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import time
import uuid
from pathlib import Path

from ..audit.manifest import CLOSURE_SCHEMA, sha256_file, write_signed
from ..audit.pcap import PcapError, count_packets, truncate
from ..logging_safe import SafeError, log_event
from ..paths import is_under
from . import Runner, egress_audit, firewall, ramdisk, smb


def egress_probe(ip: str, port: int = 443, timeout: float = 3.0) -> bool:
    """True if the probe was blocked (connection did not succeed)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) != 0
    except OSError:
        return True
    finally:
        s.close()


def _save(cfg, state: dict) -> None:
    p = Path(cfg.storage.state_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2, sort_keys=True))
    os.chmod(p, 0o600)


def load_state(cfg) -> dict:
    p = Path(cfg.storage.state_file)
    return json.loads(p.read_text()) if p.exists() else {}


def up(cfg, r: Runner) -> dict:
    st, net = cfg.storage, cfg.network
    if load_state(cfg).get("active"):
        raise SafeError("airgap_already_active")
    if not is_under(cfg.capture_dir, st.ramdisk_mount) or os.path.realpath(cfg.capture_dir) == os.path.realpath(st.ramdisk_mount):
        raise SafeError("capture_dir_not_on_ramdisk")
    state: dict = {"active": True, "session_id": uuid.uuid4().hex, "started_at": int(time.time()),
                   "manifests": []}
    _save(cfg, state)
    state["ramdisk_device"] = ramdisk.create(r, st.ramdisk_name, st.ramdisk_size_gb)
    state["ramdisk_size_gb"] = st.ramdisk_size_gb
    _save(cfg, state)
    os.makedirs(st.workspace, exist_ok=True)
    state["pf"] = firewall.load(r, net.smb_share_ip, net.smb_interface, managed=net.pf_rules_managed)
    _save(cfg, state)
    state["capture"] = egress_audit.start(r, net.smb_share_ip, cfg.capture_dir)
    _save(cfg, state)
    if not egress_probe(net.probe_ip):
        raise SafeError("egress_probe_not_blocked")
    state["probe"] = {"ip": net.probe_ip, "blocked": True, "ts": int(time.time())}
    enc = net.smb_require_encryption
    smb.mount(r, smb.share_url(st.input_share, net.smb_share_ip), st.input_mount, read_only=True,
              require_encryption=enc)
    smb.mount(r, smb.share_url(st.output_share, net.smb_share_ip), st.output_mount, read_only=False,
              require_encryption=enc)
    state["mounted"] = True
    _save(cfg, state)
    log_event("airgap_up", status="ok")
    return state


def session(cfg) -> dict:
    """The active airgap session, for binding a run's manifest to its closure."""
    st = load_state(cfg)
    if not st.get("active") or not st.get("session_id"):
        return {}
    return {"session_id": st["session_id"], "started_at": st.get("started_at", 0)}


def record_manifest(cfg, path: str) -> None:
    state = load_state(cfg)
    state.setdefault("manifests", []).append({"name": Path(path).name, "sha256": sha256_file(path)})
    _save(cfg, state)


def down(cfg, r: Runner, signer) -> str | None:
    """Idempotent teardown. Returns the closure path (None if nothing to close)."""
    st, net = cfg.storage, cfg.network
    state = load_state(cfg)
    if not state.get("active"):
        return None
    closure: dict = {"schema": CLOSURE_SCHEMA, "session_id": state.get("session_id", ""),
                     "started_at": state.get("started_at", 0), "smb_share_ip": net.smb_share_ip,
                     "smb_interface": net.smb_interface, "manifests": state.get("manifests", []),
                     "steps": [], "captures": []}
    errors: list[str] = []

    # Unmount the input share while captures are still running, then stop them.
    closure["steps"].append({"step": "unmount_input", "status": smb.unmount(r, st.input_mount)})
    closure["steps"] += egress_audit.stop(r, state.get("capture", {}))
    evidence = Path(st.output_mount, "evidence", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    output_ok = os.path.ismount(st.output_mount)
    if output_ok:
        evidence.mkdir(parents=True, exist_ok=True)
    snaplens = {"egress_pcap": egress_audit.EGRESS_SNAPLEN, "blocked_pcap": egress_audit.PFLOG_SNAPLEN}
    for key in ("egress_pcap", "blocked_pcap"):
        src = state.get("capture", {}).get(key)
        entry = {"name": os.path.basename(src) if src else key, "present": bool(src and os.path.exists(src)),
                 "snaplen": snaplens[key]}
        if entry["present"]:
            # Header-only copy, made on the RAM disk; only it leaves the machine.
            hdr = f"{src}.headers"
            try:
                entry["packets"] = count_packets(src)
                if truncate(src, hdr, snaplens[key]) != entry["packets"]:
                    errors.append(f"{key}_truncate_mismatch")
                entry["sha256"] = sha256_file(hdr)
                entry["bytes"] = os.path.getsize(hdr)
                if output_ok:
                    shutil.copyfile(hdr, evidence / entry["name"])
                    if sha256_file(evidence / entry["name"]) != entry["sha256"]:
                        errors.append(f"{key}_copy_mismatch")
            except PcapError:
                entry["packets"] = -1
                errors.append(f"{key}_unreadable")
        else:
            errors.append(f"{key}_missing")
        closure["captures"].append(entry)
    closure["capture_filter"] = state.get("capture", {}).get("filter", "")
    closure["probe"] = state.get("probe", {})

    dev = state.get("ramdisk_device")
    if dev:
        try:
            closure["ramdisk"] = {"device": dev, "size_gb": state.get("ramdisk_size_gb", 0),
                                  "teardown": ramdisk.destroy(r, dev, st.ramdisk_mount)}
        except SafeError as e:
            errors.append(e.code)
            closure["ramdisk"] = {"device": dev, "teardown_error": e.code}
    closure["ramdisk_devices_remaining"] = len(ramdisk.ram_devices(r))
    wiped = "ramdisk" in closure and "teardown" in closure["ramdisk"] or not dev
    if wiped:
        restore = firewall.restore(r, state.get("pf", {}))
    else:
        # Document data may still be in RAM: keep the airgap up.
        restore = [{"step": "pf_restore_withheld", "status": 1}]
        errors.append("airgap_kept_ramdisk_not_wiped")
    closure["pf"] = {"rules_sha256": state.get("pf", {}).get("rules_sha256", ""), "restore": restore}
    closure["finished_at"] = int(time.time())
    egress = next((c.get("packets") for c in closure["captures"] if c["name"] == "egress_audit.pcap"), None)
    closure["egress_packets"] = egress if isinstance(egress, int) else -1
    closure["errors"] = sorted(set(errors))
    closure["zero_egress"] = closure["egress_packets"] == 0 and not errors

    path = None
    if output_ok:
        path, _ = write_signed(closure, evidence / "closure.json", signer)
        (evidence / signer.export_name).write_bytes(signer.export_pem())
    if wiped:
        smb.unmount(r, st.output_mount)
        state["active"] = False
        state["closed_at"] = int(time.time())
    # else: airgap and output share stay up so `surgic down` can be retried
    # (and sign a new closure) once the RAM disk can be wiped.
    _save(cfg, state)
    log_event("airgap_down", status="ok" if closure["zero_egress"] else "errors",
              egress_packets=closure["egress_packets"])
    if not wiped:
        raise SafeError("ramdisk_teardown_failed_airgap_kept")
    if not output_ok:
        raise SafeError("output_share_unavailable_for_closure")
    return path
