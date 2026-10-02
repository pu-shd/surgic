"""Airgap bring-up and teardown, producing a signed closure record.

up:   RAM disk -> pf airgap -> captures -> egress probe -> SMB mounts
down: unmount input -> stop captures -> copy pcaps to output share ->
      zero-fill + detach RAM disk -> restore pf -> signed closure -> unmount output
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import time
from pathlib import Path

from ..audit.manifest import CLOSURE_SCHEMA, sha256_file, write_signed
from ..audit.pcap import PcapError, count_packets
from ..logging_safe import SafeError, log_event
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
    state: dict = {"active": True, "started_at": int(time.time()), "manifests": []}
    _save(cfg, state)
    state["ramdisk_device"] = ramdisk.create(r, st.ramdisk_name, st.ramdisk_size_gb)
    state["ramdisk_size_gb"] = st.ramdisk_size_gb
    _save(cfg, state)
    os.makedirs(st.workspace, exist_ok=True)
    state["pf"] = firewall.load(r, net.smb_share_ip)
    _save(cfg, state)
    state["capture"] = egress_audit.start(r, net.smb_share_ip, net.capture_dir)
    _save(cfg, state)
    if not egress_probe(net.probe_ip):
        raise SafeError("egress_probe_not_blocked")
    state["probe"] = {"ip": net.probe_ip, "blocked": True, "ts": int(time.time())}
    smb.mount(r, smb.share_url(st.input_share, net.smb_share_ip), st.input_mount, read_only=True)
    smb.mount(r, smb.share_url(st.output_share, net.smb_share_ip), st.output_mount, read_only=False)
    state["mounted"] = True
    _save(cfg, state)
    log_event("airgap_up", status="ok")
    return state


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
    closure: dict = {"schema": CLOSURE_SCHEMA, "started_at": state.get("started_at", 0),
                     "manifests": state.get("manifests", []), "steps": [], "captures": []}
    errors: list[str] = []

    # Unmount the input share while captures are still running, then stop them.
    closure["steps"].append({"step": "unmount_input", "status": smb.unmount(r, st.input_mount)})
    closure["steps"] += egress_audit.stop(r, state.get("capture", {}))
    evidence = Path(st.output_mount, "evidence", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    output_ok = os.path.ismount(st.output_mount)
    if output_ok:
        evidence.mkdir(parents=True, exist_ok=True)
    for key in ("egress_pcap", "blocked_pcap"):
        src = state.get("capture", {}).get(key)
        entry = {"name": os.path.basename(src) if src else key, "present": bool(src and os.path.exists(src))}
        if entry["present"]:
            try:
                entry["packets"] = count_packets(src)
            except PcapError:
                entry["packets"] = -1
                errors.append(f"{key}_unreadable")
            entry["sha256"] = sha256_file(src)
            entry["bytes"] = os.path.getsize(src)
            if output_ok:
                shutil.copyfile(src, evidence / entry["name"])
                if sha256_file(evidence / entry["name"]) != entry["sha256"]:
                    errors.append(f"{key}_copy_mismatch")
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
    closure["pf"] = {"rules_sha256": state.get("pf", {}).get("rules_sha256", ""),
                     "restore": firewall.restore(r, state.get("pf", {}))}
    closure["finished_at"] = int(time.time())
    egress = next((c.get("packets") for c in closure["captures"] if c["name"] == "egress_audit.pcap"), None)
    closure["egress_packets"] = egress if isinstance(egress, int) else -1
    closure["errors"] = sorted(set(errors))
    closure["zero_egress"] = closure["egress_packets"] == 0 and not errors

    path = None
    if output_ok:
        path, _ = write_signed(closure, evidence / "closure.json", signer)
        (evidence / "pubkey.pem").write_bytes(signer.public_pem())
    smb.unmount(r, st.output_mount)
    state["active"] = False
    state["closed_at"] = int(time.time())
    _save(cfg, state)
    log_event("airgap_down", status="ok" if closure["zero_egress"] else "errors",
              egress_packets=closure["egress_packets"])
    if not output_ok:
        raise SafeError("output_share_unavailable_for_closure")
    return path
