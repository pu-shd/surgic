"""Packet-capture evidence.

* egress_audit.pcap - every packet on any interface that is NOT to/from the
  approved SMB host and NOT loopback. Expected to contain zero packets.
* pflog_blocked.pcap - packets pf blocked (pflog0); informational evidence that
  the firewall is actively enforcing.
"""
from __future__ import annotations

import os
import time

from ..logging_safe import SafeError
from . import Runner


def egress_filter(smb_ip: str) -> str:
    return f"not host {smb_ip} and not host 127.0.0.1 and not host ::1"


def start(r: Runner, smb_ip: str, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    egress = os.path.join(out_dir, "egress_audit.pcap")
    blocked = os.path.join(out_dir, "pflog_blocked.pcap")
    p1 = r.spawn(["tcpdump", "-U", "-n", "-i", "any", "-w", egress, egress_filter(smb_ip)], root=True)
    p2 = r.spawn(["tcpdump", "-U", "-n", "-i", "pflog0", "-w", blocked], root=True)
    # tcpdump writes the pcap header once the interface is open.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if p1.poll() is not None or p2.poll() is not None:
            raise SafeError("capture_exited")
        if all(os.path.exists(f) and os.path.getsize(f) >= 24 for f in (egress, blocked)):
            return {"egress_pcap": egress, "blocked_pcap": blocked,
                    "egress_pid": p1.pid, "blocked_pid": p2.pid, "filter": egress_filter(smb_ip)}
        time.sleep(0.2)
    raise SafeError("capture_start_timeout")


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True  # exists, owned by root
    except ProcessLookupError:
        return False
    return True


def stop(r: Runner, state: dict) -> list[dict]:
    log = []
    for key in ("egress_pid", "blocked_pid"):
        pid = state.get(key)
        if not pid:
            continue
        was_alive = alive(pid)
        # Signal the sudo wrapper as root; sudo relays SIGINT to tcpdump, which flushes.
        p = r.run(["kill", "-INT", str(pid)], root=True, check=False)
        for _ in range(50):
            if not alive(pid):
                break
            time.sleep(0.1)
        log.append({"step": f"stop_{key}", "status": p.returncode,
                    "was_alive": was_alive, "stopped": not alive(pid)})
    return log
