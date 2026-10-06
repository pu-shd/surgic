"""Packet-capture evidence.

* egress_audit.pcap - every packet on every interface (macOS ``pktap,all``,
  which includes tunnel interfaces) except TCP 445 and ARP with the approved
  SMB host and loopback traffic. Expected to contain zero packets.
* pflog_blocked.pcap - packets pf blocked (pflog0); evidence that the firewall
  is actively enforcing.

Only headers are kept: pflog is captured with a short snap length, and both
files are truncated again when copied off the RAM disk, so the payload of a
blocked packet (a DNS query naming a host taken from a document, say) never
reaches the output share.
"""
from __future__ import annotations

import os
import time

from ..logging_safe import SafeError
from . import Runner


# Bytes kept per packet: link header + IPv4 header + transport ports/flags.
# pktap/pcapng on "pktap,all" stores Ethernet frames (14 + 20 + 30 = 64);
# pflog's header is 64 bytes (64 + 20 + 12 = 96).
EGRESS_SNAPLEN = 64
PFLOG_SNAPLEN = 96
EGRESS_INTERFACE = "pktap,all"


def egress_filter(smb_ip: str) -> str:
    return (f"not (host {smb_ip} and (tcp port 445 or arp)) "
            "and not host 127.0.0.1 and not host ::1")


def start(r: Runner, smb_ip: str, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    egress = os.path.join(out_dir, "egress_audit.pcap")
    blocked = os.path.join(out_dir, "pflog_blocked.pcap")
    p1 = r.spawn(["tcpdump", "-U", "-n", "-i", EGRESS_INTERFACE, "-w", egress, egress_filter(smb_ip)], root=True)
    p2 = r.spawn(["tcpdump", "-U", "-n", "-s", str(PFLOG_SNAPLEN), "-i", "pflog0", "-w", blocked], root=True)
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
