"""In-process egress guard (defense in depth beneath pf).

Once installed, any attempt by this Python process (or a library it loads) to
connect/send to a non-loopback address or resolve a non-local hostname raises
``EgressBlocked`` and is counted. pf remains the authoritative control; this
guard makes library phone-home behavior fail loudly and testably.
"""
from __future__ import annotations

import ipaddress
import socket
import threading

_lock = threading.Lock()
_installed = False
attempts: list[str] = []  # address family/kind only, never payloads

_orig = {}


class EgressBlocked(OSError):
    pass


def _is_local(addr) -> bool:
    if isinstance(addr, (str, bytes)):  # AF_UNIX path
        return True
    host = addr[0] if isinstance(addr, tuple) and addr else ""
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


def _block(kind: str):
    attempts.append(kind)
    raise EgressBlocked(f"egress blocked by surgic netguard ({kind})")


def install() -> None:
    global _installed
    with _lock:
        if _installed:
            return
        _orig["connect"] = socket.socket.connect
        _orig["connect_ex"] = socket.socket.connect_ex
        _orig["sendto"] = socket.socket.sendto
        _orig["getaddrinfo"] = socket.getaddrinfo

        def connect(self, addr):
            if self.family in (socket.AF_INET, socket.AF_INET6) and not _is_local(addr):
                _block("connect")
            return _orig["connect"](self, addr)

        def connect_ex(self, addr):
            if self.family in (socket.AF_INET, socket.AF_INET6) and not _is_local(addr):
                _block("connect_ex")
            return _orig["connect_ex"](self, addr)

        def sendto(self, data, *args):
            addr = args[-1]
            if self.family in (socket.AF_INET, socket.AF_INET6) and not _is_local(addr):
                _block("sendto")
            return _orig["sendto"](self, data, *args)

        def getaddrinfo(host, *a, **kw):
            h = host.decode() if isinstance(host, bytes) else host
            if h is not None and not _is_local((h,)):
                _block("dns")
            return _orig["getaddrinfo"](host, *a, **kw)

        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        socket.socket.sendto = sendto
        socket.getaddrinfo = getaddrinfo
        _installed = True


def uninstall() -> None:
    global _installed
    with _lock:
        if not _installed:
            return
        socket.socket.connect = _orig["connect"]
        socket.socket.connect_ex = _orig["connect_ex"]
        socket.socket.sendto = _orig["sendto"]
        socket.getaddrinfo = _orig["getaddrinfo"]
        _installed = False
