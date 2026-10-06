"""Minimal pcap / pcapng packet counter (no third-party parsers)."""
from __future__ import annotations

import struct

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",  # nanosecond variants
}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_PACKET_BLOCKS = {0x00000006, 0x00000003, 0x00000002}  # EPB, SPB, obsolete PB


class PcapError(ValueError):
    pass


def count_packets(path: str) -> int:
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        # tcpdump -U writes the file header immediately; an empty file means the
        # capture never started, which must not be mistaken for "zero egress".
        raise PcapError("empty capture file (no header)")
    if data[:4] in PCAP_MAGICS:
        return _count_pcap(data, PCAP_MAGICS[data[:4]])
    if len(data) >= 4 and struct.unpack("<I", data[:4])[0] == PCAPNG_SHB:
        return _count_pcapng(data)
    raise PcapError("unknown capture format")


def _count_pcap(data: bytes, endian: str) -> int:
    if len(data) < 24:
        raise PcapError("truncated pcap header")
    pos, n = 24, 0
    while pos + 16 <= len(data):
        incl = struct.unpack(endian + "I", data[pos + 8:pos + 12])[0]
        pos += 16 + incl
        if pos > len(data):
            raise PcapError("truncated pcap record")
        n += 1
    if pos != len(data):
        raise PcapError("trailing bytes in pcap")
    return n


def _count_pcapng(data: bytes) -> int:
    pos, n, endian = 0, 0, "<"
    while pos + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[pos:pos + 4])[0]
        if btype == PCAPNG_SHB:
            bom = data[pos + 8:pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        if blen < 12 or pos + blen > len(data):
            raise PcapError("truncated pcapng block")
        if btype in PCAPNG_PACKET_BLOCKS:
            n += 1
        pos += blen
    if pos != len(data):
        raise PcapError("trailing bytes in pcapng")
    return n


def _records(data: bytes):
    """Yield ("pcap", endian, pos, incl, orig) or ("pcapng", endian, pos, btype, blen)."""
    if not data:
        raise PcapError("empty capture file (no header)")
    if data[:4] in PCAP_MAGICS:
        endian = PCAP_MAGICS[data[:4]]
        if len(data) < 24:
            raise PcapError("truncated pcap header")
        pos = 24
        while pos + 16 <= len(data):
            incl, orig = struct.unpack(endian + "II", data[pos + 8:pos + 16])
            if pos + 16 + incl > len(data):
                raise PcapError("truncated pcap record")
            yield "pcap", endian, pos, incl, orig
            pos += 16 + incl
        if pos != len(data):
            raise PcapError("trailing bytes in pcap")
        return
    if len(data) >= 4 and struct.unpack("<I", data[:4])[0] == PCAPNG_SHB:
        pos, endian = 0, "<"
        while pos + 12 <= len(data):
            btype = struct.unpack(endian + "I", data[pos:pos + 4])[0]
            if btype == PCAPNG_SHB:
                endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
            if blen < 12 or pos + blen > len(data):
                raise PcapError("truncated pcapng block")
            yield "pcapng", endian, pos, btype, blen
            pos += blen
        if pos != len(data):
            raise PcapError("trailing bytes in pcapng")
        return
    raise PcapError("unknown capture format")


def max_caplen(path: str) -> int:
    """Largest number of packet bytes stored for any packet."""
    with open(path, "rb") as f:
        data = f.read()
    m = 0
    for fmt, endian, pos, a, b in _records(data):
        if fmt == "pcap":
            m = max(m, a)
        elif a == 0x00000006:  # EPB: captured length field
            m = max(m, struct.unpack(endian + "I", data[pos + 20:pos + 24])[0])
        elif a in (0x00000003, 0x00000002):  # SPB / PB: no reliable caplen
            m = max(m, b - 16)
    return m


def truncate(src: str, dst: str, snaplen: int) -> int:
    """Copy a capture keeping at most ``snaplen`` bytes of each packet (the
    link/IP/transport headers) and dropping per-packet options, so payload
    of blocked packets (e.g. DNS names) never leaves the RAM disk. Simple and
    obsolete packet blocks become EPBs. Returns the packet count."""
    with open(src, "rb") as f:
        data = f.read()
    out = bytearray()
    n = 0
    if data[:4] in PCAP_MAGICS and len(data) >= 24:
        endian = PCAP_MAGICS[data[:4]]
        hdr = bytearray(data[:24])
        hdr[16:20] = struct.pack(endian + "I", min(snaplen, struct.unpack(endian + "I", data[16:20])[0]))
        out += hdr
    for fmt, endian, pos, a, b in _records(data):
        if fmt == "pcap":
            ts = data[pos:pos + 8]
            keep = min(a, snaplen)
            out += ts + struct.pack(endian + "II", keep, b) + data[pos + 16:pos + 16 + keep]
            n += 1
            continue
        btype, blen = a, b
        if btype not in PCAPNG_PACKET_BLOCKS:
            out += data[pos:pos + blen]
            continue
        if btype == 0x00000006:
            iface, ts_hi, ts_lo, cap, orig = struct.unpack(endian + "IIIII", data[pos + 8:pos + 28])
            payload = data[pos + 28:pos + 28 + cap]
        elif btype == 0x00000003:
            orig = struct.unpack(endian + "I", data[pos + 8:pos + 12])[0]
            iface, ts_hi, ts_lo = 0, 0, 0
            payload = data[pos + 12:pos + blen - 4]
        else:  # obsolete Packet Block
            iface = struct.unpack(endian + "H", data[pos + 8:pos + 10])[0]
            ts_hi, ts_lo, cap, orig = struct.unpack(endian + "IIII", data[pos + 12:pos + 28])
            payload = data[pos + 28:pos + 28 + cap]
        payload = payload[:snaplen]
        body = struct.pack(endian + "IIIII", iface, ts_hi, ts_lo, len(payload), orig)
        body += payload + b"\x00" * (-len(payload) % 4)
        total = 12 + len(body)
        out += struct.pack(endian + "II", 0x00000006, total) + body + struct.pack(endian + "I", total)
        n += 1
    with open(dst, "wb") as f:
        f.write(bytes(out))
    return n
