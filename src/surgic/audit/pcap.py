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
