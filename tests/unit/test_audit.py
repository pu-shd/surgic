from __future__ import annotations

import base64
import io
import json
import logging
import struct

import pytest

from surgic import logging_safe, netguard
from surgic.audit.manifest import CLOSURE_SCHEMA, SCHEMA, canonical, sha256_file, write_signed
from surgic.audit.pcap import PcapError, count_packets
from surgic.audit.signing import FileStore, Signer
from surgic.audit.verify import verify_file
from surgic.logging_safe import SafeError


# ---------------------------------------------------------------- logging
def test_log_event_rejects_free_text():
    with pytest.raises(ValueError):
        logging_safe.log_event("x", detail="Margaret Thornbury SSN 219-09-9999")


def test_third_party_records_scrubbed():
    buf = io.StringIO()
    logging_safe.install(stream=buf)
    logging.getLogger("presidio").warning("found %s", "219-09-9999")
    logging.getLogger("presidio").info("debug %s", "jane@example.com")
    try:
        raise RuntimeError("Margaret Thornbury")
    except RuntimeError:
        logging.getLogger("lib").exception("boom")
    logging_safe.log_event("document", doc_id="00001-abc", regions=3)
    out = buf.getvalue()
    for leak in ("219-09-9999", "jane@example.com", "Thornbury"):
        assert leak not in out
    assert "[redacted log from presidio]" in out
    assert '"regions": 3' in out
    assert "debug" not in out  # INFO from third parties dropped entirely


def test_run_key_hmac_ephemeral():
    a, b = logging_safe.RunKey(), logging_safe.RunKey()
    assert a.token("v") == a.token("v") != b.token("v")
    a.wipe()
    assert a._key == b"\x00" * 32


def test_safe_error_fields_checked():
    with pytest.raises(ValueError):
        SafeError("x", detail="free text")
    assert SafeError("x", status=3).fields == {"status": 3}


# ---------------------------------------------------------------- signing / manifest
def test_canonical_sorted_compact_no_floats():
    assert canonical({"b": 1, "a": [2, "é"]}) == '{"a":[2,"é"],"b":1}'.encode()
    with pytest.raises(TypeError):
        canonical({"a": 1.5})


def test_sign_verify_and_tamper(tmp_path, key_store):
    signer = Signer(key_store)
    out = tmp_path / "out"
    (out / "00000-abc").mkdir(parents=True)
    f = out / "00000-abc" / "x.redacted.pdf"
    f.write_bytes(b"clean")
    m = {"schema": SCHEMA, "documents": [{"doc_id": "00000-abc", "status": "clean",
         "outputs": [{"name": "x.redacted.pdf", "sha256": sha256_file(f)}], "postscan": {"passed": True}}]}
    mp, _ = write_signed(m, tmp_path / "m.json", signer)
    pem = signer.public_pem()
    assert verify_file(mp, pem, str(out)) == []

    # 1-byte manifest tamper -> signature invalid
    data = bytearray((tmp_path / "m.json").read_bytes())
    data[10] ^= 0x01
    (tmp_path / "m.json").write_bytes(bytes(data))
    assert verify_file(mp, pem) == ["signature_invalid"]


def test_verify_detects_output_tamper_and_wrong_key(tmp_path, key_store):
    signer = Signer(key_store)
    out = tmp_path / "out" / "d1"
    out.mkdir(parents=True)
    (out / "a.txt").write_bytes(b"one")
    m = {"schema": SCHEMA, "documents": [
        {"doc_id": "d1", "status": "clean", "outputs": [{"name": "a.txt", "sha256": sha256_file(out / "a.txt")}],
         "postscan": {"passed": True}},
        {"doc_id": "d2", "status": "quarantined", "outputs": [], "postscan": {"passed": False}}]}
    mp, _ = write_signed(m, tmp_path / "m.json", signer)
    (out / "a.txt").write_bytes(b"two")
    (tmp_path / "out" / "d2").mkdir()
    fails = verify_file(mp, signer.public_pem(), str(tmp_path / "out"))
    assert "output_hash_mismatch:d1" in fails and "quarantined_output_present:d2" in fails

    other = FileStore(str(tmp_path / "other"))
    Signer.generate(other)
    assert verify_file(mp, Signer(other).public_pem()) == ["signature_invalid"]


def test_signature_missing(tmp_path, key_store):
    mp, sig = write_signed({"schema": SCHEMA, "documents": []}, tmp_path / "m.json", Signer(key_store))
    import os
    os.unlink(sig)
    assert verify_file(mp, Signer(key_store).public_pem()) == ["signature_missing"]


def test_keygen_refuses_overwrite(key_store):
    with pytest.raises(SafeError) as e:
        Signer.generate(key_store)
    assert e.value.code == "signing_key_exists"


def test_file_store_requires_opt_in(monkeypatch, tmp_path):
    monkeypatch.delenv("SURGIC_ALLOW_FILE_KEY")
    with pytest.raises(SafeError):
        FileStore(str(tmp_path / "k"))


def test_missing_key(tmp_path):
    with pytest.raises(SafeError) as e:
        Signer(FileStore(str(tmp_path / "none")))
    assert e.value.code == "signing_key_missing"


# ---------------------------------------------------------------- pcap
def pcap(n: int, nano=False) -> bytes:
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for i in range(n):
        pkt = bytes(60)
        out += struct.pack("<IIII", i, 0, len(pkt), len(pkt)) + pkt
    return out


def pcapng(n: int) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
    out = shb + idb
    for _ in range(n):
        body = struct.pack("<IIIII", 0, 0, 0, 4, 4) + b"abcd"
        out += struct.pack("<II", 6, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
    return out


@pytest.mark.parametrize("n", [0, 1, 7])
def test_pcap_counts(tmp_path, n):
    for name, data in (("a.pcap", pcap(n)), ("b.pcap", pcap(n, nano=True)), ("c.pcapng", pcapng(n))):
        p = tmp_path / name
        p.write_bytes(data)
        assert count_packets(str(p)) == n


def test_pcap_empty_and_corrupt_raise(tmp_path):
    p = tmp_path / "e.pcap"
    p.write_bytes(b"")
    with pytest.raises(PcapError):
        count_packets(str(p))
    p.write_bytes(pcap(2)[:-5])
    with pytest.raises(PcapError):
        count_packets(str(p))
    p.write_bytes(b"garbage!" * 4)
    with pytest.raises(PcapError):
        count_packets(str(p))


def _closure(tmp_path, signer, egress_n=0, blocked_n=2, **over):
    ev = tmp_path / "ev"
    ev.mkdir(exist_ok=True)
    (ev / "egress_audit.pcap").write_bytes(pcap(egress_n))
    (ev / "pflog_blocked.pcap").write_bytes(pcap(blocked_n))
    c = {"schema": CLOSURE_SCHEMA, "egress_packets": egress_n, "errors": [], "probe": {"blocked": True},
         "ramdisk_devices_remaining": 0,
         "ramdisk": {"teardown": [{"step": "zero_fill", "status": 0}, {"step": "detach", "status": 0}]},
         "captures": [
             {"name": "egress_audit.pcap", "packets": egress_n, "sha256": sha256_file(ev / "egress_audit.pcap")},
             {"name": "pflog_blocked.pcap", "packets": blocked_n, "sha256": sha256_file(ev / "pflog_blocked.pcap")}]}
    c.update(over)
    return write_signed(c, ev / "closure.json", signer)[0]


def test_closure_verifies_zero_egress(tmp_path, key_store):
    s = Signer(key_store)
    assert verify_file(_closure(tmp_path, s), s.public_pem()) == []


def test_closure_fails_on_egress_and_missing_enforcement(tmp_path, key_store):
    s = Signer(key_store)
    fails = verify_file(_closure(tmp_path, s, egress_n=3, blocked_n=0), s.public_pem())
    assert "egress_detected" in fails and "no_blocked_packets_observed" in fails


def test_closure_detects_swapped_pcap(tmp_path, key_store):
    s = Signer(key_store)
    path = _closure(tmp_path, s)
    (tmp_path / "ev" / "egress_audit.pcap").write_bytes(pcap(0) + b"")  # same content -> ok
    assert verify_file(path, s.public_pem()) == []
    (tmp_path / "ev" / "egress_audit.pcap").write_bytes(pcap(1))
    fails = verify_file(path, s.public_pem())
    assert "capture_hash_mismatch:egress_audit.pcap" in fails


def test_closure_ramdisk_not_zeroed(tmp_path, key_store):
    s = Signer(key_store)
    path = _closure(tmp_path, s, ramdisk={"teardown": [{"step": "zero_fill", "status": 1}]})
    assert "ramdisk_not_zero_filled" in verify_file(path, s.public_pem())


# ---------------------------------------------------------------- netguard
def test_netguard_blocks_external_allows_loopback():
    import socket
    import httpx

    before = len(netguard.attempts)
    with pytest.raises(OSError):
        socket.create_connection(("192.0.2.1", 443), timeout=1)
    with pytest.raises(OSError):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(httpx.HTTPError):
        httpx.get("https://example.com", timeout=1)
    assert len(netguard.attempts) > before
    del netguard.attempts[before:]  # expected attempts; don't fail the session
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    c = socket.create_connection(srv.getsockname(), timeout=1)
    c.close()
    srv.close()
    assert len(netguard.attempts) == before


def test_signature_file_is_base64(tmp_path, key_store):
    _, sig = write_signed({"schema": SCHEMA, "documents": []}, tmp_path / "m.json", Signer(key_store))
    assert len(base64.b64decode(open(sig, "rb").read().strip())) == 64
    assert json.loads((tmp_path / "m.json").read_bytes())["signer"]["alg"] == "Ed25519"
