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
    from fakes import evidence
    signer = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, signer)
    pem = signer.public_pem()
    assert verify_file(mp, pem, str(share), cp) == []
    assert verify_file(cp, pem) == []

    # 1-byte tamper of a value (still valid JSON) -> signature invalid
    data = open(mp, "rb").read()
    tampered = data.replace(b'"status":"quarantined"', b'"status":"quarantinee"', 1)
    assert tampered != data
    open(mp, "wb").write(tampered)
    assert verify_file(mp, pem, str(share), cp) == ["signature_invalid"]
    # Not JSON at all is rejected too.
    open(mp, "wb").write(b"\x00" + data)
    assert verify_file(mp, pem, str(share), cp) == ["not_json"]


def test_verify_detects_output_tamper_and_wrong_key(tmp_path, key_store):
    from fakes import evidence
    signer = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, signer)
    run = share / evidence.RUN
    (run / "00001-abc" / "00001-abc.redacted.pdf").write_bytes(b"two")
    (run / "00002-def").mkdir()
    fails = verify_file(mp, signer.public_pem(), str(share), cp)
    assert "output_hash_mismatch:00001-abc" in fails and "quarantined_output_present:00002-def" in fails

    other = FileStore(str(tmp_path / "other"))
    Signer.generate(other)
    assert verify_file(mp, Signer(other).public_pem()) == ["signature_invalid"]


@pytest.mark.parametrize("over,failure", [
    ({"aborted": "llm_unload_unverified"}, "run_aborted:llm_unload_unverified"),
    ({"environment": {"preflight": "SKIPPED"}}, "preflight_not_run"),
    ({"llm": {"backend": "mock", "model_sha256": "x", "batch_size": 1, "unloads": 2, "context_resets": 2}},
     "non_production_backend"),
    ({"llm": {"backend": "ollama", "model_sha256": "x", "batch_size": 1, "unloads": 0, "context_resets": 0}},
     "llm_isolation_counts_inconsistent"),
])
def test_verify_rejects_non_production_runs(tmp_path, key_store, over, failure):
    from fakes import evidence
    s = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, s, manifest_over=over)
    assert failure in verify_file(mp, s.public_pem(), str(share), cp)


@pytest.mark.parametrize("key,bad", [
    ("isolation", "inprocess"), ("isolation", "process"), ("require_secret_scanners", False),
    ("verify_model_hash", False), ("model_allowlisted", False), ("smb_require_encryption", False),
    ("in_process_egress_attempts", 1),
])
def test_verify_rejects_weakened_controls(tmp_path, key_store, key, bad):
    from fakes import evidence
    from surgic.audit.verify import REQUIRED_SECURITY
    s = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, s, manifest_over={"security": {**REQUIRED_SECURITY, key: bad}})
    assert f"weakened_control:{key}" in verify_file(mp, s.public_pem(), str(share), cp)


def test_verify_rejects_failed_or_partial_preflight(tmp_path, key_store):
    from fakes import evidence
    s = Signer(key_store)
    pre = [{"name": "pf_airgap_ruleset", "ok": False, "code": "pf_disabled"}]
    mp, cp, share = evidence.build(tmp_path, s, manifest_over={"environment": {"preflight": pre}})
    fails = verify_file(mp, s.public_pem(), str(share), cp)
    assert "preflight_not_passed" in fails and "preflight_missing:worker_sandbox" in fails


def test_verify_requires_outputs_and_closure(tmp_path, key_store):
    from fakes import evidence
    s = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, s)
    fails = verify_file(mp, s.public_pem())
    assert "outputs_not_checked" in fails and "closure_not_provided" in fails


def test_verify_flags_unlisted_outputs(tmp_path, key_store):
    from fakes import evidence
    s = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, s)
    (share / evidence.RUN / "99999-planted").mkdir()
    (share / evidence.RUN / "00001-abc" / "extra.txt").write_text("x")
    fails = verify_file(mp, s.public_pem(), str(share), cp)
    assert "unlisted_output:99999-planted" in fails and "unlisted_output:00001-abc/extra.txt" in fails


def test_verify_binds_manifest_to_closure(tmp_path, key_store):
    from fakes import evidence
    s = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, s, closure_over={"session_id": "b" * 32, "manifests": [],
                                                             "started_at": 1500})
    fails = verify_file(mp, s.public_pem(), str(share), cp)
    for f in ("airgap_session_mismatch", "manifest_not_in_closure", "manifest_outside_airgap_window"):
        assert f in fails


def test_verify_expected_model(tmp_path, key_store):
    from fakes import evidence
    s = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, s)
    assert verify_file(mp, s.public_pem(), str(share), cp, expect_model="m" * 64) == []
    assert "model_not_expected" in verify_file(mp, s.public_pem(), str(share), cp, expect_model="n" * 64)


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


def _closure(tmp_path, signer, egress_n=0, blocked_n=2, blocked_size=40, **over):
    from fakes import evidence
    _, cpath, _ = evidence.build(tmp_path, signer, closure_over=over, egress_n=egress_n,
                                 blocked_n=blocked_n, blocked_size=blocked_size)
    return cpath


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
    ev = tmp_path / "share" / "evidence" / "ts"
    (ev / "egress_audit.pcap").write_bytes(pcap(0) + b"")  # same content -> ok
    assert verify_file(path, s.public_pem()) == []
    (ev / "egress_audit.pcap").write_bytes(pcap(1))
    fails = verify_file(path, s.public_pem())
    assert "capture_hash_mismatch:egress_audit.pcap" in fails


def test_closure_ramdisk_not_zeroed(tmp_path, key_store):
    s = Signer(key_store)
    path = _closure(tmp_path, s, ramdisk={"teardown": [{"step": "zero_fill", "status": 1}]})
    assert "ramdisk_not_zero_filled" in verify_file(path, s.public_pem())


def test_closure_rejects_payload_bearing_capture(tmp_path, key_store):
    s = Signer(key_store)
    path = _closure(tmp_path, s, blocked_size=400)
    assert "capture_payload_not_truncated:pflog_blocked.pcap" in verify_file(path, s.public_pem())


@pytest.mark.parametrize("over,failure", [
    ({"capture_filter": "port 99999"}, "capture_filter_unexpected"),
    ({"pf": {"rules_sha256": "0" * 64}}, "pf_rules_unexpected"),
    ({"session_id": ""}, "session_id_missing"),
])
def test_closure_checks_capture_and_rules(tmp_path, key_store, over, failure):
    s = Signer(key_store)
    assert failure in verify_file(_closure(tmp_path, s, **over), s.public_pem())


# ---------------------------------------------------------------- pcap sanitizing
def test_truncate_pcap_drops_payload_keeps_count(tmp_path):
    from surgic.audit.pcap import max_caplen, truncate
    src, dst = tmp_path / "a.pcap", tmp_path / "b.pcap"
    src.write_bytes(pcap(3)[:24] + b"".join(
        struct.pack("<IIII", i, 0, 200, 200) + bytes(60) + b"SECRET-QNAME" + bytes(128) for i in range(3)))
    assert truncate(str(src), str(dst), 64) == 3
    assert count_packets(str(dst)) == 3 and max_caplen(str(dst)) == 64
    assert b"SECRET-QNAME" not in dst.read_bytes()
    src.write_bytes(pcap(0))
    assert truncate(str(src), str(dst), 64) == 0 and count_packets(str(dst)) == 0


def test_truncate_pcapng_all_packet_block_types(tmp_path):
    from surgic.audit.pcap import max_caplen, truncate
    data = pcapng(2)  # two EPBs with 4-byte payloads
    body = struct.pack("<I", 300) + bytes(60) + b"SECRET-QNAME" + bytes(228)
    data += struct.pack("<II", 3, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))  # SPB
    src, dst = tmp_path / "a.pcapng", tmp_path / "b.pcapng"
    src.write_bytes(data)
    assert truncate(str(src), str(dst), 64) == 3
    assert count_packets(str(dst)) == 3 and max_caplen(str(dst)) <= 64
    assert b"SECRET-QNAME" not in dst.read_bytes()


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
