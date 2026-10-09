"""Certificate-chain validation and Apple device-attestation extensions.

With ACME ``Attest = true``, the leaf certificate carries Apple-defined
extensions describing the device (serial, OS version, SIP / Secure Boot state,
...). The OID-to-name table below follows Apple's Managed Device Attestation
documentation; confirm it against the current Apple reference when deploying.
Unknown OIDs under Apple's arc are still reported (by OID) so nothing is
silently dropped.
"""
from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

APPLE_ARC = "1.2.840.113635.100.8."
APPLE_ATTEST_OIDS = {
    "1.2.840.113635.100.8.9.1": "serial_number",
    "1.2.840.113635.100.8.9.2": "udid",
    "1.2.840.113635.100.8.10.1": "os_version",
    "1.2.840.113635.100.8.10.2": "sepos_version",
    "1.2.840.113635.100.8.10.3": "llb_version",
    "1.2.840.113635.100.8.11.1": "freshness_code",
    "1.2.840.113635.100.8.13.1": "sip_status",
    "1.2.840.113635.100.8.13.2": "secure_boot_status",
    "1.2.840.113635.100.8.13.3": "third_party_kexts_allowed",
}


def _der_value(b: bytes):
    """Decode a single primitive DER TLV; fall back to text/hex."""
    if len(b) >= 2:
        tag, ln, off = b[0], b[1], 2
        if ln & 0x80:
            n = ln & 0x7F
            ln, off = int.from_bytes(b[2:2 + n], "big"), 2 + n
        body = b[off:off + ln]
        if off + ln == len(b):
            if tag in (0x0C, 0x13, 0x16, 0x1A):     # UTF8/Printable/IA5/Visible string
                return body.decode("utf-8", errors="replace")
            if tag == 0x01:                          # BOOLEAN
                return body != b"\x00"
            if tag == 0x02:                          # INTEGER
                return int.from_bytes(body, "big", signed=True)
            if tag == 0x04:                          # OCTET STRING (possibly nested)
                inner = _der_value(body)
                return inner
    try:
        text = b.decode("utf-8")
        if text.isprintable():
            return text
    except UnicodeDecodeError:
        pass
    return b.hex()


def attestation_claims(cert: x509.Certificate) -> dict:
    out = {}
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if oid.startswith(APPLE_ARC):
            raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
            out[APPLE_ATTEST_OIDS.get(oid, oid)] = _der_value(raw)
    return out


def _fp(c: x509.Certificate) -> bytes:
    return c.fingerprint(hashes.SHA256())


def _valid_at(c: x509.Certificate, when: dt.datetime) -> bool:
    return c.not_valid_before_utc <= when <= c.not_valid_after_utc


def _is_ca(c: x509.Certificate) -> bool:
    try:
        return c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False


def validate_chain(chain: list[x509.Certificate], anchors: list[x509.Certificate],
                   when: dt.datetime) -> list[str]:
    """Validate leaf-first ``chain`` up to one of ``anchors`` at time ``when``."""
    if not chain:
        return ["cert_chain_missing"]
    if not anchors:
        return ["ca_bundle_empty"]
    leaf = chain[0]
    try:
        ku = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not ku.digital_signature:
            return ["leaf_not_for_signing"]
    except x509.ExtensionNotFound:
        pass
    anchor_fps = {_fp(a) for a in anchors}
    pool = chain[1:] + anchors
    cur = leaf
    for _ in range(8):
        if not _valid_at(cur, when):
            return ["cert_not_valid_at_signing_time"]
        if _fp(cur) in anchor_fps:
            return []
        issuer = None
        for cand in pool:
            if cand.subject != cur.issuer or _fp(cand) == _fp(cur):
                continue
            try:
                cur.verify_directly_issued_by(cand)
            except Exception:  # noqa: BLE001 - signature/algorithm mismatch: try next
                continue
            issuer = cand
            break
        if issuer is None:
            return ["cert_chain_untrusted"]
        if not _is_ca(issuer):
            return ["issuer_not_ca"]
        cur = issuer
    return ["cert_chain_too_long"]
