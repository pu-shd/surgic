"""Secure Enclave signing via the Security framework (pyobjc).

Production: a Jamf ACME payload (HardwareBound=true, Attest=true, P-256) makes
macOS generate the private key inside the Secure Enclave and enroll a
certificate for it. ``find_identity`` locates that identity by subject CN (and
optionally issuer), confirms the key is Secure-Enclave-backed, and returns a
signing callable plus the certificate chain. The private key never leaves the
Secure Enclave and cannot be exported.

Note: pyobjc's bridged Python dicts raise KeyError when the Security framework
probes optional keys, so every attribute dictionary is passed as NSDictionary.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..logging_safe import SafeError


@dataclass
class Identity:
    sign: Callable[[bytes], bytes]
    public_key: ec.EllipticCurvePublicKey
    chain_der: list[bytes]
    hardware_bound: bool


@dataclass
class Candidate:
    cert_der: bytes
    key_ref: object
    hardware_bound: bool
    chain_der: list[bytes]


def _S():
    try:
        import Security
        from Foundation import NSDictionary
    except ImportError as e:
        raise SafeError("secure_enclave_unavailable") from e
    return Security, NSDictionary


def _sign_with(key_ref) -> Callable[[bytes], bytes]:
    S, _ = _S()

    def sign(data: bytes) -> bytes:
        sig, err = S.SecKeyCreateSignature(key_ref, S.kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                           data, None)
        if sig is None:
            raise SafeError("secure_enclave_sign_failed")
        return bytes(sig)

    return sign


def _is_se_key(key_ref) -> bool:
    S, _ = _S()
    attrs = S.SecKeyCopyAttributes(key_ref)
    if attrs is None:
        return False
    token = attrs.objectForKey_(S.kSecAttrTokenID) if hasattr(attrs, "objectForKey_") else attrs.get(S.kSecAttrTokenID)
    return token == S.kSecAttrTokenIDSecureEnclave


def _chain(cert_ref) -> list[bytes]:
    S, _ = _S()
    leaf = bytes(S.SecCertificateCopyData(cert_ref))
    try:
        status, trust = S.SecTrustCreateWithCertificates(cert_ref, S.SecPolicyCreateBasicX509(), None)
        if status != 0 or trust is None:
            return [leaf]
        S.SecTrustEvaluateWithError(trust, None)
        certs = S.SecTrustCopyCertificateChain(trust) or []
        chain = [bytes(S.SecCertificateCopyData(c)) for c in certs]
        return chain if chain and chain[0] == leaf else [leaf]
    except Exception:  # noqa: BLE001 - chain building is best effort; verifier needs CA anyway
        return [leaf]


def _query_candidates() -> list[Candidate]:
    S, NSDictionary = _S()
    q = NSDictionary.dictionaryWithDictionary_({
        S.kSecClass: S.kSecClassIdentity,
        S.kSecReturnRef: True,
        S.kSecMatchLimit: S.kSecMatchLimitAll,
    })
    status, result = S.SecItemCopyMatching(q, None)
    if status != 0 or result is None:
        return []
    out = []
    for ident in result:
        st1, cert = S.SecIdentityCopyCertificate(ident, None)
        st2, key = S.SecIdentityCopyPrivateKey(ident, None)
        if st1 != 0 or st2 != 0 or cert is None or key is None:
            continue
        out.append(Candidate(bytes(S.SecCertificateCopyData(cert)), key, _is_se_key(key), _chain(cert)))
    return out


def select(cands: list[Candidate], subject_cn: str, issuer_contains: str = "",
           now: dt.datetime | None = None) -> Candidate:
    """Pick the newest currently-valid P-256 identity with the given subject CN."""
    now = now or dt.datetime.now(dt.timezone.utc)
    best, best_nb = None, None
    for c in cands:
        cert = x509.load_der_x509_certificate(c.cert_der)
        cns = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        if subject_cn not in cns:
            continue
        if issuer_contains and issuer_contains not in cert.issuer.rfc4514_string():
            continue
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            continue
        pub = cert.public_key()
        if not (isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)):
            continue
        if best is None or cert.not_valid_before_utc > best_nb:
            best, best_nb = c, cert.not_valid_before_utc
    if best is None:
        raise SafeError("signer_identity_not_found")
    return best


def find_identity(subject_cn: str, issuer_contains: str = "") -> Identity:
    c = select(_query_candidates(), subject_cn, issuer_contains)
    pub = x509.load_der_x509_certificate(c.cert_der).public_key()
    return Identity(_sign_with(c.key_ref), pub, c.chain_der or [c.cert_der], c.hardware_bound)


def ephemeral_key() -> tuple[Callable[[bytes], bytes], ec.EllipticCurvePublicKey]:
    """Non-persistent Secure Enclave key (tests / self-check). No entitlement needed."""
    S, NSDictionary = _S()
    attrs = NSDictionary.dictionaryWithDictionary_({
        S.kSecAttrKeyType: S.kSecAttrKeyTypeECSECPrimeRandom,
        S.kSecAttrKeySizeInBits: 256,
        S.kSecAttrTokenID: S.kSecAttrTokenIDSecureEnclave,
        S.kSecPrivateKeyAttrs: NSDictionary.dictionaryWithDictionary_({S.kSecAttrIsPermanent: False}),
    })
    key, err = S.SecKeyCreateRandomKey(attrs, None)
    if key is None:
        raise SafeError("secure_enclave_keygen_failed")
    if not _is_se_key(key):
        raise SafeError("secure_enclave_key_not_hardware")
    ext, _ = S.SecKeyCopyExternalRepresentation(S.SecKeyCopyPublicKey(key), None)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(ext))
    return _sign_with(key), pub
