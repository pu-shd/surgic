"""Manifest signing.

* Ed25519 with the private seed held in the macOS Keychain (default), or
* ECDSA P-256 with a Secure Enclave key issued by a Jamf ACME payload
  (``P256Signer.from_secure_enclave``; see surgic.audit.secure_enclave).

For Ed25519:

Keychain has no native Ed25519 key type, so the 32-byte seed is stored as a
generic-password item (accessed through the Security framework by `keyring`,
never via command-line arguments). A file-backed store exists for CI/tests and
must be selected explicitly.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..logging_safe import SafeError


class SeedStore(Protocol):
    def get(self) -> bytes | None: ...
    def put(self, seed: bytes) -> None: ...


class KeychainStore:
    def __init__(self, service: str, account: str) -> None:
        self.service, self.account = service, account

    def _kr(self):
        import keyring
        from keyring.backends import macOS

        keyring.set_keyring(macOS.Keyring())
        return keyring

    def get(self) -> bytes | None:
        v = self._kr().get_password(self.service, self.account)
        return base64.b64decode(v) if v else None

    def put(self, seed: bytes) -> None:
        self._kr().set_password(self.service, self.account, base64.b64encode(seed).decode())


class FileStore:
    """Test/CI only. Requires SURGIC_ALLOW_FILE_KEY=1."""

    def __init__(self, path: str) -> None:
        if os.environ.get("SURGIC_ALLOW_FILE_KEY") != "1":
            raise SafeError("file_key_store_not_allowed")
        self.path = Path(path)

    def get(self) -> bytes | None:
        return base64.b64decode(self.path.read_bytes()) if self.path.exists() else None

    def put(self, seed: bytes) -> None:
        self.path.write_bytes(base64.b64encode(seed))
        os.chmod(self.path, 0o600)


def store_from_env(service: str, account: str) -> SeedStore:
    fp = os.environ.get("SURGIC_KEY_FILE")
    return FileStore(fp) if fp else KeychainStore(service, account)


class Signer:
    """Ed25519 signer (seed in the login Keychain, or a file store for tests)."""

    alg = "Ed25519"
    export_name = "pubkey.pem"

    def __init__(self, store: SeedStore) -> None:
        seed = store.get()
        if seed is None:
            raise SafeError("signing_key_missing")
        if len(seed) != 32:
            raise SafeError("signing_key_invalid")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    @staticmethod
    def generate(store: SeedStore, overwrite: bool = False) -> None:
        if store.get() is not None and not overwrite:
            raise SafeError("signing_key_exists")
        key = Ed25519PrivateKey.generate()
        store.put(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption()))

    def public_pem(self) -> bytes:
        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)

    def export_pem(self) -> bytes:
        return self.public_pem()

    def fingerprint(self) -> str:
        return pubkey_fingerprint(self._key.public_key())

    def signer_block(self) -> dict:
        return {"alg": self.alg, "fingerprint": self.fingerprint()}

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


Ed25519Signer = Signer


class P256Signer:
    """ECDSA P-256 / SHA-256 signer whose private key may live anywhere (Secure
    Enclave in production). The signed block embeds the DER certificate chain
    (leaf first) so verifiers can validate it against the issuing CA and read
    Apple device-attestation extensions."""

    alg = "ES256"
    export_name = "signer-chain.pem"

    def __init__(self, sign_fn, public_key: ec.EllipticCurvePublicKey, cert_chain_der: list[bytes],
                 hardware_bound: bool) -> None:
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise SafeError("signer_not_p256")
        if cert_chain_der:
            leaf = x509.load_der_x509_certificate(cert_chain_der[0])
            if spki(leaf.public_key()) != spki(public_key):
                raise SafeError("signer_cert_key_mismatch")
        self._sign = sign_fn
        self._pub = public_key
        self.chain = list(cert_chain_der)
        self.hardware_bound = hardware_bound

    @classmethod
    def from_secure_enclave(cls, subject_cn: str, issuer_contains: str = "",
                            require_hardware_bound: bool = True) -> "P256Signer":
        from . import secure_enclave
        ident = secure_enclave.find_identity(subject_cn, issuer_contains)
        if require_hardware_bound and not ident.hardware_bound:
            raise SafeError("signer_not_hardware_bound")
        return cls(ident.sign, ident.public_key, ident.chain_der, ident.hardware_bound)

    def public_pem(self) -> bytes:
        return self._pub.public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)

    def export_pem(self) -> bytes:
        if not self.chain:
            return self.public_pem()
        return b"".join(x509.load_der_x509_certificate(d).public_bytes(serialization.Encoding.PEM)
                        for d in self.chain)

    def fingerprint(self) -> str:
        return pubkey_fingerprint(self._pub)

    def signer_block(self) -> dict:
        return {"alg": self.alg, "fingerprint": self.fingerprint(),
                "hardware_bound": self.hardware_bound,
                "cert_chain": [base64.b64encode(d).decode() for d in self.chain]}

    def sign(self, data: bytes) -> bytes:
        sig = self._sign(data)
        # Self-check: never emit a signature that does not verify.
        if not verify_sig(self._pub, data, sig):
            raise SafeError("signer_selfcheck_failed")
        return sig


def spki(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def pubkey_fingerprint(pub) -> str:
    if isinstance(pub, Ed25519PublicKey):
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        raw = spki(pub)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_public(pem: bytes):
    key = serialization.load_pem_public_key(pem)
    if isinstance(key, Ed25519PublicKey):
        return key
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return key
    raise SafeError("unsupported_public_key")


def verify_sig(pub, data: bytes, sig: bytes) -> bool:
    try:
        if isinstance(pub, Ed25519PublicKey):
            pub.verify(sig, data)
        else:
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def make_signer(acfg):
    if acfg.signer == "secure-enclave":
        return P256Signer.from_secure_enclave(acfg.acme_subject_cn, acfg.acme_issuer_contains,
                                              acfg.require_hardware_bound)
    return Signer(store_from_env(acfg.keychain_service, acfg.keychain_account))
