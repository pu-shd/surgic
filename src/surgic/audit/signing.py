"""Ed25519 manifest signing with the private seed held in the macOS Keychain.

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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
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

    def fingerprint(self) -> str:
        return pubkey_fingerprint(self._key.public_key())

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


def pubkey_fingerprint(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_public(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise SafeError("not_ed25519")
    return key


def verify_sig(pub: Ed25519PublicKey, data: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, data)
        return True
    except InvalidSignature:
        return False
