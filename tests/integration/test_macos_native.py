"""Native macOS facilities (run by scripts/test.zsh and the macos CI job)."""
from __future__ import annotations

import io
import os
import sys
import uuid

import pytest

pytestmark = pytest.mark.macos


def test_vision_ocr_reads_planted_values():
    from fixtures.make import STRUCTURED, text_image
    from surgic.extract.ocr import recognize_vision

    buf = io.BytesIO()
    text_image().save(buf, format="PNG")
    words = recognize_vision(buf.getvalue())
    text = " ".join(w.text for w in words)
    assert STRUCTURED["ssn"] in text and STRUCTURED["email"] in text
    assert all(0 <= w.x0 < w.x1 and 0 <= w.y0 < w.y1 for w in words)


@pytest.mark.skipif(os.environ.get("CI") == "true", reason="CI keychain is locked/ephemeral")
def test_keychain_seed_roundtrip():
    import keyring
    from surgic.audit.signing import KeychainStore, Signer

    store = KeychainStore("com.surgic.test." + uuid.uuid4().hex[:8], "test")
    try:
        Signer.generate(store)
        s = Signer(store)
        assert s.fingerprint().startswith("sha256:")
        assert Signer(store).fingerprint() == s.fingerprint()
    finally:
        keyring.delete_password(store.service, store.account)


def test_hdiutil_info_parses():
    from surgic.env import Runner, ramdisk
    assert isinstance(ramdisk.ram_devices(Runner()), list)


def test_pf_template_syntax_with_pfctl_if_sudo():
    """pfctl -n parses the rendered ruleset without loading it (needs passwordless sudo)."""
    import subprocess
    from surgic.env.firewall import render

    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("passwordless sudo unavailable")
    p = subprocess.run(["sudo", "-n", "pfctl", "-n", "-f", "-"], input=render("10.0.0.5").encode(),
                       capture_output=True)
    assert p.returncode == 0, p.stderr.decode()


def test_platform_is_macos():
    assert sys.platform == "darwin"
