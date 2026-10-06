"""Content checks that do not trust the file extension.

* ``check_magic`` - the leading bytes must match the format the extension
  claims; a PDF renamed to .txt, or a ZIP renamed to .csv, is rejected.
* ``check_text`` - files handled as plain text must actually be text, and must
  not carry encoded payloads (data: URIs, long base64 or hex runs) that the
  detectors cannot read but the released copy would keep byte for byte.
"""
from __future__ import annotations

import re

from .base import UnsupportedDocument

ZIP = (b"PK\x03\x04",)
OLE = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)
_MAGIC: dict[str, tuple[bytes, ...]] = {
    ".pdf": (b"%PDF-",),
    ".docx": ZIP, ".xlsx": ZIP, ".xlsm": ZIP, ".odt": ZIP, ".ods": ZIP,
    ".doc": OLE, ".xls": OLE,
    ".rtf": (b"{\\rtf",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".tif": (b"II*\x00", b"MM\x00*"), ".tiff": (b"II*\x00", b"MM\x00*"),
    ".bmp": (b"BM",),
}

# Signatures of binary/container formats that must never be handled as text.
_BINARY_SIGNATURES = (
    b"%PDF-", b"PK\x03\x04", b"\xd0\xcf\x11\xe0", b"\x89PNG", b"\xff\xd8\xff", b"GIF8",
    b"II*\x00", b"MM\x00*", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh", b"\xfd7zXZ",
    b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"{\\rtf",
)

_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+[^,]{0,200}?;base64,", re.I)
# Single character classes only (no nested quantifiers): linear-time scans.
# Base64 may be line-wrapped (MIME/PEM), so whitespace is part of a run.
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=\s]{256,}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f:\s]{512,}")
MIN_BASE64_RUN = 256
MIN_HEX_RUN = 512
MAX_CONTROL_FRACTION = 0.001


def check_magic(path: str, ext: str) -> None:
    expected = _MAGIC.get(ext)
    if expected is None:
        return
    with open(path, "rb") as f:
        head = f.read(1024)
    if ext == ".pdf":
        ok = b"%PDF-" in head  # the spec allows leading junk before the header
    else:
        ok = head.startswith(expected)
    if not ok:
        raise UnsupportedDocument("content_type_mismatch")


def _is_base64_blob(run: str) -> bool:
    # Prose matches the character class too; encoded data is long unbroken
    # tokens mixing upper case, lower case and digits.
    tokens = [t for t in run.split() if len(t) >= 40]
    compact = "".join(tokens)
    if len(compact) < MIN_BASE64_RUN:
        return False
    return (any(c.islower() for c in compact) and any(c.isupper() for c in compact)
            and any(c.isdigit() for c in compact))


def _is_hex_blob(run: str) -> bool:
    compact = re.sub(r"[:\s]", "", run)
    return len(compact) >= MIN_HEX_RUN and len(compact) >= 0.7 * len(run) and any(c.isdigit() for c in compact)


def check_text(raw: bytes, text: str) -> None:
    head = raw[:16]
    if any(head.startswith(sig) for sig in _BINARY_SIGNATURES):
        raise UnsupportedDocument("content_type_mismatch")
    if b"\x00" in raw:
        raise UnsupportedDocument("binary_content")
    controls = sum(1 for c in text if ord(c) < 32 and c not in "\t\n\r\f")
    if text and controls / len(text) > MAX_CONTROL_FRACTION:
        raise UnsupportedDocument("binary_content")
    if _DATA_URI.search(text):
        raise UnsupportedDocument("embedded_data_uri")
    if any(_is_base64_blob(m.group(0)) for m in _BASE64_RUN.finditer(text)):
        raise UnsupportedDocument("embedded_encoded_blob")
    if any(_is_hex_blob(m.group(0)) for m in _HEX_RUN.finditer(text)):
        raise UnsupportedDocument("embedded_encoded_blob")
