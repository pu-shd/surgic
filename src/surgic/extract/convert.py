"""LibreOffice headless conversion (DOCX/DOC/ODT/RTF -> PDF, XLS/ODS -> XLSX).

The LibreOffice user profile and all outputs live in the workspace (RAM disk),
so no document-derived state touches persistent storage.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .base import UnsupportedDocument

_MAC_SOFFICE = "/Applications/LibreOffice.app/Contents/MacOS/soffice"


def find_soffice() -> str | None:
    for cand in (os.environ.get("SURGIC_SOFFICE"), shutil.which("soffice"),
                 shutil.which("libreoffice"), _MAC_SOFFICE):
        if cand and os.path.exists(cand):
            return cand
    return None


def convert(src: str, out_dir: str, target: str, timeout: int = 300) -> str:
    soffice = find_soffice()
    if not soffice:
        raise UnsupportedDocument("soffice_unavailable")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    profile = out / ".lo_profile"
    cmd = [
        soffice, "--headless", "--norestore", "--nolockcheck", "--nodefault",
        f"-env:UserInstallation=file://{profile}",
        "--convert-to", target, "--outdir", str(out), src,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise UnsupportedDocument("soffice_convert_failed") from e
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    ext = target.split(":")[0]
    result = out / (Path(src).stem + "." + ext)
    if not result.exists():
        raise UnsupportedDocument("soffice_no_output")
    return str(result)
