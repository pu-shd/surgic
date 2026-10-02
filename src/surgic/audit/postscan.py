"""Post-sanitization leak scan, run on the OUTPUT artifacts before release.

Checks (any hit fails the document):
  1. known_values  - no detected sensitive value (Phase A + Phase B, original
                     text) appears in any re-extraction or raw decoded part;
  2. phase_a       - deterministic detectors find nothing new in re-extracted
                     text (placeholders excluded);
  3. gitleaks / trufflehog - offline secret scanners over text renderings.
Re-extraction uses the primary parser (with OCR) and an independent second
parser (pdfplumber), plus every decoded PDF stream / XLSX XML part.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pymupdf

from ..detect.spans import Span
from ..extract.ocr import OcrFn
from ..extract.pdf import extract_pdf, extract_pdf_plumber_text
from ..extract.xlsx import extract_xlsx
from ..logging_safe import SafeError

_REDACTION_MARK = re.compile(r"\[REDACTED:[A-Z_]+\]|\[FORMULA REMOVED\]")
MIN_VALUE_LEN = 4


@dataclass
class ScanReport:
    passed: bool = True
    checks: dict[str, int] = field(default_factory=dict)
    rules: dict[str, int] = field(default_factory=dict)
    new_values: set[str] = field(default_factory=set)  # in-memory only, never serialized

    def fail(self, check: str, n: int = 1) -> None:
        self.passed = False
        self.checks[check] = self.checks.get(check, 0) + n

    def public(self) -> dict:
        return {"passed": self.passed, "checks": dict(sorted(self.checks.items())),
                "rules": dict(sorted(self.rules.items()))}


def pdf_raw_text(path: str) -> str:
    """All decoded object definitions and streams, as text."""
    out = []
    pdf = pymupdf.open(path)
    for xref in range(1, pdf.xref_length()):
        try:
            out.append(pdf.xref_object(xref, compressed=False))
            if pdf.xref_is_stream(xref):
                out.append((pdf.xref_stream(xref) or b"").decode("latin-1"))
        except Exception:  # noqa: BLE001
            continue
    out.append(json.dumps(pdf.metadata))
    out.append(pdf.get_xml_metadata() or "")
    pdf.close()
    return "\n".join(out)


def zip_raw_text(path: str) -> str:
    out = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            out.append(name)
            out.append(z.read(name).decode("utf-8", errors="replace"))
    return "\n".join(out)


def renderings(primary: str, sidecar: str, ocr: OcrFn | None) -> dict[str, str]:
    r: dict[str, str] = {"sidecar": Path(sidecar).read_text(encoding="utf-8")}
    ext = Path(primary).suffix.lower()
    if ext == ".pdf":
        r["primary"] = extract_pdf(primary, "postscan", ocr).text
        r["second_parser"] = extract_pdf_plumber_text(primary)
        r["raw"] = pdf_raw_text(primary)
    elif ext == ".xlsx":
        r["primary"] = extract_xlsx(primary, "postscan").text
        r["raw"] = zip_raw_text(primary)
    return r


def _strip_marks(text: str) -> str:
    return _REDACTION_MARK.sub(" ", text)


class SecretScanners:
    def __init__(self, gitleaks: str, trufflehog: str, required: bool, runner=subprocess.run) -> None:
        self.gitleaks = shutil.which(gitleaks) or (gitleaks if os.path.exists(gitleaks) else None)
        self.trufflehog = shutil.which(trufflehog) or (trufflehog if os.path.exists(trufflehog) else None)
        self.required = required
        self.run = runner
        if required and not (self.gitleaks and self.trufflehog):
            raise SafeError("secret_scanner_missing")

    def scan_dir(self, d: str, report: ScanReport) -> None:
        if self.gitleaks:
            rep = os.path.join(d, ".gitleaks.json")
            p = self.run([self.gitleaks, "detect", "--no-git", "--no-banner", "--redact",
                          "--source", d, "--report-format", "json", "--report-path", rep,
                          "--exit-code", "3"], capture_output=True, timeout=600)
            if p.returncode not in (0, 3):
                raise SafeError("gitleaks_failed", status=p.returncode)
            items = json.loads(Path(rep).read_text() or "[]") if os.path.exists(rep) else []
            os.unlink(rep) if os.path.exists(rep) else None
            if p.returncode == 3 and not items:
                raise SafeError("gitleaks_inconsistent")
            for it in items:
                rid = "gitleaks:" + str(it.get("RuleID", "unknown"))[:64]
                report.rules[rid] = report.rules.get(rid, 0) + 1
            if items:
                report.fail("gitleaks", len(items))
            report.checks.setdefault("gitleaks_ran", 1)
        if self.trufflehog:
            p = self.run([self.trufflehog, "filesystem", d, "--json", "--no-update",
                          "--no-verification", "--fail"], capture_output=True, timeout=600)
            # --fail: exit 183 when results are found.
            if p.returncode not in (0, 183):
                raise SafeError("trufflehog_failed", status=p.returncode)
            n = 0
            for line in (p.stdout or b"").decode("utf-8", errors="replace").splitlines():
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "DetectorName" in obj or "SourceMetadata" in obj:
                    n += 1
                    rid = "trufflehog:" + str(obj.get("DetectorName", "unknown"))[:64]
                    report.rules[rid] = report.rules.get(rid, 0) + 1
            if p.returncode == 183 and n == 0:
                raise SafeError("trufflehog_inconsistent")
            if n:
                report.fail("trufflehog", n)
            report.checks.setdefault("trufflehog_ran", 1)


def postscan(primary: str, sidecar: str, known_values: set[str], phase_a, ocr: OcrFn | None,
             scanners: SecretScanners | None, scratch_dir: str) -> ScanReport:
    report = ScanReport()
    texts = renderings(primary, sidecar, ocr)
    report.checks["renderings"] = len(texts)

    values = sorted({v for v in known_values if len(v.strip()) >= MIN_VALUE_LEN}, key=len, reverse=True)
    for name, text in texts.items():
        n = sum(1 for v in values if v in text)
        if n:
            report.fail(f"known_values:{name}", n)

    for name in ("sidecar", "primary", "second_parser"):
        if name not in texts:
            continue
        clean = _strip_marks(texts[name])
        spans: list[Span] = phase_a.find(clean)
        if spans:
            report.fail(f"phase_a:{name}", len(spans))
            for s in spans:
                report.new_values.add(clean[s.start:s.end])

    if scanners is not None:
        d = tempfile.mkdtemp(prefix="scan_", dir=scratch_dir)
        try:
            for name, text in texts.items():
                Path(d, f"{name}.txt").write_text(text, encoding="utf-8")
            scanners.scan_dir(d, report)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return report
