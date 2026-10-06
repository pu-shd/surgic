"""Planted-secret leak tests: every value must be absent from every rendering
of every output artifact, and redaction must have actually happened."""
from __future__ import annotations

import shutil
import zipfile

import openpyxl
import pymupdf
import pytest

from fixtures import make
from surgic.audit.postscan import pdf_raw_text, postscan, zip_raw_text
from surgic.config import LLMConfig
from surgic.detect import propagate
from surgic.detect.contextual import contextual_spans
from surgic.detect.mask import build
from surgic.detect.spans import merge
from surgic.extract import extract
from surgic.extract.convert import find_soffice
from surgic.llm.mock import MockBackend
from surgic.redact import render


def sanitize(path, phase_a, ocr, tmp_path):
    doc = extract(str(path), "d", str(tmp_path / "conv"), ocr)
    a = propagate(doc.text, phase_a.find(doc.text))
    b = MockBackend(LLMConfig(backend="mock"), terms=[t.split("=", 1) for t in make.MOCK_TERMS.split(";")])
    b.start()
    bs, stats, _ = contextual_spans(build(doc.text, a), b, 6000, 400)
    spans = merge(propagate(doc.text, a + bs))
    res = render(doc, spans, str(tmp_path / "out"), "d")
    return doc, spans, res, stats


def all_renderings(primary: str, sidecar: str, ocr) -> dict[str, str]:
    from surgic.audit.postscan import renderings
    r = renderings(primary, sidecar, ocr)
    if primary.endswith(".xlsx"):
        r["raw"] = zip_raw_text(primary)
    with open(primary, "rb") as f:
        r["bytes"] = f.read().decode("latin-1")
    return r


def _ws(t: str) -> str:
    return " ".join(t.split())


def assert_no_leaks(texts: dict[str, str], values):
    # Whitespace-normalized: a value split across lines ("4111\n1111 ...") still counts.
    leaks = {(name, v) for name, t in texts.items() for v in values if _ws(v) in _ws(t)}
    assert not leaks, f"leaked: {sorted(leaks)}"


def ocr_recognized(doc_text: str) -> list[str]:
    """Planted values the OCR engine read correctly (modulo whitespace)."""
    norm = _ws(doc_text)
    return [v for v in make.MUST_NOT_LEAK if _ws(v) in norm]


def test_text_pdf(phase_a, ocr, tmp_path):
    src = make.make_text_pdf(tmp_path / "memo.pdf")
    doc, spans, res, stats = sanitize(src, phase_a, ocr, tmp_path)
    assert all(v in doc.text for v in make.ALL_VALUES), "fixture extraction incomplete"
    assert res.regions >= len(make.ALL_VALUES)
    assert stats.findings >= 2 and stats.relocated >= 1  # mock gives loose offsets
    texts = all_renderings(res.primary, res.sidecar, ocr)
    assert_no_leaks(texts, make.MUST_NOT_LEAK)
    pdf = pymupdf.open(res.primary)
    content_keys = ("title", "author", "subject", "keywords", "creator", "producer")
    assert all(not pdf.metadata.get(k) for k in content_keys), pdf.metadata
    assert not pdf.get_xml_metadata()
    assert list(pdf[0].annots()) == [] and pdf.embfile_count() == 0
    # Unrelated words survive (redaction is targeted, not a blank page).
    assert "renewal" in texts["primary"] and "memo" in texts["primary"]


def test_scanned_pdf_ocr(phase_a, ocr, tmp_path):
    src = make.make_scanned_pdf(tmp_path / "scan.pdf")
    doc, spans, res, _ = sanitize(src, phase_a, ocr, tmp_path)
    assert doc.ocr_pages == 1
    assert make.STRUCTURED["ssn"] in doc.text and make.STRUCTURED["email"] in doc.text
    assert res.regions > 5
    texts = all_renderings(res.primary, res.sidecar, ocr)
    # Every value OCR read correctly (modulo whitespace) must be gone from every rendering.
    recognized = ocr_recognized(doc.text)
    assert len(recognized) >= 9, recognized
    for v in ("phone", "card"):  # multi-token values: regression for per-word newline joins
        assert make.STRUCTURED[v] in doc.text, f"{v} not contiguous in OCR text"
    assert_no_leaks(texts, recognized)


def test_png_image(phase_a, ocr, tmp_path):
    src = make.make_png(tmp_path / "wb.png")
    doc, spans, res, _ = sanitize(src, phase_a, ocr, tmp_path)
    assert res.primary.endswith(".pdf") and res.regions > 5
    texts = all_renderings(res.primary, res.sidecar, ocr)
    recognized = ocr_recognized(doc.text)
    assert len(recognized) >= 9, recognized
    assert_no_leaks(texts, recognized + [make.PERSON])


def test_xlsx_all_parts(phase_a, ocr, tmp_path):
    src = make.make_xlsx(tmp_path / "p.xlsx")
    doc, spans, res, _ = sanitize(src, phase_a, ocr, tmp_path)
    assert res.primary.endswith(".xlsx") and res.regions > 5
    texts = all_renderings(res.primary, res.sidecar, ocr)
    values = [make.PERSON, make.STRUCTURED["ssn"], make.STRUCTURED["email"], make.STRUCTURED["card"],
              make.STRUCTURED["ip"], make.STRUCTURED["emp"], make.STRUCTURED["dcn"],
              make.STRUCTURED["codename"], make.STRUCTURED["marker"], make.CONTEXTUAL["client"]]
    assert_no_leaks(texts, values)
    wb = openpyxl.load_workbook(res.primary)
    assert wb.properties.creator in ("", None) and not wb.properties.title
    assert len(wb.worksheets) == 2  # formerly hidden sheet: redacted, renamed, and visible
    assert wb.worksheets[1].title == "Sheet2"
    assert all(w.sheet_state == "visible" for w in wb.worksheets)
    assert not wb.worksheets[0].row_dimensions[7].hidden
    assert wb.worksheets[0]["B8"].number_format == "General" and wb.worksheets[0]["B8"].value == 1250
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for c in row:
                assert c.comment is None and c.data_type != "f"
    with zipfile.ZipFile(res.primary) as z:
        assert not [n for n in z.namelist() if "comment" in n.lower() or "vba" in n.lower()]
    assert wb.worksheets[0]["A1"].value == "Name"  # unrelated cells intact


def test_txt(phase_a, ocr, tmp_path):
    src = make.make_txt(tmp_path / "n.txt")
    doc, spans, res, _ = sanitize(src, phase_a, ocr, tmp_path)
    out = open(res.primary).read()
    assert_no_leaks({"txt": out}, make.MUST_NOT_LEAK)
    assert "[REDACTED:US_SSN]" in out


@pytest.mark.requires_tool
@pytest.mark.skipif(find_soffice() is None, reason="LibreOffice (soffice) not installed; runs in Docker")
def test_docx_via_pdf(phase_a, ocr, tmp_path):
    src = make.make_docx(tmp_path / "l.docx")
    doc, spans, res, _ = sanitize(src, phase_a, ocr, tmp_path)
    assert res.primary.endswith(".pdf") and res.regions > 5
    texts = all_renderings(res.primary, res.sidecar, ocr)
    assert_no_leaks(texts, make.MUST_NOT_LEAK)


def test_postscan_quarantines_unredacted_output(phase_a, ocr, tmp_path, fake_scanners):
    src = make.make_text_pdf(tmp_path / "memo.pdf")
    sidecar = tmp_path / "side.txt"
    sidecar.write_text(make.PARAGRAPH)
    known = set(make.ALL_VALUES)
    rep = postscan(str(src), str(sidecar), known, phase_a, ocr, fake_scanners, str(tmp_path))
    assert not rep.passed
    for check in ("known_values:primary", "known_values:sidecar", "known_values:second_parser",
                  "phase_a:sidecar", "gitleaks", "trufflehog"):
        assert rep.checks.get(check, 0) > 0, check
    assert rep.rules.get("gitleaks:aws-access-token", 0) >= 1
    pub = rep.public()
    assert "new_values" not in pub and not any(v in str(pub) for v in make.ALL_VALUES)


def test_postscan_passes_clean_output(phase_a, ocr, tmp_path, real_or_fake_scanners):
    src = make.make_text_pdf(tmp_path / "memo.pdf")
    doc, spans, res, _ = sanitize(src, phase_a, ocr, tmp_path)
    known = {doc.text[s.start:s.end] for s in spans}
    rep = postscan(res.primary, res.sidecar, known, phase_a, ocr, real_or_fake_scanners, str(tmp_path))
    assert rep.passed, rep.public()
    assert rep.checks["renderings"] == 5  # sidecar, primary, second_parser, raw, raw_structured
    assert rep.checks.get("gitleaks_ran") == 1 and rep.checks.get("trufflehog_ran") == 1


@pytest.mark.requires_tool
@pytest.mark.skipif(not (shutil.which("gitleaks") and shutil.which("trufflehog")),
                    reason="real gitleaks/trufflehog not installed; runs in Docker")
def test_real_scanners_flag_aws_key(tmp_path, regex_only):
    from surgic.audit.postscan import ScanReport, SecretScanners
    d = tmp_path / "scan"
    d.mkdir()
    # Fabricated credential assembled at runtime so no secret-like literal is in source.
    import random
    rng = random.Random(7)
    alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    key_id = "AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
    secret = "".join(rng.choice(alnum) for _ in range(40))
    (d / "a.txt").write_text(f"aws_access_key_id = {key_id}\naws_secret_access_key = {secret}\n")
    rep = ScanReport()
    SecretScanners("gitleaks", "trufflehog", True).scan_dir(str(d), rep)
    assert not rep.passed and rep.checks.get("gitleaks", 0) >= 1


def test_raw_pdf_text_includes_metadata(tmp_path):
    src = make.make_text_pdf(tmp_path / "memo.pdf")
    raw = pdf_raw_text(str(src))
    assert make.PERSON in raw  # sanity: the raw extractor really sees metadata


def test_pdf_hidden_content_is_found_and_redacted(phase_a, ocr, tmp_path):
    src = make.make_hiding_pdf(tmp_path / "hiding.pdf")
    plain = "".join(p.get_text() for p in pymupdf.open(src))
    assert not any(v in plain for v in make.HIDDEN.values()), "fixture must hide its values"
    doc, spans, res, _ = sanitize(src, phase_a, ocr, tmp_path)
    for k, v in make.HIDDEN.items():
        assert v in doc.text, f"{k} not extracted"
    texts = all_renderings(res.primary, res.sidecar, ocr)
    assert_no_leaks(texts, list(make.HIDDEN.values()) + [make.PERSON])
    out = pymupdf.open(res.primary)
    cat = out.pdf_catalog()
    for key in ("StructTreeRoot", "OCProperties", "Names", "AcroForm"):
        assert out.xref_get_key(cat, key)[0] == "null", key
    assert out[0].cropbox == out[0].mediabox
    # Nothing can be revealed by changing the view: the output has no layers
    # and no text outside the page.
    words = out[0].get_text("words", clip=pymupdf.INFINITE_RECT(),
                            flags=pymupdf.TEXTFLAGS_WORDS & ~pymupdf.TEXT_MEDIABOX_CLIP)
    assert all(pymupdf.Rect(w[:4]).intersects(out[0].rect) for w in words)


def test_misencoded_text_is_recovered_by_ocr(tmp_path):
    """A font whose Unicode mapping lies: the text layer says one thing, the
    page shows another. The OCR word the text layer does not account for is
    added as its own located segment."""
    from surgic.extract.ocr import OcrWord
    from surgic.extract.pdf import extract_pdf
    pdf = pymupdf.open()
    page = pdf.new_page(width=612, height=792)
    page.insert_text((72, 100), "Xq#zZ!kk@pp", fontsize=12)       # "garbled" text layer
    page.insert_text((72, 200), "Quarterly", fontsize=12)
    pdf.save(tmp_path / "g.pdf")
    scale = 300 / 72

    def fake_ocr(png):
        return [OcrWord("219-09-9999", int(72 * scale), int(90 * scale), int(160 * scale), int(102 * scale), 0),
                OcrWord("Quarterly", int(72 * scale), int(190 * scale), int(130 * scale), int(202 * scale), 1)]

    doc = extract_pdf(str(tmp_path / "g.pdf"), "g", fake_ocr)
    assert "219-09-9999" in doc.text            # what the page shows
    assert doc.text.count("Quarterly") == 1     # matching OCR is not duplicated
    seg = next(s for s in doc.segments if doc.text[s.start:s.end] == "219-09-9999")
    assert seg.loc.ocr and abs(seg.loc.x0 - 72) < 1


def test_postscan_regex_scans_raw_parts(regex_only, tmp_path):
    """A structured value that only exists in a PDF object (not page text) fails the scan."""
    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "nothing here")
    xref = pdf.get_new_xref()
    pdf.update_object(xref, f"<</Private ({make.STRUCTURED['ssn']})>>")
    pdf.xref_set_key(pdf.pdf_catalog(), "PieceInfo", f"{xref} 0 R")
    pdf.save(tmp_path / "o.pdf")
    side = tmp_path / "o.txt"
    side.write_text("nothing here")
    rep = postscan(str(tmp_path / "o.pdf"), str(side), set(), regex_only, None, None, str(tmp_path))
    assert not rep.passed and rep.checks.get("regex_raw", 0) >= 1
    assert rep.rules.get("regex_raw:US_SSN", 0) >= 1
