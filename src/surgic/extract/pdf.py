"""PDF extraction: normalized page, native word boxes, plus full-page OCR.

Normalization makes everything the file can display visible and on-page
before anything is read: optional-content layers are switched on (their
definitions are removed), the page is un-rotated, and the media box is grown
to cover every drawn object, which also discards any narrower crop box. Text
hidden by a crop box, placed off-page or kept in an "off" layer would
otherwise be invisible to extraction yet survive into the released file.

Every page is then rendered and OCR'd in full. OCR words that the native text
layer already accounts for are dropped; the rest (text drawn as vector paths,
fonts whose Unicode mapping is wrong or missing, text inside images of any
size, scans) are added as located segments so they are detected and redacted.
"""
from __future__ import annotations

import difflib
import re

import pymupdf as fitz

from .base import Document, PdfBox, TextBuilder, UnsupportedDocument
from .ocr import OcrFn, OcrWord

OCR_DPI = 300
MAX_OCR_PIXELS = 60_000_000      # lower the DPI for very large pages
MAX_PAGE_EXTENT = 14_400.0       # 200 in: the PDF user-space limit
MIN_OVERLAP = 0.3                # fraction of an OCR box a native word must cover
MATCH_RATIO = 0.6                # OCR vs native text similarity that counts as "same word"
_BAND = 24.0                     # points per bucket in the native-word index

_NORM = re.compile(r"[\W_]+", re.UNICODE)


def _norm(s: str) -> str:
    return _NORM.sub("", s).lower()


def normalize(pdf: fitz.Document) -> None:
    """Make all displayable content visible and inside the page (in place)."""
    pdf.xref_set_key(pdf.pdf_catalog(), "OCProperties", "null")
    for pno in range(pdf.page_count):
        page = pdf[pno]
        if page.rotation:
            page.set_rotation(0)
        for key in ("CropBox", "TrimBox", "BleedBox", "ArtBox"):
            pdf.xref_set_key(page.xref, key, "null")
        page = pdf.reload_page(page)
        box = fitz.Rect(page.rect)
        for _kind, bbox in page.get_bboxlog():
            r = fitz.Rect(bbox)
            if r.is_empty or r.is_infinite:
                continue
            box |= r
        if (box.width > MAX_PAGE_EXTENT or box.height > MAX_PAGE_EXTENT
                or max(abs(box.x0), abs(box.y0), abs(box.x1), abs(box.y1)) > 2 * MAX_PAGE_EXTENT):
            raise UnsupportedDocument("pdf_content_out_of_range")
        if box != page.rect:
            # Page space is y-down from the media box's top-left; MediaBox is
            # stored in PDF user space, so map back through the page matrix.
            m = box * ~page.transformation_matrix
            pdf.xref_set_key(page.xref, "MediaBox", f"[{m.x0:.4f} {m.y0:.4f} {m.x1:.4f} {m.y1:.4f}]")
            pdf.reload_page(page)


def _index(words) -> dict[int, list]:
    idx: dict[int, list] = {}
    for w in words:
        for b in range(int(w[1] // _BAND), int(w[3] // _BAND) + 1):
            idx.setdefault(b, []).append(w)
    return idx


def _covered(r: fitz.Rect, text: str, idx: dict[int, list]) -> bool:
    """True if native words under ``r`` already carry ``text``."""
    area = abs(r) or 1.0
    seen, cands = set(), []
    for b in range(int(r.y0 // _BAND), int(r.y1 // _BAND) + 1):
        for w in idx.get(b, ()):
            if id(w) in seen:
                continue
            seen.add(id(w))
            inter = r & fitz.Rect(w[:4])
            if not inter.is_empty and abs(inter) >= MIN_OVERLAP * min(area, abs(fitz.Rect(w[:4])) or 1.0):
                cands.append(w)
    if not cands:
        return False
    t = _norm(text)
    native = _norm("".join(w[4] for w in sorted(cands, key=lambda w: (w[1], w[0]))))
    if not t or t in native:
        return True
    return difflib.SequenceMatcher(None, t, native).ratio() >= MATCH_RATIO


def _page_ocr(page: fitz.Page, ocr: OcrFn) -> tuple[list[OcrWord], float]:
    dpi = OCR_DPI
    w_in, h_in = page.rect.width / 72.0, page.rect.height / 72.0
    if w_in * h_in * dpi * dpi > MAX_OCR_PIXELS:
        dpi = int((MAX_OCR_PIXELS / (w_in * h_in)) ** 0.5)
    pix = page.get_pixmap(dpi=dpi, alpha=False)
    return ocr(pix.tobytes("png")), 72.0 / dpi


def extract_pdf(path: str, doc_id: str, ocr: OcrFn | None, kind: str = "pdf",
                normalized_out: str | None = None) -> Document:
    """Extract located text. With ``normalized_out`` the normalized PDF is
    saved there and becomes the document's render path (what gets redacted)."""
    try:
        pdf = fitz.open(path)
    except Exception as e:  # noqa: BLE001
        raise UnsupportedDocument("pdf_open_failed") from e
    if pdf.needs_pass:
        raise UnsupportedDocument("pdf_encrypted")
    if not pdf.is_pdf:
        raise UnsupportedDocument("pdf_open_failed")
    normalize(pdf)

    tb = TextBuilder()
    ocr_pages = 0
    for pno, page in enumerate(pdf):
        words = page.get_text("words", sort=True)
        prev_block = None
        for x0, y0, x1, y1, w, block, _line, _ in words:
            # Lines inside a block are soft-wrapped prose: join with a space so
            # values wrapped across lines ("Halvorsen\nMaritime") stay contiguous.
            if prev_block is not None:
                tb.sep("\n" if block != prev_block else " ")
            prev_block = block
            tb.add(w, PdfBox(pno, x0, y0, x1, y1))

        if ocr is not None:
            idx = _index(words)
            ocr_words, scale = _page_ocr(page, ocr)
            prev_line = None
            added = 0
            for ow in ocr_words:
                r = fitz.Rect(ow.x0 * scale, ow.y0 * scale, ow.x1 * scale, ow.y1 * scale)
                if _covered(r, ow.text, idx):
                    continue
                # Space within an OCR line, newline between lines: values such as
                # "(415) 555-0142" must stay contiguous for the pattern engines.
                tb.sep(" " if ow.line == prev_line else "\n")
                prev_line = ow.line
                tb.add(ow.text, PdfBox(pno, r.x0, r.y0, r.x1, r.y1, ocr=True))
                added += 1
            if added:
                ocr_pages += 1
        tb.sep("\n\f\n")

    render_path = path
    if normalized_out:
        pdf.save(normalized_out, garbage=1)
        render_path = normalized_out
    pdf.close()
    return Document(doc_id=doc_id, kind=kind, text=tb.text, segments=tb.segments,
                    source_path=path, render_path=render_path, ocr_pages=ocr_pages)


def extract_pdf_plumber_text(path: str) -> str:
    """Independent second parser, used only by the post-sanitization scan."""
    import pdfplumber

    out = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            out.append(page.extract_text() or "")
    return "\n".join(out)
