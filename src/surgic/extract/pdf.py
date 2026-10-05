"""PDF extraction with PyMuPDF word boxes plus OCR of embedded image regions."""
from __future__ import annotations

import pymupdf as fitz

from .base import Document, PdfBox, TextBuilder, UnsupportedDocument
from .ocr import OcrFn

OCR_DPI = 300
MIN_IMAGE_FRACTION = 0.01  # OCR image regions covering >= 1% of the page


def _image_regions(page: fitz.Page) -> list[fitz.Rect]:
    area = abs(page.rect)
    rects = []
    for info in page.get_image_info():
        r = fitz.Rect(info["bbox"]) & page.rect
        if not r.is_empty and abs(r) >= MIN_IMAGE_FRACTION * area:
            rects.append(r)
    return rects


def extract_pdf(path: str, doc_id: str, ocr: OcrFn | None, kind: str = "pdf") -> Document:
    try:
        pdf = fitz.open(path)
    except Exception as e:  # noqa: BLE001
        raise UnsupportedDocument("pdf_open_failed") from e
    if pdf.needs_pass:
        raise UnsupportedDocument("pdf_encrypted")

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

        regions = _image_regions(page) if ocr else []
        if regions:
            ocr_pages += 1
        scale = 72.0 / OCR_DPI
        for r in regions:
            pix = page.get_pixmap(dpi=OCR_DPI, clip=r, alpha=False)
            prev_line = None
            for ow in ocr(pix.tobytes("png")):
                # Space within an OCR line, newline between lines: values such as
                # "(415) 555-0142" must stay contiguous for the pattern engines.
                tb.sep(" " if ow.line == prev_line else "\n")
                prev_line = ow.line
                tb.add(
                    ow.text,
                    PdfBox(pno, r.x0 + ow.x0 * scale, r.y0 + ow.y0 * scale,
                           r.x0 + ow.x1 * scale, r.y0 + ow.y1 * scale, ocr=True),
                )
        tb.sep("\n\f\n")
    pdf.close()
    return Document(doc_id=doc_id, kind=kind, text=tb.text, segments=tb.segments,
                    source_path=path, render_path=path, ocr_pages=ocr_pages)


def extract_pdf_plumber_text(path: str) -> str:
    """Independent second parser, used only by the post-sanitization scan."""
    import pdfplumber

    out = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            out.append(page.extract_text() or "")
    return "\n".join(out)
