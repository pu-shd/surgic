"""Redaction renderers: write the sanitized artifact for each document kind.

Every renderer returns a ``RenderResult`` listing the files written and the
number of regions actually redacted; the caller fails closed if spans were
requested but nothing was redacted.
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

import pymupdf
from PIL import Image, ImageDraw

from ..detect.spans import Span, apply_to_text, merge
from ..extract import load_image_png
from ..extract.base import CellRef, Document, PdfBox, PixelBox
from .xlsx_redact import redact_xlsx

PAD = 1.0       # points of padding around each redacted PDF word box
OCR_PAD = 1.0   # OCR boxes; vector glyph paths fully inside are removed too

# Document-level objects that can carry text outside page content: the
# accessibility tree (/Alt, /ActualText, /T), name trees (JavaScript, embedded
# files, destinations), forms (incl. XFA), actions, outlines, page labels,
# article threads, XMP and private application data.
_CATALOG_KEYS = ("StructTreeRoot", "MarkInfo", "Names", "Dests", "AcroForm", "OpenAction", "AA",
                 "Outlines", "PageLabels", "Threads", "Metadata", "PieceInfo", "SpiderInfo",
                 "OCProperties", "Perms", "Legal", "URI", "Collection", "Lang")
_PAGE_KEYS = ("PieceInfo", "Metadata", "Thumb", "AA", "B", "StructParents", "Annots")


@dataclass
class RenderResult:
    primary: str
    sidecar: str
    regions: int
    files: list[str] = field(default_factory=list)


def _strip_objects(pdf: pymupdf.Document) -> None:
    cat = pdf.pdf_catalog()
    for key in _CATALOG_KEYS:
        pdf.xref_set_key(cat, key, "null")
    for page in pdf:
        for key in _PAGE_KEYS:
            pdf.xref_set_key(page.xref, key, "null")


def _scrub_and_save(pdf: pymupdf.Document, out: str) -> None:
    pdf.scrub(attached_files=True, clean_pages=True, embedded_files=True, hidden_text=True,
              javascript=True, metadata=True, redactions=True, remove_links=True,
              reset_fields=True, reset_responses=True, thumbnails=True, xml_metadata=True)
    pdf.set_metadata({})
    pdf.del_xml_metadata()
    pdf.set_toc([])
    _strip_objects(pdf)
    pdf.save(out, garbage=4, deflate=True, clean=True, no_new_id=True)


def redact_pdf(doc: Document, spans: list[Span], out: str) -> int:
    pdf = pymupdf.open(doc.render_path)
    for page in pdf:
        for w in list(page.widgets() or []):
            page.delete_widget(w)
        for a in list(page.annots() or []):
            page.delete_annot(a)
    regions = 0
    touched: set[int] = set()
    for s in merge(spans):
        for seg in doc.segments_overlapping(s.start, s.end):
            if not isinstance(seg.loc, PdfBox):
                continue
            b = seg.loc
            page = pdf[b.page]
            pad = OCR_PAD if b.ocr else PAD
            rect = pymupdf.Rect(b.x0 - pad, b.y0 - pad, b.x1 + pad, b.y1 + pad) & page.rect
            page.add_redact_annot(rect, fill=(0, 0, 0))
            touched.add(b.page)
            regions += 1
    for pno in touched:
        pdf[pno].apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS,
                                  graphics=pymupdf.PDF_REDACT_LINE_ART_REMOVE_IF_COVERED,
                                  text=pymupdf.PDF_REDACT_TEXT_REMOVE)
    _scrub_and_save(pdf, out)
    pdf.close()
    return regions


def redact_image(doc: Document, spans: list[Span], out: str) -> int:
    _, img = load_image_png(doc.render_path)
    draw = ImageDraw.Draw(img)
    regions = 0
    for s in merge(spans):
        for seg in doc.segments_overlapping(s.start, s.end):
            if isinstance(seg.loc, PixelBox):
                b = seg.loc
                draw.rectangle([b.x0 - 2, b.y0 - 2, b.x1 + 2, b.y1 + 2], fill=(0, 0, 0))
                regions += 1
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    pdf = pymupdf.open()
    page = pdf.new_page(width=img.width * 72 / 300, height=img.height * 72 / 300)
    page.insert_image(page.rect, stream=buf.getvalue())
    _scrub_and_save(pdf, out)
    pdf.close()
    return regions


def render(doc: Document, spans: list[Span], out_dir: str, stem: str) -> RenderResult:
    od = Path(out_dir)
    od.mkdir(parents=True, exist_ok=True)
    sidecar = str(od / f"{stem}.redacted.txt")
    merged = merge(spans)
    if doc.kind == "pdf":
        primary = str(od / f"{stem}.redacted.pdf")
        regions = redact_pdf(doc, merged, primary)
    elif doc.kind == "image":
        primary = str(od / f"{stem}.redacted.pdf")
        regions = redact_image(doc, merged, primary)
    elif doc.kind == "xlsx":
        primary = str(od / f"{stem}.redacted.xlsx")
        regions = redact_xlsx(doc, merged, primary)
    elif doc.kind == "text":
        primary = sidecar
        regions = len(merged)
    else:
        raise ValueError("unknown kind")
    Path(sidecar).write_text(apply_to_text(doc.text, merged), encoding="utf-8")
    files = [primary] if primary == sidecar else [primary, sidecar]
    return RenderResult(primary=primary, sidecar=sidecar, regions=regions, files=files)


__all__ = ["render", "RenderResult", "CellRef"]
