"""Format dispatch for extraction."""
from __future__ import annotations

import io
from pathlib import Path

from PIL import Image

from .base import Document, PixelBox, TextBuilder, UnsupportedDocument
from .convert import convert
from .ocr import OcrFn
from .pdf import extract_pdf
from .xlsx import extract_xlsx

PDF_EXT = {".pdf"}
OFFICE_TO_PDF_EXT = {".docx", ".doc", ".odt", ".rtf"}
SHEET_EXT = {".xlsx", ".xlsm"}
OFFICE_TO_XLSX_EXT = {".xls", ".ods"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif"}
TEXT_EXT = {".txt", ".md", ".csv", ".log", ".json", ".xml", ".html", ".htm"}
SUPPORTED_EXT = PDF_EXT | OFFICE_TO_PDF_EXT | SHEET_EXT | OFFICE_TO_XLSX_EXT | IMAGE_EXT | TEXT_EXT


def load_image_png(path: str) -> tuple[bytes, Image.Image]:
    """Decode to pixels only (drops EXIF/XMP/ICC text chunks)."""
    with Image.open(path) as im:
        im.seek(0)
        rgb = im.convert("RGB")
    clean = Image.new("RGB", rgb.size)
    clean.paste(rgb)
    buf = io.BytesIO()
    clean.save(buf, format="PNG")
    return buf.getvalue(), clean


def extract_image(path: str, doc_id: str, ocr: OcrFn) -> Document:
    png, _ = load_image_png(path)
    tb = TextBuilder()
    for w in ocr(png):
        if tb.segments:
            tb.sep(" ")
        tb.add(w.text, PixelBox(w.x0, w.y0, w.x1, w.y1))
    return Document(doc_id=doc_id, kind="image", text=tb.text, segments=tb.segments,
                    source_path=path, render_path=path, ocr_pages=1)


def extract_text(path: str, doc_id: str) -> Document:
    raw = Path(path).read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return Document(doc_id=doc_id, kind="text", text=text, source_path=path, render_path=path)


def extract(path: str, doc_id: str, work_dir: str, ocr: OcrFn) -> Document:
    ext = Path(path).suffix.lower()
    if ext in PDF_EXT:
        return extract_pdf(path, doc_id, ocr)
    if ext in OFFICE_TO_PDF_EXT:
        rendered = convert(path, work_dir, "pdf")
        doc = extract_pdf(rendered, doc_id, ocr)
        doc.source_path = path
        return doc
    if ext in SHEET_EXT:
        return extract_xlsx(path, doc_id)
    if ext in OFFICE_TO_XLSX_EXT:
        doc = extract_xlsx(convert(path, work_dir, "xlsx"), doc_id)
        doc.source_path = path
        return doc
    if ext in IMAGE_EXT:
        return extract_image(path, doc_id, ocr)
    if ext in TEXT_EXT:
        return extract_text(path, doc_id)
    raise UnsupportedDocument("unsupported_extension")


__all__ = ["Document", "UnsupportedDocument", "extract", "SUPPORTED_EXT"]
