"""Cell-level XLSX redaction.

The output workbook keeps only values: formulas become their (redacted) cached
values, and comments, hyperlinks, defined names, document properties, external
links, data validation, conditional formatting, tables, pivots, images and
charts are removed. VBA is never retained.
"""
from __future__ import annotations

from collections import defaultdict

import openpyxl
from openpyxl.formatting.formatting import ConditionalFormattingList
from openpyxl.packaging.core import DocumentProperties
from openpyxl.packaging.custom import CustomPropertyList

from ..detect.spans import Span
from ..extract.base import CellRef, Document

MARK = "[REDACTED:{cat}]"
FORMULA_REMOVED = "[FORMULA REMOVED]"


def _redact_segment(text: str, seg_start: int, spans: list[Span]) -> str:
    out, pos = [], 0
    for s in spans:
        a = max(s.start - seg_start, 0)
        b = min(s.end - seg_start, len(text))
        if b <= pos:
            continue
        out.append(text[pos:a] if a > pos else "")
        out.append(MARK.format(cat=s.category))
        pos = max(pos, b)
    out.append(text[pos:])
    return "".join(out)


def redact_xlsx(doc: Document, spans: list[Span], out: str) -> int:
    wb = openpyxl.load_workbook(doc.render_path, data_only=False, keep_links=False, keep_vba=False)
    wb_v = openpyxl.load_workbook(doc.render_path, data_only=True, keep_links=False)

    # Per-segment overlapping spans.
    hits: dict[CellRef, tuple[int, str, list[Span]]] = {}
    for seg in doc.segments:
        if not isinstance(seg.loc, CellRef):
            continue
        ov = [s for s in spans if s.start < seg.end and s.end > seg.start]
        hits[seg.loc] = (seg.start, doc.text[seg.start:seg.end], ov)

    regions = 0
    title_map: dict[str, str] = {}
    hf_redactions: dict[str, dict[str, str]] = defaultdict(dict)
    for ref, (start, text, ov) in hits.items():
        if not ov:
            continue
        regions += len(ov)
        if ref.part == "title":
            title_map[ref.sheet] = ""
        elif ref.part == "header_footer":
            hf_redactions[ref.sheet][ref.coord] = _redact_segment(text, start, ov)

    for idx, ws in enumerate(wb.worksheets, start=1):
        title = ws.title
        ws_v = wb_v[title]
        for row in ws.iter_rows():
            for cell in row:
                cell.comment = None
                cell.hyperlink = None
                if cell.value is None:
                    continue
                if cell.data_type == "f":
                    cached = ws_v[cell.coordinate].value
                    if cached is None:
                        cell.value = FORMULA_REMOVED
                        continue
                    cell.value = cached
                ref = CellRef(title, cell.coordinate)
                if ref in hits and hits[ref][2]:
                    start, text, ov = hits[ref]
                    cell.value = _redact_segment(text, start, ov)
                    cell.number_format = "General"
        for part, new_text in hf_redactions.get(title, {}).items():
            hf_name, pos = part.split(".")
            getattr(getattr(ws, hf_name), pos).text = new_text
        ws.data_validations.dataValidation = []
        ws.conditional_formatting = ConditionalFormattingList()
        for name in list(ws.tables.keys()):
            del ws.tables[name]
        ws._images = []
        ws._charts = []
        ws._pivots = []
        if hasattr(ws, "defined_names"):
            ws.defined_names.clear()
        if title in title_map:
            ws.title = f"Sheet{idx}"

    wb.defined_names.clear()
    wb._external_links = []
    wb.properties = DocumentProperties(creator="", lastModifiedBy="", title="", subject="",
                                       description="", keywords="", category="")
    wb.custom_doc_props = CustomPropertyList()
    wb.save(out)
    return regions
