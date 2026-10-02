"""Extracted document model.

Every character of ``Document.text`` that came from the source maps to a
``Segment`` with a locator, so spans found in text coordinates can be applied
back onto the source file (PDF word boxes, image pixels, spreadsheet cells).
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Literal, Union

Kind = Literal["pdf", "image", "xlsx", "text"]


@dataclass(frozen=True)
class PdfBox:
    page: int
    x0: float
    y0: float
    x1: float
    y1: float
    ocr: bool = False


@dataclass(frozen=True)
class PixelBox:
    x0: int
    y0: int
    x1: int
    y1: int


@dataclass(frozen=True)
class CellRef:
    sheet: str
    coord: str          # "A1"; "" for sheet-title segments
    part: Literal["value", "title", "header_footer"] = "value"


Locator = Union[PdfBox, PixelBox, CellRef, None]


@dataclass(frozen=True)
class Segment:
    start: int
    end: int
    loc: Locator


@dataclass
class Document:
    doc_id: str
    kind: Kind
    text: str
    segments: list[Segment] = field(default_factory=list)
    source_path: str = ""
    render_path: str = ""   # PDF actually redacted (e.g. DOCX rendered to PDF)
    ocr_pages: int = 0

    def segments_overlapping(self, start: int, end: int) -> list[Segment]:
        starts = [s.start for s in self.segments]
        i = max(bisect.bisect_right(starts, start) - 1, 0)
        out = []
        for seg in self.segments[i:]:
            if seg.start >= end:
                break
            if seg.end > start:
                out.append(seg)
        return out


class TextBuilder:
    """Accumulates text while recording segment locators."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._len = 0
        self.segments: list[Segment] = []

    def add(self, s: str, loc: Locator = None) -> None:
        if not s:
            return
        if loc is not None:
            self.segments.append(Segment(self._len, self._len + len(s), loc))
        self._parts.append(s)
        self._len += len(s)

    def sep(self, s: str = " ") -> None:
        self.add(s, None)

    @property
    def text(self) -> str:
        return "".join(self._parts)


class UnsupportedDocument(Exception):
    pass
