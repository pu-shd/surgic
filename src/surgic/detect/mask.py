"""Masked text for the LLM plus an offset map back to original coordinates.

Phase A spans are replaced by stable placeholders (``[US_SSN_1]``); identical
values share a placeholder so the model can still follow coreference without
ever seeing the value.
"""
from __future__ import annotations

from dataclasses import dataclass

from .spans import Span, merge


@dataclass(frozen=True)
class Piece:
    m_start: int
    m_end: int
    o_start: int
    o_end: int
    placeholder: bool


@dataclass
class Masked:
    text: str
    pieces: list[Piece]

    def to_original(self, m_start: int, m_end: int) -> tuple[int, int]:
        """Map a masked-text range to the minimal original range covering it.
        Touching any part of a placeholder covers its whole original span."""
        if not 0 <= m_start < m_end <= len(self.text):
            raise ValueError("range outside masked text")
        o_start = o_end = None
        for p in self.pieces:
            if p.m_end <= m_start or p.m_start >= m_end:
                continue
            if p.placeholder:
                a, b = p.o_start, p.o_end
            else:
                a = p.o_start + max(m_start, p.m_start) - p.m_start
                b = p.o_start + min(m_end, p.m_end) - p.m_start
            o_start = a if o_start is None else min(o_start, a)
            o_end = b if o_end is None else max(o_end, b)
        assert o_start is not None and o_end is not None
        return o_start, o_end


def build(text: str, spans: list[Span]) -> Masked:
    pieces: list[Piece] = []
    parts: list[str] = []
    counters: dict[str, int] = {}
    seen: dict[tuple[str, str], str] = {}
    m = o = 0
    for s in merge(spans):
        if s.start > o:
            chunk = text[o:s.start]
            pieces.append(Piece(m, m + len(chunk), o, s.start, False))
            parts.append(chunk)
            m += len(chunk)
        key = (s.category, text[s.start:s.end])
        if key not in seen:
            counters[s.category] = counters.get(s.category, 0) + 1
            seen[key] = f"[{s.category}_{counters[s.category]}]"
        ph = seen[key]
        pieces.append(Piece(m, m + len(ph), s.start, s.end, True))
        parts.append(ph)
        m += len(ph)
        o = s.end
    if o < len(text):
        chunk = text[o:]
        pieces.append(Piece(m, m + len(chunk), o, len(text), False))
        parts.append(chunk)
    return Masked("".join(parts), pieces)
