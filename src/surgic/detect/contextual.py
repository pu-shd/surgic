"""Phase B: contextual redaction with the local LLM.

LLM offsets are never trusted. Each finding's ``text`` must match the chunk at
the reported offsets; otherwise it is relocated by exact substring search, and
rejected if absent (a fabricated span). Accepted strings are then propagated to
every occurrence in the document, so a counterparty named once in context is
removed everywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..llm.backend import LLMBackend
from ..llm.chunker import chunks
from .mask import Masked
from .spans import Span

_PLACEHOLDER_ONLY = re.compile(r"^\s*(?:\[[A-Z0-9_]+_\d+\]\s*)+$")


@dataclass
class PhaseBStats:
    chunks: int = 0
    findings: int = 0
    exact: int = 0
    relocated: int = 0
    rejected: int = 0
    by_category: dict[str, int] = field(default_factory=dict)


def _ws_pattern(text: str) -> re.Pattern:
    return re.compile(r"\s+".join(re.escape(t) for t in text.split()))


def _occurrences(hay: str, needle: str) -> list[int]:
    out, i = [], hay.find(needle)
    while i != -1:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def contextual_spans(masked: Masked, backend: LLMBackend, chunk_chars: int,
                     overlap: int) -> tuple[list[Span], PhaseBStats, set[str]]:
    """Returns (spans in ORIGINAL coordinates, stats, accepted masked strings)."""
    stats = PhaseBStats()
    accepted: dict[str, str] = {}  # masked text -> category
    for off, chunk in chunks(masked.text, chunk_chars, overlap):
        stats.chunks += 1
        for f in backend.find(chunk):
            stats.findings += 1
            if _PLACEHOLDER_ONLY.match(f.text):
                stats.rejected += 1
                continue
            if f.end <= len(chunk) and f.start < f.end and chunk[f.start:f.end] == f.text:
                stats.exact += 1
                found = [f.text]
            elif f.text in chunk:
                stats.relocated += 1
                found = [f.text]
            else:
                # Models normalize whitespace ("Halvorsen Maritime" for a value
                # wrapped across lines): match any run of whitespace instead.
                found = sorted({m.group(0) for m in _ws_pattern(f.text).finditer(chunk)})
                if not found:
                    stats.rejected += 1
                    continue
                stats.relocated += 1
            for text in found:
                accepted.setdefault(text, f.category)
            stats.by_category[f.category] = stats.by_category.get(f.category, 0) + 1

    spans: list[Span] = []
    for text, cat in accepted.items():
        for p in _occurrences(masked.text, text):
            a, b = masked.to_original(p, p + len(text))
            spans.append(Span(a, b, cat, "llm"))
    return spans, stats, set(accepted)
