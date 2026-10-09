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

from ..llm import guard
from ..llm.backend import LLMBackend
from ..logging_safe import SafeError
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
    canaries: int = 0
    canary_misses: int = 0
    by_category: dict[str, int] = field(default_factory=dict)


def _ws_pattern(text: str) -> re.Pattern:
    return re.compile(r"\s+".join(re.escape(t) for t in text.split()))


def _occurrences(hay: str, needle: str) -> list[int]:
    out, i = [], hay.find(needle)
    while i != -1:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def _find_with_canary(chunk: str, backend: LLMBackend, retries: int, stats: PhaseBStats):
    """Ask the model about ``chunk`` with a planted canary. Returns findings
    in chunk coordinates (canary findings removed). Raises if the model keeps
    missing the canary: its view of this chunk cannot be trusted."""
    for _ in range(retries + 1):
        canary = guard.make_canary()
        probe, k, n = guard.insert_canary(chunk, canary)
        stats.canaries += 1
        seen, kept = False, []
        for f in backend.find(probe):
            if canary.marker.lower() in f.text.lower():
                seen = True
                continue
            if f.end <= k:
                kept.append(f)
            elif f.start >= k + n:
                kept.append(f.model_copy(update={"start": f.start - n, "end": f.end - n}))
            elif f.text in canary.sentence:
                continue  # another piece of the canary sentence
            else:
                # Straddles the insertion point: drop the offsets and let the
                # text be relocated in the real chunk (or rejected).
                kept.append(f.model_copy(update={"start": 0, "end": 1}))
        if seen:
            return kept
        stats.canary_misses += 1
    raise SafeError("llm_canary_missed")


def llm_accept(masked_text: str, backend: LLMBackend, chunk_chars: int, overlap: int,
               canaries: bool = True, canary_retries: int = 1) -> tuple[dict[str, str], PhaseBStats]:
    """Run the model over masked text. Returns {accepted masked string: category}.

    Needs only the masked text, so it runs in the orchestrating process and
    never touches a document file."""
    stats = PhaseBStats()
    accepted: dict[str, str] = {}  # masked text -> category
    for off, chunk in chunks(masked_text, chunk_chars, overlap):
        stats.chunks += 1
        found = (_find_with_canary(chunk, backend, canary_retries, stats) if canaries
                 else backend.find(chunk))
        for f in found:
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
                found = sorted({m.group(0) for m in _ws_pattern(f.text).finditer(chunk)} - {""})
                if not found:
                    stats.rejected += 1
                    continue
                stats.relocated += 1
            for text in found:
                if text.strip():
                    accepted.setdefault(text, f.category)
            stats.by_category[f.category] = stats.by_category.get(f.category, 0) + 1
    return accepted, stats


def map_accepted(masked: Masked, accepted: dict[str, str]) -> list[Span]:
    """Spans in ORIGINAL coordinates for every occurrence of each accepted
    masked string. Strings absent from the masked text yield nothing."""
    spans: list[Span] = []
    for text, cat in accepted.items():
        if not text.strip():
            continue
        for p in _occurrences(masked.text, text):
            a, b = masked.to_original(p, p + len(text))
            spans.append(Span(a, b, cat, "llm"))
    return spans


def contextual_spans(masked: Masked, backend: LLMBackend, chunk_chars: int, overlap: int,
                     canaries: bool = True) -> tuple[list[Span], PhaseBStats, set[str]]:
    """Returns (spans in ORIGINAL coordinates, stats, accepted masked strings)."""
    accepted, stats = llm_accept(masked.text, backend, chunk_chars, overlap, canaries=canaries)
    return map_accepted(masked, accepted), stats, set(accepted)
