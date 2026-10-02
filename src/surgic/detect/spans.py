"""Span model and merging."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class Span:
    start: int
    end: int
    category: str
    source: str            # "regex" | "presidio" | "llm"
    score: float = 1.0

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("invalid span")


def merge(spans: list[Span]) -> list[Span]:
    """Union overlapping/adjacent spans. The merged category is the one from
    the longest contributing span (ties: deterministic sources first)."""
    if not spans:
        return []
    prio = {"regex": 0, "presidio": 1, "llm": 2}
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    out: list[Span] = []
    cur = ordered[0]
    best = cur
    for s in ordered[1:]:
        if s.start <= cur.end:
            if (s.end - s.start, -prio.get(s.source, 9)) > (best.end - best.start, -prio.get(best.source, 9)):
                best = s
            cur = Span(cur.start, max(cur.end, s.end), best.category, best.source, max(cur.score, s.score))
        else:
            out.append(Span(cur.start, cur.end, best.category, best.source, cur.score))
            cur, best = s, s
    out.append(Span(cur.start, cur.end, best.category, best.source, cur.score))
    return out


def apply_to_text(text: str, spans: list[Span], fmt: str = "[REDACTED:{cat}]") -> str:
    out, pos = [], 0
    for s in merge(spans):
        out.append(text[pos:s.start])
        out.append(fmt.format(cat=s.category))
        pos = s.end
    out.append(text[pos:])
    return "".join(out)
