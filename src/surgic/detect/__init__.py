"""Phase A: deterministic detection (regex/Hyperscan/RE2 + Presidio)."""
from __future__ import annotations

from typing import Protocol

from .regex_engine import RegexEngine, load_patterns
from .spans import Span, merge


class Finder(Protocol):
    def find(self, text: str) -> list[Span]: ...


class PhaseA:
    def __init__(self, regex: RegexEngine, presidio: Finder | None) -> None:
        self.regex = regex
        self.presidio = presidio

    @classmethod
    def from_config(cls, dcfg, presidio: Finder | None = None) -> "PhaseA":
        regex = RegexEngine(load_patterns(dcfg.patterns_file), use_hyperscan=dcfg.use_hyperscan)
        if presidio is None:
            from .presidio_engine import PresidioEngine
            presidio = PresidioEngine(dcfg.spacy_model, dcfg.spacy_fallback,
                                      dcfg.presidio_entities, dcfg.presidio_score_threshold)
        return cls(regex, presidio)

    def find(self, text: str) -> list[Span]:
        spans = self.regex.find(text)
        if self.presidio is not None:
            spans += self.presidio.find(text)
        return spans


def propagate(text: str, spans: list[Span], min_len: int = 3) -> list[Span]:
    """Add every other exact occurrence of each detected value."""
    out = list(spans)
    seen = set()
    for s in spans:
        val = text[s.start:s.end]
        if len(val.strip()) < min_len or (val, s.category) in seen:
            continue
        seen.add((val, s.category))
        i = text.find(val)
        while i != -1:
            if i != s.start:
                out.append(Span(i, i + len(val), s.category, s.source, s.score))
            i = text.find(val, i + 1)
    return out


__all__ = ["PhaseA", "Span", "merge", "propagate"]
