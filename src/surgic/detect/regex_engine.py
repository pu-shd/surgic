"""Deterministic pattern engine: Hyperscan/Vectorscan prefilter + RE2 spans.

Hyperscan scans the whole document once with every pattern to determine
*which* patterns occur at all; RE2 (linear-time, no catastrophic
backtracking) then produces exact, non-overlapping character spans only for
those patterns. Without Hyperscan, RE2 runs every pattern.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import re2
import yaml

from .spans import Span


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: str
    validator: str | None = None


def luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


VALIDATORS = {"luhn": luhn_ok}


def load_patterns(extra_file: str = "") -> list[Pattern]:
    builtin = yaml.safe_load(resources.files("surgic.data").joinpath("patterns.yaml").read_text())
    by_name = {p["name"]: Pattern(**p) for p in builtin["patterns"]}
    if extra_file:
        extra = yaml.safe_load(Path(extra_file).read_text())
        for p in extra.get("patterns", []):
            by_name[p["name"]] = Pattern(**p)
    for p in by_name.values():
        if p.validator and p.validator not in VALIDATORS:
            raise ValueError(f"unknown validator for pattern {p.name}")
    return list(by_name.values())


class RegexEngine:
    def __init__(self, patterns: list[Pattern], use_hyperscan: bool = True) -> None:
        self.patterns = patterns
        self._re2 = [re2.compile(p.regex) for p in patterns]
        self._hs = None
        if use_hyperscan:
            self._hs = _build_hyperscan(patterns)

    @property
    def hyperscan_active(self) -> bool:
        return self._hs is not None

    def candidate_ids(self, text: str) -> set[int]:
        if self._hs is None:
            return set(range(len(self.patterns)))
        hits: set[int] = set()

        def on_match(pid, _from, _to, _flags, _ctx):
            hits.add(pid)
            return None

        self._hs.scan(text.encode("utf-8"), match_event_handler=on_match)
        return hits

    def find(self, text: str) -> list[Span]:
        out = []
        for pid in sorted(self.candidate_ids(text)):
            p, rx = self.patterns[pid], self._re2[pid]
            check = VALIDATORS.get(p.validator) if p.validator else None
            for m in rx.finditer(text):
                if m.end() <= m.start():
                    continue
                if check and not check(m.group(0)):
                    continue
                out.append(Span(m.start(), m.end(), p.name, "regex"))
        return out


def _build_hyperscan(patterns: list[Pattern]):
    try:
        import hyperscan
    except ImportError:
        return None
    # No HS_FLAG_UCP: \b, \w and \d must stay ASCII exactly as in RE2, otherwise
    # the prefilter could reject text that RE2 would match.
    db = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)
    try:
        db.compile(
            expressions=[p.regex.encode("utf-8") for p in patterns],
            ids=list(range(len(patterns))),
            flags=[hyperscan.HS_FLAG_UTF8 | hyperscan.HS_FLAG_SINGLEMATCH] * len(patterns),
        )
    except hyperscan.error:
        return None  # fall back to running every RE2 pattern
    return db
