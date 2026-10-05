"""Deterministic in-process backend for tests and dry runs (never production).

It flags every occurrence of the terms listed in SURGIC_MOCK_TERMS
(``category=term;category=term``), with deliberately loose offsets so the
validation/relocation path is exercised.
"""
from __future__ import annotations

import json
import os
import re

from .backend import LLMBackend


class MockBackend(LLMBackend):
    name = "mock"

    def __init__(self, cfg, terms: list[tuple[str, str]] | None = None) -> None:
        super().__init__(cfg)
        if terms is None:
            terms = []
            for item in filter(None, os.environ.get("SURGIC_MOCK_TERMS", "").split(";")):
                cat, _, term = item.partition("=")
                terms.append((cat, term))
        self.terms = terms
        self.loaded = False
        self.requests = 0

    def start(self) -> None:
        self.loaded = True

    def is_loaded(self) -> bool:
        return self.loaded

    def complete_json(self, system: str, user: str) -> str:
        assert self.loaded, "mock backend used while unloaded"
        self.requests += 1
        m = re.search(r"<chunk length=\"\d+\">\n(.*)\n</chunk>\Z", user, re.S)
        chunk = m.group(1) if m else ""
        findings = []
        for cat, term in self.terms:
            # Like real models: match across line wraps but report the term with
            # normal spacing, and with a deliberately wrong (off-by-two) start.
            pattern = r"\s+".join(re.escape(t) for t in term.split())
            for mm in re.finditer(pattern, chunk):
                findings.append({"start": max(mm.start() - 2, 0), "end": mm.end(), "text": term,
                                 "category": cat, "rationale_code": "NAMED_ENTITY_IN_CONTEXT"})
        return json.dumps({"findings": findings})

    def reset_context(self) -> None:
        self.reset_count += 1

    def unload(self) -> None:
        if self.loaded:
            self.loaded = False
            self.unload_count += 1
