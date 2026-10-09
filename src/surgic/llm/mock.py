"""Deterministic in-process backend for tests and dry runs (never production).

It flags every occurrence of the terms listed in SURGIC_MOCK_TERMS
(``category=term;category=term``), with deliberately loose offsets so the
validation/relocation path is exercised, and (like a working model) the
synthetic canary organizations the pipeline plants. ``flag_canaries=False``
simulates a model that has been steered into reporting nothing.
"""
from __future__ import annotations

import json
import os
import re

from .backend import LLMBackend
from .guard import CANARY_RE


class MockBackend(LLMBackend):
    name = "mock"

    def __init__(self, cfg, terms: list[tuple[str, str]] | None = None, flag_canaries: bool = True) -> None:
        super().__init__(cfg)
        if terms is None:
            terms = []
            for item in filter(None, os.environ.get("SURGIC_MOCK_TERMS", "").split(";")):
                cat, _, term = item.partition("=")
                terms.append((cat, term))
        self.terms = terms
        self.flag_canaries = flag_canaries
        self.loaded = False
        self.requests = 0

    def start(self) -> None:
        self.loaded = True

    def is_loaded(self) -> bool:
        return self.loaded

    def complete_json(self, system: str, user: str) -> str:
        assert self.loaded, "mock backend used while unloaded"
        self.requests += 1
        m = re.search(r"<<<DATA (\w+) length=\d+>>>\n(.*)\n<<<END \1>>>\Z", user, re.S)
        chunk = m.group(2) if m else ""
        findings = []
        for cat, term in self.terms:
            # Like real models: match across line wraps but report the term with
            # normal spacing, and with a deliberately wrong (off-by-two) start.
            pattern = r"\s+".join(re.escape(t) for t in term.split())
            for mm in re.finditer(pattern, chunk):
                findings.append({"start": max(mm.start() - 2, 0), "end": mm.end(), "text": term,
                                 "category": cat, "rationale_code": "NAMED_ENTITY_IN_CONTEXT"})
        if self.flag_canaries:
            for mm in CANARY_RE.finditer(chunk):
                findings.append({"start": mm.start(), "end": mm.end(), "text": mm.group(0),
                                 "category": "VENDOR_RELATIONSHIP", "rationale_code": "CONTRACT_COUNTERPARTY"})
        return json.dumps({"findings": findings})

    def reset_context(self) -> None:
        self.reset_count += 1

    def unload(self) -> None:
        if self.loaded:
            self.loaded = False
            self.unload_count += 1
