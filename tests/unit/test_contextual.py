from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from surgic.config import LLMConfig
from surgic.detect.contextual import contextual_spans
from surgic.detect.mask import build
from surgic.detect.spans import Span
from surgic.llm.backend import LLMBackend
from surgic.llm.chunker import chunks
from surgic.llm.schema import json_schema
from surgic.logging_safe import SafeError


class ScriptedBackend(LLMBackend):
    name = "scripted"

    def __init__(self, responses):
        super().__init__(LLMConfig(backend="mock", max_retries=1))
        self.responses = list(responses)
        self.calls = 0

    def start(self): pass
    def is_loaded(self): return True
    def reset_context(self): pass
    def unload(self): pass

    def complete_json(self, system, user):
        self.calls += 1
        r = self.responses.pop(0) if self.responses else {"findings": []}
        return r if isinstance(r, str) else json.dumps(r)


def F(start, end, text, cat="CLIENT_RELATIONSHIP"):
    return {"start": start, "end": end, "text": text, "category": cat, "rationale_code": "CONTRACT_COUNTERPARTY"}


TEXT = "We supply Halvorsen Maritime. Later, Halvorsen Maritime renewed. SSN 219-09-9999."


def run(responses, text=TEXT, spans=()):
    m = build(text, list(spans))
    b = ScriptedBackend(responses)
    out, stats, accepted = contextual_spans(m, b, 10_000, 100)
    return out, stats, b


def test_exact_offsets_accepted_and_propagated():
    i = TEXT.index("Halvorsen")
    out, stats, _ = run([{"findings": [F(i, i + 18, "Halvorsen Maritime")]}])
    assert stats.exact == 1 and stats.rejected == 0
    assert sorted((s.start, s.end) for s in out) == [
        (i, i + 18), (TEXT.index("Halvorsen", i + 1), TEXT.index("Halvorsen", i + 1) + 18)]
    assert all(TEXT[s.start:s.end] == "Halvorsen Maritime" for s in out)


def test_wrong_offsets_relocated():
    out, stats, _ = run([{"findings": [F(0, 5, "Halvorsen Maritime")]}])
    assert stats.relocated == 1 and len(out) == 2


def test_fabricated_text_rejected():
    out, stats, _ = run([{"findings": [F(0, 5, "Nonexistent Corp")]}])
    assert stats.rejected == 1 and out == []


def test_placeholder_only_rejected_and_mapping_through_mask():
    s0 = TEXT.index("219")
    spans = [Span(s0, s0 + 11, "US_SSN", "regex")]
    m = build(TEXT, spans)
    assert "[US_SSN_1]" in m.text
    out, stats, _ = run([{"findings": [F(0, 1, "[US_SSN_1]"), F(0, 1, "SSN [US_SSN_1]", "PERSON_CONTEXTUAL")]}],
                        spans=spans)
    assert stats.rejected == 1
    # "SSN [US_SSN_1]" maps back to "SSN 219-09-9999" in original coordinates.
    assert [TEXT[s.start:s.end] for s in out] == ["SSN 219-09-9999"]


def test_invalid_json_retries_then_fails_closed():
    with pytest.raises(SafeError) as e:
        run(["not json", '{"findings": [{"start": 1}]}'])
    assert e.value.code == "llm_output_invalid"


def test_invalid_then_valid_recovers():
    out, stats, b = run(["{oops", {"findings": []}])
    assert b.calls == 2 and out == [] and stats.chunks == 1


def test_extra_fields_rejected_by_schema():
    with pytest.raises(SafeError):
        run([{"findings": [], "explanation": "leak"}, {"findings": [], "x": 1}])


def test_unknown_category_rejected():
    bad = F(0, 1, "We", "MADE_UP")
    with pytest.raises(SafeError):
        run([{"findings": [bad]}, {"findings": [bad]}])


def test_json_schema_inlined_and_strict():
    s = json_schema()
    item = s["properties"]["findings"]["items"]
    assert item["additionalProperties"] is False
    assert set(item["required"]) == {"start", "end", "text", "category", "rationale_code"}
    assert "$defs" not in s


@settings(max_examples=200, deadline=None)
@given(st.text(min_size=1, max_size=400), st.integers(10, 120), st.integers(0, 60))
def test_chunks_cover_all_text(text, size, overlap):
    cs = chunks(text, size, overlap)
    covered = set()
    for off, c in cs:
        assert text[off:off + len(c)] == c
        covered.update(range(off, off + len(c)))
    assert covered == set(range(len(text)))
    offs = [o for o, _ in cs]
    assert offs == sorted(set(offs))


def test_chunk_size_validation():
    with pytest.raises(ValueError):
        chunks("abc", 0, 0)
