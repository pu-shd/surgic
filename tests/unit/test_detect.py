from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fixtures.make import PARAGRAPH, STRUCTURED
from surgic.detect import propagate
from surgic.detect.mask import build
from surgic.detect.regex_engine import Pattern, RegexEngine, load_patterns, luhn_ok
from surgic.detect.spans import Span, apply_to_text, merge

EXPECTED_REGEX = {
    "ssn": "US_SSN", "email": "EMAIL_ADDRESS", "phone": "PHONE_NUMBER", "card": "CREDIT_CARD",
    "ip": "IP_ADDRESS", "emp": "EMPLOYEE_ID", "marker": "CLASSIFICATION_MARKER",
    "codename": "PROJECT_CODENAME", "dcn": "DOC_CONTROL_NUMBER", "aws": "AWS_ACCESS_KEY",
}


@pytest.fixture(scope="module", params=[True, False], ids=["hyperscan", "re2_only"])
def engine(request):
    e = RegexEngine(load_patterns(), use_hyperscan=request.param)
    assert e.hyperscan_active is request.param
    return e


@pytest.mark.parametrize("key", sorted(EXPECTED_REGEX))
def test_each_structured_value_detected_exactly(engine, key):
    value = STRUCTURED[key]
    spans = engine.find(PARAGRAPH)
    start = PARAGRAPH.index(value)
    hits = [s for s in spans if s.category == EXPECTED_REGEX[key]]
    assert hits, f"{key} not detected"
    assert any(s.start <= start and s.end >= start + len(value) for s in hits)


def test_luhn():
    assert luhn_ok("4111 1111 1111 1111")
    assert not luhn_ok("4111 1111 1111 1112")
    assert not luhn_ok("1234")


def test_card_validator_rejects_non_luhn(engine):
    assert not [s for s in engine.find("number 4111 1111 1111 1112 here") if s.category == "CREDIT_CARD"]


def test_extra_patterns_file_overrides(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("patterns:\n  - name: EMPLOYEE_ID\n    regex: '\\bZZ\\d{3}\\b'\n  - name: BADGE\n    regex: '\\bBDG\\d{4}\\b'\n")
    pats = {p.name: p for p in load_patterns(str(f))}
    assert pats["EMPLOYEE_ID"].regex == r"\bZZ\d{3}\b"
    e = RegexEngine(list(pats.values()))
    cats = {s.category for s in e.find("ZZ123 and BDG9876")}
    assert {"EMPLOYEE_ID", "BADGE"} <= cats


def test_unknown_validator_rejected(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("patterns:\n  - name: X\n    regex: 'x'\n    validator: nope\n")
    with pytest.raises(ValueError):
        load_patterns(str(f))


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("0123456789-. ()@abcXYZéñ日AKIA/") + ["\n"]), max_size=80))
def test_hyperscan_prefilter_never_drops_re2_matches(text):
    pats = load_patterns()
    full = RegexEngine(pats, use_hyperscan=False)
    hs = RegexEngine(pats, use_hyperscan=True)
    assert hs.hyperscan_active
    assert set(full.find(text)) == set(hs.find(text))


def test_presidio_finds_person(presidio_engine):
    spans = presidio_engine.find("Prepared by Margaret Thornbury of the finance office.")
    assert any(s.category == "PERSON" and "Thornbury" in
               "Prepared by Margaret Thornbury of the finance office."[s.start:s.end] for s in spans)


def test_merge_overlaps_and_category():
    m = merge([Span(0, 5, "A", "regex"), Span(3, 10, "B", "llm"), Span(20, 25, "C", "presidio")])
    assert [(s.start, s.end) for s in m] == [(0, 10), (20, 25)]
    assert m[0].category == "B"  # longest contributor


def test_span_validation():
    with pytest.raises(ValueError):
        Span(5, 5, "X", "regex")


def test_apply_to_text():
    assert apply_to_text("abc SECRET def", [Span(4, 10, "M", "regex")]) == "abc [REDACTED:M] def"


def test_propagate_finds_all_occurrences():
    text = "Acme paid Acme. acme lower"
    out = propagate(text, [Span(0, 4, "ORG", "llm")])
    assert sorted((s.start, s.end) for s in out) == [(0, 4), (10, 14)]


def test_mask_placeholders_consistent_and_mapped():
    text = "SSN 219-09-9999 again 219-09-9999 end"
    spans = [Span(4, 15, "US_SSN", "regex"), Span(22, 33, "US_SSN", "regex")]
    m = build(text, spans)
    assert m.text == "SSN [US_SSN_1] again [US_SSN_1] end"
    assert "219" not in m.text
    i = m.text.index("again")
    assert m.to_original(i, i + 5) == (text.index("again"), text.index("again") + 5)
    # Touching part of a placeholder covers the whole original value.
    assert m.to_original(5, 7) == (4, 15)


@settings(max_examples=200, deadline=None)
@given(st.text(min_size=1, max_size=60), st.lists(st.tuples(st.integers(0, 59), st.integers(1, 10)), max_size=6))
def test_mask_roundtrip_property(text, raw):
    spans = [Span(a, min(a + l, len(text)), "X", "regex") for a, l in raw if a < len(text) and a + 1 <= len(text)]
    spans = [s for s in spans if s.end > s.start]
    m = build(text, spans)
    for p in m.pieces:
        if not p.placeholder:
            assert m.text[p.m_start:p.m_end] == text[p.o_start:p.o_end]
    # Unmasked text round-trips exactly through the offset map.
    for p in m.pieces:
        if not p.placeholder and p.m_end > p.m_start:
            a, b = m.to_original(p.m_start, p.m_end)
            assert text[a:b] == m.text[p.m_start:p.m_end]
    # No original sensitive char survives in masked text positions mapped from spans.
    covered = set()
    for s in merge(spans):
        covered.update(range(s.start, s.end))
    unmasked_orig = set()
    for p in m.pieces:
        if not p.placeholder:
            unmasked_orig.update(range(p.o_start, p.o_end))
    assert not (covered & unmasked_orig)


def test_pattern_dataclass_frozen():
    p = Pattern("A", "a")
    with pytest.raises(Exception):
        p.name = "B"


def test_example_config_loads():
    from pathlib import Path
    from surgic.config import Config
    p = Path(__file__).resolve().parents[2] / "config" / "surgic.example.toml"
    cfg = Config.load(p)
    assert cfg.network.smb_share_ip == "10.0.0.5" and cfg.llm.batch_size == 1
    assert len(cfg.source_sha256) == 64
    assert not cfg.storage.input_mount.startswith("~")
