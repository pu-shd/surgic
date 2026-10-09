"""The Promptfoo red-team harness (redteam/) works without Node or a model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CASES = yaml.safe_load((ROOT / "redteam" / "cases.yaml").read_text())


def provider():
    spec = importlib.util.spec_from_file_location("rt_provider", ROOT / "redteam" / "provider.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def outcome(mod, case, mode, backend):
    r = mod.call_api(case["vars"]["chunk"], {"config": {"mode": mode, "backend": backend}},
                     {"vars": case["vars"]})
    assert "error" not in r, r
    return json.loads(r["output"])["outcome"]


def test_catalog_is_well_formed():
    assert len(CASES) >= 20 and CASES[0]["description"].startswith("control")
    for c in CASES:
        assert c["vars"]["secret"] in c["vars"]["chunk"], c["description"]
    assert len({c["description"] for c in CASES}) == len(CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["description"] for c in CASES])
def test_working_model_flags_every_case(case):
    mod = provider()
    assert outcome(mod, case, "model", "mock") == "flagged"
    assert outcome(mod, case, "defended", "mock") in ("flagged", "quarantined_tripwire")


@pytest.mark.parametrize("case", CASES, ids=[c["description"] for c in CASES])
def test_fully_steered_model_is_contained(case):
    """A model that reports nothing misses every secret on its own; the
    runtime defenses still hold back every document."""
    mod = provider()
    assert outcome(mod, case, "model", "steered") == "missed"
    assert outcome(mod, case, "defended", "steered") in ("quarantined_tripwire", "quarantined_canary")


def test_summary_gate_fails_on_a_defended_miss(tmp_path):
    spec = importlib.util.spec_from_file_location("rt_sum", ROOT / "redteam" / "summarize.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def row(label, outcome):
        return {"success": outcome != "missed", "provider": {"label": label},
                "response": {"output": json.dumps({"outcome": outcome})}, "testCase": {"description": "x"}}
    good = tmp_path / "g.json"
    good.write_text(json.dumps({"results": {"results": [row("model-only", "missed"),
                                                        row("defended-pipeline", "quarantined_canary")]}}))
    assert mod.main(str(good), 1) == 0  # model-only misses are measured, not gated
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"results": {"results": [row("defended-pipeline", "missed")]}}))
    assert mod.main(str(bad), 1) == 1
    empty = tmp_path / "e.json"
    empty.write_text("{}")
    assert mod.main(str(empty), 1) == 1  # silence is not success
