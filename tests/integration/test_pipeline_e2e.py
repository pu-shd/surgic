from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pymupdf
import pytest

from fixtures import make
from surgic.audit.postscan import pdf_raw_text
from surgic.audit.signing import Signer
from surgic.audit.verify import verify_file
from surgic.config import AuditConfig, Config, LLMConfig, NetworkConfig
from surgic.llm.mock import MockBackend
from surgic.logging_safe import SafeError
from surgic.pipeline import Pipeline


def make_cfg(batch_size=1):
    return Config(network=NetworkConfig(smb_share_ip="10.0.0.5"),
                  llm=LLMConfig(backend="mock", batch_size=batch_size),
                  audit=AuditConfig(require_secret_scanners=False))


def terms():
    return [tuple(t.split("=", 1)) for t in make.MOCK_TERMS.split(";")]


@pytest.fixture
def corpus(tmp_path):
    from surgic.extract.convert import find_soffice
    make.make_corpus(tmp_path / "in", include_docx=find_soffice() is not None)
    (tmp_path / "out").mkdir()
    (tmp_path / "ws").mkdir()
    return tmp_path


def run_pipeline(corpus, phase_a, ocr, key_store, scanners, batch_size=1, backend=None):
    cfg = make_cfg(batch_size)
    backend = backend or MockBackend(cfg.llm, terms=terms())
    p = Pipeline(cfg, backend, phase_a, ocr, scanners, Signer(key_store), "f" * 64, {"preflight": "TEST"})
    mpath, manifest = p.run(str(corpus / "in"), str(corpus / "out"), str(corpus / "ws"))
    return p, backend, mpath, manifest


def output_texts(out: Path) -> dict[str, str]:
    texts = {}
    for f in out.rglob("*"):
        if not f.is_file() or "manifests" in f.parts:
            continue
        if f.suffix == ".pdf":
            pdf = pymupdf.open(f)
            texts[str(f)] = "\n".join(p.get_text() for p in pdf) + pdf_raw_text(str(f))
        elif f.suffix == ".xlsx":
            with zipfile.ZipFile(f) as z:
                texts[str(f)] = "\n".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())
        else:
            texts[str(f)] = f.read_text(encoding="utf-8", errors="replace")
    return texts


def test_end_to_end_corpus(corpus, phase_a, ocr, key_store, fake_scanners):
    p, backend, mpath, man = run_pipeline(corpus, phase_a, ocr, key_store, fake_scanners)
    docs = {d["doc_id"]: d for d in man["documents"]}
    by_status = {}
    for d in docs.values():
        by_status.setdefault(d["status"], []).append(d)
    n_supported = len([f for f in (corpus / "in").iterdir() if f.suffix != ".zip"])
    assert man["summary"]["total"] == n_supported + 1
    assert len(by_status["skipped"]) == 1 and by_status["skipped"][0]["reason"] == "unsupported_extension"
    quarantined = by_status.get("quarantined", [])
    assert [d["reason"] for d in quarantined] == ["pdf_open_failed"], quarantined
    assert len(by_status["clean"]) == n_supported - 1
    for d in by_status["clean"]:
        assert d["postscan"]["passed"] and d["regions"] > 0 and d["outputs"]
        assert d["token_hmacs"] and all(len(h) == 64 for h in d["token_hmacs"])
        assert any(k.startswith("llm:") for k in d["phase_a"]) is False
        assert d["phase_b"]["chunks"] >= 1
    # Isolation: one unload per batch (batch_size=1 -> per supported document), reset per doc.
    assert backend.unload_count == n_supported and backend.reset_count == n_supported
    assert man["llm"]["unloads"] == n_supported
    assert not backend.is_loaded()
    # Nothing left in the workspace; quarantined docs have no output dir.
    assert list((corpus / "ws").iterdir()) == []
    for d in quarantined:
        assert not (corpus / "out" / d["doc_id"]).exists()
    # Signed manifest verifies against outputs, and contains no sensitive values.
    pem = (corpus / "out" / "manifests" / "pubkey.pem").read_bytes()
    assert verify_file(mpath, pem, str(corpus / "out")) == []
    raw_manifest = Path(mpath).read_text()
    for v in make.ALL_VALUES + ["memo.pdf", "payroll.xlsx"]:
        assert v not in raw_manifest
    # No planted value anywhere in the released outputs.
    texts = output_texts(corpus / "out")
    assert len(texts) >= 2 * (n_supported - 1) - 1
    leaks = {(Path(f).name, v) for f, t in texts.items() for v in make.MUST_NOT_LEAK if v in t}
    assert not leaks, sorted(leaks)


def test_batching_unloads_per_batch(corpus, regex_only, ocr, key_store):
    for f in ("scan.pdf", "whiteboard.png", "letter.docx"):
        (corpus / "in" / f).unlink(missing_ok=True)
    _, backend, _, man = run_pipeline(corpus, regex_only, ocr, key_store, None, batch_size=2)
    supported = man["summary"]["clean"] + man["summary"]["quarantined"]
    assert supported == 4
    assert backend.unload_count == 2 and backend.reset_count == 4


class FailingUnload(MockBackend):
    def unload(self):
        from surgic.logging_safe import SafeError
        raise SafeError("llm_unload_unverified", backend="mock")


def test_unverified_unload_aborts_run(corpus, regex_only, ocr, key_store):
    cfg = make_cfg()
    with pytest.raises(SafeError) as e:
        run_pipeline(corpus, regex_only, ocr, key_store, None, backend=FailingUnload(cfg.llm, terms=terms()))
    assert e.value.code == "llm_unload_unverified"
    assert not (corpus / "out" / "manifests").exists()


class LeakyRender:
    """Simulate a renderer bug: write the source text unredacted."""

    def __init__(self):
        from surgic import redact
        self.orig = redact.render

    def __call__(self, doc, spans, out_dir, stem):
        res = self.orig(doc, [], out_dir, stem)
        res.regions = max(res.regions, 1)
        return res


def test_renderer_bug_is_quarantined_not_released(corpus, regex_only, ocr, key_store, monkeypatch):
    import surgic.pipeline as pl
    monkeypatch.setattr(pl, "render", LeakyRender())
    _, _, mpath, man = run_pipeline(corpus, regex_only, ocr, key_store, None)
    released = [d for d in man["documents"] if d["status"] == "clean"]
    assert released == []
    q = [d for d in man["documents"] if d["status"] == "quarantined" and d["reason"] == "postscan_failed"]
    assert len(q) >= 4
    for d in q:
        assert d["postscan"]["passed"] is False
        assert 0 <= d["rescans"] <= 2
        assert not (corpus / "out" / d["doc_id"]).exists()


def test_cli_run_and_verify(corpus, tmp_path, monkeypatch, capsys, key_store):
    from surgic import cli
    cfgf = tmp_path / "c.toml"
    cfgf.write_text('[network]\nsmb_share_ip = "10.0.0.5"\n[llm]\nbackend = "mock"\n'
                    '[audit]\nrequire_secret_scanners = false\n[detect]\nspacy_model = "en_core_web_sm"\n')
    for f in ("scan.pdf", "whiteboard.png", "letter.docx", "corrupt.pdf"):
        (corpus / "in" / f).unlink(missing_ok=True)
    monkeypatch.setenv("SURGIC_KEY_FILE", key_store.path.as_posix())
    monkeypatch.setenv("SURGIC_MOCK_TERMS", make.MOCK_TERMS)
    monkeypatch.setenv("SURGIC_ALLOW_NO_PREFLIGHT", "1")
    rc = cli.main(["run", "-c", str(cfgf), "--input", str(corpus / "in"), "--output", str(corpus / "out"),
                   "--workspace", str(corpus / "ws"), "--skip-preflight", "--ocr", "auto"])
    out = capsys.readouterr().out.strip().splitlines()[-1]
    res = json.loads(out)
    assert rc == 0 and res["clean"] == 3 and res["quarantined"] == 0
    pub = corpus / "out" / "manifests" / "pubkey.pem"
    assert cli.main(["verify", res["manifest"], "--pubkey", str(pub), "--outputs", str(corpus / "out")]) == 0
    assert "VERIFIED" in capsys.readouterr().out


def test_cli_refuses_skip_preflight_without_opt_in(tmp_path, monkeypatch, capsys):
    from surgic import cli
    cfgf = tmp_path / "c.toml"
    cfgf.write_text('[network]\nsmb_share_ip = "10.0.0.5"\n[llm]\nbackend = "mock"\n')
    monkeypatch.delenv("SURGIC_ALLOW_NO_PREFLIGHT", raising=False)
    rc = cli.main(["run", "-c", str(cfgf), "--skip-preflight"])
    assert rc == 2 and "preflight_skip_not_allowed" in capsys.readouterr().err


def test_record_paths_off_by_default(corpus, regex_only, ocr, key_store):
    _, _, mpath, man = run_pipeline(corpus, regex_only, ocr, key_store, None)
    assert all("input_path" not in d for d in man["documents"])
    assert os.path.basename(mpath).endswith(".manifest.json")
