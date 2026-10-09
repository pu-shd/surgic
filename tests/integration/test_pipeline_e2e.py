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


# Failures a test run is expected to produce (it is not a production run);
# anything else - especially about outputs - is a real failure.
NON_PRODUCTION = ("weakened_control:", "non_production_backend", "preflight_", "closure_not_provided",
                  "model_not_expected")


def output_failures(fails):
    return [f for f in fails if not f.startswith(NON_PRODUCTION)]


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
    run_dir = corpus / "out" / man["run_id"]
    for d in quarantined:
        assert not (run_dir / d["doc_id"]).exists()
    assert man["security"]["isolation"] == "inprocess" and man["aborted"] == ""
    # Signed manifest's outputs verify; it is (correctly) not a production run.
    pem = (corpus / "out" / "manifests" / "pubkey.pem").read_bytes()
    fails = verify_file(mpath, pem, str(corpus / "out"))
    assert output_failures(fails) == [], fails
    assert "weakened_control:isolation" in fails and "non_production_backend" in fails
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
    # Nothing was released, and a signed manifest records the abort.
    released = [p for p in (corpus / "out").iterdir() if p.name != "manifests"]
    assert released == []
    [mpath] = (corpus / "out" / "manifests").glob("*.manifest.json")
    man = json.loads(mpath.read_text())
    assert man["aborted"] == "llm_unload_unverified"
    assert all(d["status"] != "clean" and not d["outputs"] for d in man["documents"])
    pem = (corpus / "out" / "manifests" / "pubkey.pem").read_bytes()
    assert "run_aborted:llm_unload_unverified" in verify_file(str(mpath), pem, str(corpus / "out"))


def test_in_process_egress_attempt_releases_nothing(corpus, regex_only, ocr, key_store, monkeypatch):
    from surgic import netguard
    monkeypatch.setattr(netguard, "attempts", ["connect"])
    with pytest.raises(SafeError) as e:
        run_pipeline(corpus, regex_only, ocr, key_store, None)
    assert e.value.code == "in_process_egress_attempted"
    assert [p.name for p in (corpus / "out").iterdir()] == ["manifests"]


def test_hidden_files_and_symlinks_are_recorded(corpus, regex_only, ocr, key_store):
    import os as _os
    (corpus / "in" / ".hidden.txt").write_text("SSN 219-09-9999")
    (corpus / "in" / ".snapshot").mkdir()
    (corpus / "in" / ".snapshot" / "old.txt").write_text("x")
    _os.symlink(corpus / "in" / "notes.txt", corpus / "in" / "link.txt")
    _, _, _, man = run_pipeline(corpus, regex_only, ocr, key_store, None)
    reasons = sorted(d["reason"] for d in man["documents"] if d["status"] == "skipped")
    assert reasons.count("hidden_file") == 1 and reasons.count("hidden_dir") == 1
    assert reasons.count("symlink") == 1


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
    import surgic.redact as rd
    monkeypatch.setattr(rd, "render", LeakyRender())
    _, _, mpath, man = run_pipeline(corpus, regex_only, ocr, key_store, None)
    released = [d for d in man["documents"] if d["status"] == "clean"]
    assert released == []
    q = [d for d in man["documents"] if d["status"] == "quarantined" and d["reason"] == "postscan_failed"]
    assert len(q) >= 4
    for d in q:
        assert d["postscan"]["passed"] is False
        assert 0 <= d["rescans"] <= 2
        assert not (corpus / "out" / man["run_id"] / d["doc_id"]).exists()


def test_cli_run_and_verify(corpus, tmp_path, monkeypatch, capsys, key_store):
    """Full CLI run with real worker processes (unsandboxed "process" mode,
    which also runs on Linux CI)."""
    from surgic import cli
    cfgf = tmp_path / "c.toml"
    cfgf.write_text('[network]\nsmb_share_ip = "10.0.0.5"\n[llm]\nbackend = "mock"\n'
                    '[audit]\nrequire_secret_scanners = false\n[detect]\nspacy_model = "en_core_web_sm"\n'
                    '[isolation]\nmode = "process"\n')
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
    man = json.loads(open(res["manifest"]).read())
    assert man["security"]["isolation"] == "process"
    pub = corpus / "out" / "manifests" / "pubkey.pem"
    # A mock, unsandboxed, preflight-skipped run must never verify...
    assert cli.main(["verify", res["manifest"], "--pubkey", str(pub), "--outputs", str(corpus / "out")]) == 1
    lines = capsys.readouterr().out.splitlines()
    fails = [ln.removeprefix("FAIL ") for ln in lines if ln.startswith("FAIL ")]
    for f in ("preflight_not_run", "non_production_backend", "weakened_control:isolation", "closure_not_provided"):
        assert f in fails
    # ...but everything it released matches the manifest.
    assert output_failures(fails) == [], fails


def test_cli_refuses_skip_preflight_without_opt_in(tmp_path, monkeypatch, capsys):
    from surgic import cli
    cfgf = tmp_path / "c.toml"
    cfgf.write_text('[network]\nsmb_share_ip = "10.0.0.5"\n[llm]\nbackend = "mock"\n')
    monkeypatch.delenv("SURGIC_ALLOW_NO_PREFLIGHT", raising=False)
    rc = cli.main(["run", "-c", str(cfgf), "--skip-preflight"])
    assert rc == 2 and "preflight_skip_not_allowed" in capsys.readouterr().err


def test_cli_unexpected_error_is_content_free(tmp_path, capsys):
    from surgic import cli
    cfgf = tmp_path / "Margaret Thornbury salary.toml"
    cfgf.write_text("not = [valid toml")
    assert cli.main(["preflight", "-c", str(cfgf)]) == 2
    err = capsys.readouterr().err
    assert "Thornbury" not in err and err.startswith("error: unexpected")


def test_record_paths_off_by_default(corpus, regex_only, ocr, key_store):
    _, _, mpath, man = run_pipeline(corpus, regex_only, ocr, key_store, None)
    assert all("input_path" not in d for d in man["documents"])
    assert os.path.basename(mpath).endswith(".manifest.json")


# ---------------------------------------------------------------- output naming
def _named_run(tmp_path, regex_only, key_store, files: dict[str, str], analyzer=None):
    from surgic.worker import DocWorker, InProcessClient, ScanWorker
    cfg = make_cfg()
    cfg.storage.output_names = "original"
    for rel, text in files.items():
        p = tmp_path / "in" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (tmp_path / "out").mkdir()
    a = InProcessClient(DocWorker(cfg, regex_only, None))
    p = Pipeline(cfg, MockBackend(cfg.llm, terms=terms()), signer=Signer(key_store), model_sha256="f" * 64,
                 analyzer=analyzer(a) if analyzer else a, scanner=InProcessClient(ScanWorker(regex_only, None, None)))
    mpath, man = p.run(str(tmp_path / "in"), str(tmp_path / "out"), str(tmp_path / "ws"))
    run_dir = tmp_path / "out" / man["run_id"]
    released = sorted(f.relative_to(run_dir).as_posix() for f in run_dir.rglob("*") if f.is_file())
    return mpath, man, released


def test_original_names_keep_tree_and_redact_names(tmp_path, regex_only, key_store):
    body = "Our supplier Halvorsen Maritime renewal; SSN 219-09-9999.\n"
    mpath, man, released = _named_run(tmp_path, regex_only, key_store, {
        "Clients/Halvorsen Maritime/renewal memo.txt": body,   # folder named after a redacted value
        "HR/SSN 219-09-9999 review.txt": body,                 # structured value in the file name
        "notes.txt": "Quarterly notes, nothing sensitive.\n",
    })
    assert man["summary"]["clean"] == 3 and man["security"]["output_names"] == "original"
    assert released == [
        "Clients/REDACTED_VALUE/renewal memo.txt.redacted.txt",
        "HR/SSN REDACTED_US_SSN review.txt.redacted.txt",
        "notes.txt.redacted.txt",
    ], released
    for d in man["documents"]:
        assert d["name_mode"] == "original"
    raw = Path(mpath).read_text()
    assert "Halvorsen" not in raw and "219-09-9999" not in raw
    pem = (tmp_path / "out" / "manifests" / "pubkey.pem").read_bytes()
    fails = verify_file(mpath, pem, str(tmp_path / "out"))
    assert output_failures(fails) == [], fails
    assert "original_names_released" in verify_file(mpath, pem, str(tmp_path / "out"), require_opaque_names=True)
    # A file slipped into the released tree is caught.
    (tmp_path / "out" / man["run_id"] / "HR" / "planted.txt").write_text("x")
    assert "unlisted_output:HR/planted.txt" in verify_file(mpath, pem, str(tmp_path / "out"))


def test_original_names_collision_falls_back_to_opaque(tmp_path, regex_only, key_store):
    _, man, released = _named_run(tmp_path, regex_only, key_store, {
        "a 219-09-9999.txt": "first\n", "a 219-09-8888.txt": "second\n"})
    modes = sorted(d["name_mode"] for d in man["documents"])
    assert modes == ["opaque_fallback", "original"]
    fallback = next(d for d in man["documents"] if d["name_mode"] == "opaque_fallback")
    assert f"{fallback['doc_id']}/{fallback['doc_id']}.redacted.txt" in released
    assert "a REDACTED_US_SSN.txt.redacted.txt" in released


def test_unsafe_name_from_worker_falls_back_to_opaque(tmp_path, regex_only, key_store):
    """A (compromised) analyzer that leaves a redacted value in the name."""
    class Leaky:
        def __init__(self, inner):
            self.inner, self.isolation = inner, inner.isolation

        def start(self, w):
            self.inner.start(w)

        def stop(self):
            self.inner.stop()

        def restart(self):
            pass

        def call(self, op, **args):
            if op == "redact_name":
                return {"name": args["text"], "redactions": 0}
            return self.inner.call(op, **args)

    _, man, released = _named_run(tmp_path, regex_only, key_store,
                                  {"SSN 219-09-9999.txt": "SSN 219-09-9999\n"}, analyzer=Leaky)
    [d] = man["documents"]
    assert d["name_mode"] == "opaque_fallback" and not any("219-09" in r for r in released)


def test_verifier_rejects_output_path_traversal(tmp_path, key_store):
    from fakes import evidence
    s = Signer(key_store)
    mp, cp, share = evidence.build(tmp_path, s)
    man = json.loads(open(mp).read())
    man["documents"][0]["output_dir"] = "../escape"
    man.pop("signer")
    from surgic.audit.manifest import write_signed
    write_signed(man, mp, s)
    assert "output_path_invalid:00001-abc" in verify_file(mp, s.public_pem(), str(share), cp)
