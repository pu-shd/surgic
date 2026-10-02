from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("SURGIC_ALLOW_MOCK", "1")
os.environ.setdefault("SURGIC_ALLOW_FILE_KEY", "1")

from surgic import netguard  # noqa: E402

# The whole suite runs under the in-process egress guard: any library that
# tries to reach the network fails the session (see pytest_sessionfinish).
netguard.install()


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "macos" in item.keywords and sys.platform != "darwin":
            item.add_marker(pytest.mark.skip(reason="macOS-only facility (mocked elsewhere)"))


_results = {"passed": 0, "failed": 0}


def pytest_runtest_logreport(report):
    if report.when == "call":
        if report.passed:
            _results["passed"] += 1
        elif report.failed:
            _results["failed"] += 1


def pytest_sessionfinish(session, exitstatus):
    # Silence is never success: a run that executed fewer tests than expected fails.
    if netguard.attempts:
        print(f"\nERROR: in-process egress attempted: {netguard.attempts}", file=sys.stderr)
        session.exitstatus = 1
    minimum = int(os.environ.get("SURGIC_MIN_TESTS", "1"))
    if session.config.option.collectonly or getattr(session.config.option, "keyword", ""):
        return
    if _results["passed"] < minimum and exitstatus == 0:
        print(f"\nERROR: only {_results['passed']} tests passed; expected >= {minimum}", file=sys.stderr)
        session.exitstatus = 1


@pytest.fixture(scope="session")
def presidio_engine():
    from surgic.detect.presidio_engine import PresidioEngine
    from surgic.config import DetectConfig
    d = DetectConfig()
    model = os.environ.get("SURGIC_TEST_SPACY", "en_core_web_lg")
    return PresidioEngine(model, "en_core_web_sm", d.presidio_entities, d.presidio_score_threshold)


@pytest.fixture(scope="session")
def phase_a(presidio_engine):
    from surgic.config import DetectConfig
    from surgic.detect import PhaseA
    return PhaseA.from_config(DetectConfig(), presidio=presidio_engine)


@pytest.fixture(scope="session")
def regex_only():
    from surgic.config import DetectConfig
    from surgic.detect import PhaseA
    pa = PhaseA.from_config(DetectConfig(), presidio=None)
    pa.presidio = None
    return pa


@pytest.fixture(scope="session")
def ocr():
    from surgic.extract.ocr import default_ocr
    if not (sys.platform == "darwin" or shutil.which("tesseract")):
        pytest.fail("no OCR engine available (Vision or tesseract required)")
    return default_ocr("auto")


@pytest.fixture
def key_store(tmp_path):
    from surgic.audit.signing import FileStore, Signer
    store = FileStore(str(tmp_path / "seed.b64"))
    Signer.generate(store)
    return store


def _write_exec(path: Path, body: str) -> str:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture
def fake_scanners(tmp_path):
    """Executable stand-ins for gitleaks/trufflehog that flag AKIA keys."""
    from surgic.audit.postscan import SecretScanners
    gl = _write_exec(tmp_path / "gitleaks", f"""#!{sys.executable}
import json, os, re, sys
a = sys.argv
src = a[a.index('--source') + 1]; rep = a[a.index('--report-path') + 1]
hits = []
for n in os.listdir(src):
    p = os.path.join(src, n)
    if os.path.isfile(p) and re.search(r'AKIA[0-9A-Z]{{16}}', open(p, errors='ignore').read()):
        hits.append({{"RuleID": "aws-access-token", "File": n}})
json.dump(hits, open(rep, 'w'))
sys.exit(3 if hits else 0)
""")
    th = _write_exec(tmp_path / "trufflehog", f"""#!{sys.executable}
import json, os, re, sys
src = sys.argv[2]; n = 0
for f in os.listdir(src):
    p = os.path.join(src, f)
    if os.path.isfile(p) and re.search(r'AKIA[0-9A-Z]{{16}}', open(p, errors='ignore').read()):
        print(json.dumps({{"DetectorName": "AWS", "SourceMetadata": {{}}}})); n += 1
sys.exit(183 if n else 0)
""")
    return SecretScanners(gl, th, required=True)


@pytest.fixture
def real_or_fake_scanners(fake_scanners):
    from surgic.audit.postscan import SecretScanners
    if shutil.which("gitleaks") and shutil.which("trufflehog"):
        return SecretScanners("gitleaks", "trufflehog", required=True)
    return fake_scanners
