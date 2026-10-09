"""surgic command-line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import logging_safe
from .logging_safe import SafeError


def _cfg(args):
    from .config import Config
    return Config.load(args.config)


def _signer(cfg):
    from .audit.signing import Signer, store_from_env
    return Signer(store_from_env(cfg.audit.keychain_service, cfg.audit.keychain_account))


def cmd_keygen(args) -> int:
    from .audit.signing import Signer, store_from_env
    cfg = _cfg(args)
    store = store_from_env(cfg.audit.keychain_service, cfg.audit.keychain_account)
    Signer.generate(store, overwrite=args.overwrite)
    print(Signer(store).fingerprint())
    return 0


def cmd_pubkey(args) -> int:
    sys.stdout.buffer.write(_signer(_cfg(args)).public_pem())
    return 0


def cmd_up(args) -> int:
    from .env import Runner
    from .env.lifecycle import up
    up(_cfg(args), Runner())
    return 0


def cmd_down(args) -> int:
    from .env import Runner
    from .env.lifecycle import down
    path = down(_cfg(args), Runner(), _signer(_cfg(args)))
    print(path or "nothing to tear down")
    return 0


def _preflight(cfg, model_hash):
    from .env import Runner
    from .env.preflight import enforce, run_preflight
    checks = run_preflight(cfg, Runner(), model_hash)
    for c in checks:
        print(f"{'PASS' if c.ok else 'FAIL'}  {c.name}{'  (' + c.code + ')' if c.code else ''}", file=sys.stderr)
    enforce(checks)
    return [c.public() for c in checks]


def cmd_preflight(args) -> int:
    from .llm.identity import model_sha256
    cfg = _cfg(args)
    _preflight(cfg, lambda: model_sha256(cfg.llm))
    return 0


def cmd_run(args) -> int:
    from . import netguard
    from .env import Runner
    from .env.lifecycle import record_manifest, session
    from .llm.backend import make_backend
    from .llm.identity import model_sha256
    from .pipeline import Pipeline
    from .worker import make_clients

    netguard.install()  # before any model library is imported
    cfg = _cfg(args)
    st = cfg.storage
    input_dir = args.input or st.input_mount
    output_dir = args.output or st.output_mount
    workspace = args.workspace or st.workspace
    backend = make_backend(cfg.llm)
    env_report: dict = {}
    # Weights are hashed from disk before any model server starts.
    sha = model_sha256(cfg.llm)
    if not args.skip_preflight:
        env_report["preflight"] = _preflight(cfg, lambda: sha)
        # Drop the operator's sudo ticket: nothing in the run needs root, and
        # teardown asks again.
        Runner().run(["sudo", "-k"], check=False)
    else:
        if os.environ.get("SURGIC_ALLOW_NO_PREFLIGHT") != "1":
            raise SafeError("preflight_skip_not_allowed")
        env_report["preflight"] = "SKIPPED"
    analyzer, scanner = make_clients(cfg, args.ocr)
    pipe = Pipeline(cfg, backend, signer=_signer(cfg), model_sha256=sha, environment=env_report,
                    analyzer=analyzer, scanner=scanner, airgap=session(cfg))
    mpath, manifest = pipe.run(input_dir, output_dir, workspace)
    if session(cfg):
        record_manifest(cfg, mpath)
    print(json.dumps({"manifest": mpath, **manifest["summary"]}))
    return 0 if manifest["summary"]["quarantined"] == 0 else 3


def cmd_verify(args) -> int:
    from .audit.verify import verify_file
    with open(args.pubkey, "rb") as f:
        pem = f.read()
    failures = verify_file(args.file, pem, args.outputs, args.closure, args.expect_model,
                           require_opaque_names=args.require_opaque_names)
    if failures:
        for x in failures:
            print("FAIL", x)
        return 1
    print("VERIFIED")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="surgic")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def with_cfg(p):
        p.add_argument("--config", "-c", required=True)
        return p

    p = with_cfg(sub.add_parser("keygen", help="create Ed25519 signing key in Keychain"))
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(fn=cmd_keygen)
    with_cfg(sub.add_parser("pubkey", help="print signing public key (PEM)")).set_defaults(fn=cmd_pubkey)
    with_cfg(sub.add_parser("up", help="bring up airgap: RAM disk, pf, capture, mounts")).set_defaults(fn=cmd_up)
    with_cfg(sub.add_parser("down", help="tear down airgap and write signed closure")).set_defaults(fn=cmd_down)
    with_cfg(sub.add_parser("preflight", help="run fail-closed environment checks")).set_defaults(fn=cmd_preflight)

    p = with_cfg(sub.add_parser("run", help="sanitize all documents"))
    p.add_argument("--input")
    p.add_argument("--output")
    p.add_argument("--workspace")
    p.add_argument("--ocr", default="auto", choices=["auto", "vision", "tesseract"])
    p.add_argument("--skip-preflight", action="store_true",
                   help="testing only; requires SURGIC_ALLOW_NO_PREFLIGHT=1")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("verify", help="verify a signed manifest or closure")
    p.add_argument("file")
    p.add_argument("--pubkey", required=True)
    p.add_argument("--outputs", help="output share root (required for a manifest)")
    p.add_argument("--closure", help="closure.json of the airgap session (required for a manifest)")
    p.add_argument("--expect-model", help="model SHA-256 InfoSec approved; must match the manifest")
    p.add_argument("--require-opaque-names", action="store_true",
                   help="fail if the run released original (redacted) folder and file names")
    p.set_defaults(fn=cmd_verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    logging_safe.install()
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except SafeError as e:
        print(f"error: {e.code} {json.dumps(e.fields, sort_keys=True)}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - messages/tracebacks can hold paths or content
        print(f"error: unexpected {type(e).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
