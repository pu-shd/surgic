#!/bin/zsh
# ONLINE provisioning of the Mac Studio (run BEFORE the machine is air-gapped).
#
#   scripts/provision.zsh <ollama-tag | model-file | model-dir> [--wheelhouse]
#   e.g. scripts/provision.zsh qwen3.6:27b
#
# Installs runtimes and tools, creates the venv from the hash-locked dependency
# set (requirements/macos-arm64.lock, spaCy models included), records the
# model's SHA-256 for the allowlist, requires signed SMB in /etc/nsmb.conf,
# generates the signing key, and optionally builds an offline wheelhouse.
set -euo pipefail
cd "${0:A:h}/.."

MODEL="${1:-}"
WHEELHOUSE="${2:-}"
[[ -n "$MODEL" ]] || { print -u2 "usage: $0 <ollama-tag | model-file | model-dir> [--wheelhouse]"; exit 64; }
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { print -u2 "Apple Silicon macOS required"; exit 1; }

print "==> Homebrew packages"
command -v brew >/dev/null || { print -u2 "Homebrew is required"; exit 1; }
brew install python@3.12 llama.cpp ollama tesseract gitleaks trufflehog
brew install --cask libreoffice

print "==> Python environment (hash-locked)"
LOCK=requirements/macos-arm64.lock
[[ -s "$LOCK" ]] || { print -u2 "missing $LOCK (scripts/lock_deps.zsh)"; exit 1; }
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r "$LOCK"
.venv/bin/pip install --no-deps --no-build-isolation -e .
.venv/bin/pip check
# Test-only tools, outside the locked runtime set.
.venv/bin/pip install 'pytest>=8' 'hypothesis>=6.100' 'python-docx>=1.1' 'pytest-timeout>=2.3'

if [[ "$WHEELHOUSE" == "--wheelhouse" ]]; then
  print "==> Offline wheelhouse (./wheelhouse)"
  .venv/bin/pip download --require-hashes --no-deps -d wheelhouse -r "$LOCK"
fi

print "==> SMB client policy (/etc/nsmb.conf)"
if [[ ! -e /etc/nsmb.conf ]]; then
  print "[default]\nsigning_required=yes\nprotocol_vers_map=4" | sudo tee /etc/nsmb.conf >/dev/null
  print "wrote /etc/nsmb.conf (SMB3 only, signing required)"
elif ! grep -q '^signing_required=yes' /etc/nsmb.conf; then
  print -u2 "/etc/nsmb.conf exists without signing_required=yes; add it (and protocol_vers_map=4) by hand"
fi

print "==> Model identity"
# Values are passed as arguments, never interpolated into Python source.
if [[ -d "$MODEL" ]]; then
  SHA=$(.venv/bin/python -c 'import sys; from surgic.llm.identity import dir_sha256; print(dir_sha256(sys.argv[1]))' "$MODEL")
elif [[ -f "$MODEL" ]]; then
  SHA=$(shasum -a 256 "$MODEL" | awk '{print $1}')
else
  # Ollama tag: pull through a temporary private server, stop only that
  # server (by PID), then hash the manifest and every blob from disk.
  PORT=18093
  OLLAMA_HOST="127.0.0.1:$PORT" ollama serve >/dev/null 2>&1 &
  OLLAMA_PID=$!
  trap 'kill $OLLAMA_PID 2>/dev/null' EXIT
  for i in {1..30}; do curl -sf "http://127.0.0.1:$PORT/api/version" >/dev/null && break; sleep 1; done
  OLLAMA_HOST="127.0.0.1:$PORT" ollama pull "$MODEL"
  kill $OLLAMA_PID 2>/dev/null; wait $OLLAMA_PID 2>/dev/null; trap - EXIT
  SHA=$(.venv/bin/python -c 'import os, sys; from surgic.llm.identity import ollama_identity; print(ollama_identity(sys.argv[1], os.path.expanduser("~/.ollama/models")))' "$MODEL")
  [[ -n "$SHA" ]] || { print -u2 "could not hash $MODEL"; exit 1; }
fi
print "model_sha256 = [\"$SHA\"]   # add to [llm] in config/surgic.toml"

if [[ ! -f config/surgic.toml ]]; then
  cp config/surgic.example.toml config/surgic.toml
  print "==> Created config/surgic.toml from example; edit smb_share_ip, smb_interface, shares and model before use."
fi

print "==> Signing key (Keychain)"
.venv/bin/surgic keygen -c config/surgic.toml || print "signing key already present (kept)"
.venv/bin/surgic pubkey -c config/surgic.toml > pubkey.pem
print "Public key written to ./pubkey.pem; hand it to InfoSec for manifest verification."

print "==> Running native test suite"
scripts/test.zsh -q
print "==> External tool versions (record for InfoSec)"
brew list --versions python@3.12 llama.cpp ollama tesseract gitleaks trufflehog || true
print "Provisioning complete. Disconnect every network except the SMB VLAN before scripts/run.zsh."
