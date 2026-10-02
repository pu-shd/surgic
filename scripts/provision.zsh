#!/bin/zsh
# ONLINE provisioning of the Mac Studio (run BEFORE the machine is air-gapped).
#
#   scripts/provision.zsh <model-file-or-dir> [--wheelhouse]
#
# Installs runtimes and tools, creates the venv, downloads spaCy models, records
# the model's SHA-256 for the allowlist, generates the signing key, and
# optionally builds an offline wheelhouse for re-provisioning without network.
set -euo pipefail
cd "${0:A:h}/.."

MODEL="${1:-}"
WHEELHOUSE="${2:-}"
[[ -n "$MODEL" ]] || { print -u2 "usage: $0 <model-file-or-dir> [--wheelhouse]"; exit 64; }
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { print -u2 "Apple Silicon macOS required"; exit 1; }

print "==> Homebrew packages"
command -v brew >/dev/null || { print -u2 "Homebrew is required"; exit 1; }
brew install python@3.12 llama.cpp ollama tesseract gitleaks trufflehog
brew install --cask libreoffice

print "==> Python environment"
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[ocr-vision,hyperscan,mlx,dev]'
.venv/bin/python -m spacy download en_core_web_trf
.venv/bin/python -m spacy download en_core_web_lg

if [[ "$WHEELHOUSE" == "--wheelhouse" ]]; then
  print "==> Offline wheelhouse (./wheelhouse)"
  .venv/bin/pip wheel -w wheelhouse '.[ocr-vision,hyperscan,mlx]'
fi

print "==> Model identity"
if [[ -d "$MODEL" ]]; then
  SHA=$(.venv/bin/python -c "from surgic.llm.identity import dir_sha256; print(dir_sha256('$MODEL'))")
else
  SHA=$(shasum -a 256 "$MODEL" | awk '{print $1}')
fi
print "model_sha256 = [\"$SHA\"]   # add to [llm] in config/surgic.toml"

if [[ ! -f config/surgic.toml ]]; then
  cp config/surgic.example.toml config/surgic.toml
  print "==> Created config/surgic.toml from example; edit smb_share_ip, shares and model before use."
fi

print "==> Signing key (Keychain)"
.venv/bin/surgic keygen -c config/surgic.toml || print "signing key already present (kept)"
.venv/bin/surgic pubkey -c config/surgic.toml > pubkey.pem
print "Public key written to ./pubkey.pem; hand it to InfoSec for manifest verification."

print "==> Running native test suite"
scripts/test.zsh -q
print "Provisioning complete. Disconnect every network except the SMB VLAN before scripts/run.zsh."
