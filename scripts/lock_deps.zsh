#!/bin/zsh
# Regenerate the hash-locked dependency set for the target (macOS arm64,
# Python 3.12). Needs network; run on a workstation, review the diff, commit.
#
#   scripts/lock_deps.zsh
set -euo pipefail
cd "${0:A:h}/.."
command -v uv >/dev/null || { print -u2 "uv is required (https://docs.astral.sh/uv/)"; exit 1; }
uv pip compile requirements/macos-arm64.in \
  --python-version 3.12 --python-platform aarch64-apple-darwin \
  --generate-hashes --no-header --no-emit-package surgic \
  -o requirements/macos-arm64.lock
# Silence is not success: the lock must exist and every requirement must be hashed.
[[ -s requirements/macos-arm64.lock ]] || { print -u2 "lock file not produced"; exit 1; }
grep -q -- '--hash=sha256:' requirements/macos-arm64.lock || { print -u2 "no hashes in lock"; exit 1; }
print "wrote requirements/macos-arm64.lock"
