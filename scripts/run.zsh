#!/bin/zsh
# Full sanitization run under the airgap.
#
#   scripts/run.zsh [config/surgic.toml]
#
# airgap up -> preflight -> sanitize -> teardown (always, via trap) -> verify.
set -euo pipefail
cd "${0:A:h}/.."
CONFIG="${1:-config/surgic.toml}"
[[ -f "$CONFIG" ]] || { print -u2 "missing $CONFIG"; exit 64; }

# The path is passed as an argument, never interpolated into Python source.
RAMDISK_NAME=$(.venv/bin/python -c 'import sys; from surgic.config import Config; print(Config.load(sys.argv[1]).storage.ramdisk_name)' "$CONFIG")

# No sudo keepalive: `surgic run` drops the ticket after preflight, and
# document parsing runs in sandboxed workers with no terminal. Teardown asks
# for the password again (the airgap stays up until it is given).
sudo -v

teardown() {
  local rc=$?
  trap - EXIT INT TERM
  scripts/teardown.zsh "$CONFIG" || rc=$(( rc ? rc : 4 ))
  exit $rc
}
trap teardown EXIT INT TERM

ulimit -c 0
scripts/airgap_up.zsh "$CONFIG"

export TMPDIR="/Volumes/${RAMDISK_NAME}"
export PIPELINE_WORKSPACE="/Volumes/${RAMDISK_NAME}/workspace"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_DATASETS_OFFLINE=1 DO_NOT_TRACK=1
mkdir -p "$PIPELINE_WORKSPACE"

set +e
.venv/bin/surgic run -c "$CONFIG"
RUN_RC=$?
set -e
print "surgic run exit code: $RUN_RC (0=all clean, 3=some quarantined, other=aborted)"

# Teardown (trap) writes the signed closure; verify both after it completes.
trap - EXIT INT TERM
scripts/teardown.zsh "$CONFIG"

print "==> Verification"
print "Remount the output share read-only on a separate workstation and run, with"
print "InfoSec's own copy of the public key (not the pubkey.pem on the share):"
print "  surgic verify <share>/manifests/<run>.manifest.json --pubkey pubkey.pem \\"
print "      --outputs <share> --closure <share>/evidence/<ts>/closure.json --expect-model <sha256>"
exit $RUN_RC
