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

RAMDISK_NAME=$(.venv/bin/python -c "from surgic.config import Config; print(Config.load('$CONFIG').storage.ramdisk_name)")

sudo -v
# Keep sudo alive for the duration of the run.
( while true; do sudo -n true; sleep 50; done ) 2>/dev/null &
SUDO_KEEPALIVE=$!

teardown() {
  local rc=$?
  trap - EXIT INT TERM
  scripts/teardown.zsh "$CONFIG" || rc=$(( rc ? rc : 4 ))
  kill $SUDO_KEEPALIVE 2>/dev/null || true
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
kill $SUDO_KEEPALIVE 2>/dev/null || true

print "==> Verification"
print "Remount the output share read-only on a separate workstation and run:"
print "  surgic verify <share>/manifests/<run>.manifest.json --pubkey pubkey.pem --outputs <share>"
print "  surgic verify <share>/evidence/<ts>/closure.json --pubkey pubkey.pem"
exit $RUN_RC
