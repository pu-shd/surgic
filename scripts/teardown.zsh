#!/bin/zsh
# Idempotent teardown: stop captures, archive evidence to the output share,
# zero-fill + detach the RAM disk, restore pf, write the signed closure record.
set -uo pipefail
cd "${0:A:h}/.."
CONFIG="${1:-config/surgic.toml}"
sudo -v
.venv/bin/surgic down -c "$CONFIG"
rc=$?
if (( rc != 0 )); then
  print -u2 "teardown reported errors (rc=$rc); inspect 'hdiutil info' and 'sudo pfctl -s info'"
fi
exit $rc
