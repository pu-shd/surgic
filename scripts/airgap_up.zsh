#!/bin/zsh
# Bring up the airgap: RAM disk, pf default-deny, packet captures, egress probe, SMB mounts.
set -euo pipefail
cd "${0:A:h}/.."
CONFIG="${1:-config/surgic.toml}"
sudo -v
exec .venv/bin/surgic up -c "$CONFIG"
