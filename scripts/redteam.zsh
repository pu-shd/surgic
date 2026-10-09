#!/bin/zsh
# Prompt-injection red team for the Phase B model (Promptfoo), fully local:
# synthetic cases only (redteam/cases.yaml), the model served by a private
# loopback Ollama, Promptfoo telemetry, sharing and remote attack generation
# off. Run when the model, prompt or defenses change, before InfoSec approval.
#
#   scripts/redteam.zsh               # qwen3.6:27b (or SURGIC_REDTEAM_MODEL)
#   scripts/redteam.zsh --mock        # harness smoke test, no model (CI)
#
# Needs Node (npx) the first time to fetch the pinned Promptfoo; never run it
# on the air-gapped host during a sanitization session.
set -euo pipefail
cd "${0:A:h}/.."

PF_VERSION=0.124.1
MODE="${1:-real}"
CONFIG=redteam/promptfooconfig.yaml
[[ "$MODE" == "--mock" ]] && CONFIG=redteam/promptfooconfig.mock.yaml
command -v npx >/dev/null || { print -u2 "npx (Node.js) is required"; exit 1; }
[[ -x .venv/bin/python ]] || { print -u2 "missing .venv (scripts/test.zsh creates it)"; exit 1; }

export PROMPTFOO_DISABLE_TELEMETRY=1 PROMPTFOO_DISABLE_UPDATE=1 PROMPTFOO_DISABLE_SHARING=1
export PROMPTFOO_DISABLE_REMOTE_GENERATION=true PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
export PROMPTFOO_PYTHON="$PWD/.venv/bin/python" PYTHONPATH="$PWD/src"
WORK=$(mktemp -d)
export PROMPTFOO_CONFIG_DIR="$WORK/promptfoo"   # its database stays out of $HOME

OLLAMA_PID=""
cleanup() { [[ -n "$OLLAMA_PID" ]] && kill $OLLAMA_PID 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

if [[ "$MODE" != "--mock" ]]; then
  export SURGIC_REDTEAM_MODEL="${SURGIC_REDTEAM_MODEL:-qwen3.6:27b}" SURGIC_REDTEAM_PORT=18094
  OLLAMA_HOST="127.0.0.1:$SURGIC_REDTEAM_PORT" OLLAMA_MODELS="${OLLAMA_MODELS:-$HOME/.ollama/models}" \
    OLLAMA_KEEP_ALIVE=30m ollama serve >/dev/null 2>&1 &
  OLLAMA_PID=$!
  for i in {1..60}; do curl -sf "http://127.0.0.1:$SURGIC_REDTEAM_PORT/api/version" >/dev/null && break; sleep 1; done
  curl -sf "http://127.0.0.1:$SURGIC_REDTEAM_PORT/api/version" >/dev/null || { print -u2 "ollama did not start"; exit 1; }
fi

mkdir -p redteam/results
OUT="redteam/results/$(date -u +%Y%m%dT%H%M%SZ)${MODE/--mock/-mock}.json"
OUT="${OUT/real/}"
# Promptfoo exits non-zero when any assertion fails (model-only misses are
# expected to be possible); the gate below decides.
npx -y "promptfoo@$PF_VERSION" eval -c "$CONFIG" --no-cache --max-concurrency 1 --no-progress-bar \
  -o "$OUT" || true
[[ -s "$OUT" ]] || { print -u2 "no results written"; exit 1; }
CASES=$(.venv/bin/python -c 'import sys, yaml; print(len(yaml.safe_load(open(sys.argv[1]))))' redteam/cases.yaml)
.venv/bin/python redteam/summarize.py "$OUT" "$CASES"
