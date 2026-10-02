#!/bin/zsh
# Native macOS test run (includes Vision OCR / Keychain / hdiutil tests).
set -euo pipefail
cd "${0:A:h}/.."

if [[ ! -x .venv/bin/python ]]; then
  python3.12 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -e '.[dev,ocr-vision,hyperscan]'
fi
for m in en_core_web_lg en_core_web_sm; do
  .venv/bin/python -c "import spacy.util,sys; sys.exit(0 if spacy.util.is_package('$m') else 1)" \
    || .venv/bin/python -m spacy download "$m"
done

export SURGIC_MIN_TESTS="${SURGIC_MIN_TESTS:-120}"
exec .venv/bin/python -m pytest -rs tests "$@"
