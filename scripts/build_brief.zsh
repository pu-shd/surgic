#!/bin/zsh
# Render the printable security brief (docs/brief/*.html) to PDF with headless
# Chrome or Edge. Fonts load from Google Fonts, so this needs network access
# (run it on a workstation or in CI, never on the air-gapped host).
#
#   scripts/build_brief.zsh            # writes docs/brief/surgic-security-brief.pdf
set -euo pipefail
cd "${0:A:h}/.."

SRC="docs/brief/surgic-security-brief.html"
OUT="docs/brief/surgic-security-brief.pdf"

CHROME=""
for c in "${CHROME_BIN:-}" \
         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
         "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
         google-chrome google-chrome-stable chromium chromium-browser; do
  [[ -z "$c" ]] && continue
  if [[ -x "$c" ]] || command -v "$c" >/dev/null 2>&1; then CHROME="$c"; break; fi
done
[[ -n "$CHROME" ]] || { print -u2 "no Chrome/Chromium/Edge found (set CHROME_BIN)"; exit 1; }

PROFILE=$(mktemp -d)
rm -f "$OUT"
# Headless Chrome on macOS can keep running after writing the PDF, so run it in
# the background, wait until the file stops growing, then stop that instance.
"$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
  --user-data-dir="$PROFILE" --no-pdf-header-footer --virtual-time-budget=10000 \
  --print-to-pdf="$PWD/$OUT" "file://$PWD/$SRC" >/dev/null 2>&1 &
CPID=$!
cleanup() { kill $CPID 2>/dev/null; pkill -f -- "--user-data-dir=$PROFILE" 2>/dev/null; rm -rf "$PROFILE"; }
trap cleanup EXIT
last=-1
for i in {1..120}; do
  if ! kill -0 $CPID 2>/dev/null; then break; fi
  if [[ -s "$OUT" ]]; then
    size=$(wc -c < "$OUT" | tr -d ' ')
    (( size == last )) && break
    last=$size
  fi
  sleep 1
done

# Silence is not success: the PDF must exist, be a PDF, and be non-trivial.
[[ -s "$OUT" ]] || { print -u2 "PDF was not produced"; exit 1; }
[[ "$(head -c 5 "$OUT")" == "%PDF-" ]] || { print -u2 "output is not a PDF"; exit 1; }
(( $(wc -c < "$OUT" | tr -d ' ') > 20000 )) || { print -u2 "PDF suspiciously small"; exit 1; }
print "wrote $OUT"
