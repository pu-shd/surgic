#!/bin/zsh
# Jamf Extension Attribute: SHA-256, owner and mode of the deployed pf airgap ruleset.
f=/etc/pf.anchors/airgap.rules
if [[ -f $f ]]; then
  h=$(/usr/bin/shasum -a 256 "$f" | /usr/bin/awk '{print $1}')
  o=$(/usr/bin/stat -f '%Su:%Sg %Lp' "$f")
  echo "<result>${h} ${o}</result>"
else
  echo "<result>MISSING</result>"
fi
