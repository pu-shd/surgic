#!/bin/zsh
# Jamf Extension Attribute: whether a surgic airgap is active (pf status + RAM disk).
pf=$(/sbin/pfctl -s info 2>/dev/null | /usr/bin/awk '/^Status:/ {print $2}')
ram=$(/usr/bin/hdiutil info 2>/dev/null | /usr/bin/grep -c 'ram://')
echo "<result>pf=${pf:-unknown} ramdisks=${ram}</result>"
