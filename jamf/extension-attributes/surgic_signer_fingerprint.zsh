#!/bin/zsh
# Jamf Extension Attribute: SHA-256 of the Secure Enclave signing certificate
# (subject CN "surgic-signing") in the System keychain. InfoSec records this
# centrally as the expected signer, independent of anything on the output share.
CN="${SURGIC_SIGNER_CN:-surgic-signing}"
fp=$(/usr/bin/security find-certificate -c "$CN" -Z /Library/Keychains/System.keychain 2>/dev/null \
      | /usr/bin/awk '/SHA-256 hash:/ {print $3; exit}')
echo "<result>${fp:-MISSING}</result>"
