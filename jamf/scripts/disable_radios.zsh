#!/bin/zsh
# Jamf policy script (runs as root): power off Wi-Fi and remove it from the
# service order, and power off Bluetooth when blueutil is deployed. Profiles can
# lock these settings but cannot force the radios off; pair with the
# surgic_radios Extension Attribute to detect drift.
set -u
wifi_dev=$(/usr/sbin/networksetup -listallhardwareports | /usr/bin/awk '/Hardware Port: (Wi-Fi|AirPort)/{getline; print $2; exit}')
if [[ -n ${wifi_dev:-} ]]; then
  /usr/sbin/networksetup -setairportpower "$wifi_dev" off
  /usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off 2>/dev/null || true
fi
for bu in /opt/homebrew/bin/blueutil /usr/local/bin/blueutil; do
  [[ -x $bu ]] && { "$bu" --power 0; break; }
done
exit 0
