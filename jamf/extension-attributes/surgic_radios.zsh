#!/bin/zsh
# Jamf Extension Attribute: Wi-Fi power and Bluetooth controller state.
wifi_dev=$(/usr/sbin/networksetup -listallhardwareports | /usr/bin/awk '/Hardware Port: (Wi-Fi|AirPort)/{getline; print $2; exit}')
wifi=$([[ -n $wifi_dev ]] && /usr/sbin/networksetup -getairportpower "$wifi_dev" | /usr/bin/awk '{print $NF}' || echo none)
bt=$(/usr/sbin/system_profiler SPBluetoothDataType -json 2>/dev/null \
      | /usr/bin/plutil -extract SPBluetoothDataType.0.controller_properties.controller_state raw - 2>/dev/null)
echo "<result>wifi=${wifi} bluetooth=${bt:-unknown}</result>"
