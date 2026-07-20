#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <target_subnet>"
    exit 1
fi

TARGET="$1"
ALLOWED_FILE="/var/ossec/etc/allowed_macs.txt"
LOG_FILE="/var/ossec/logs/nmap_shadow_it.log"
TMP_SCAN="/tmp/nmap_shadow_scan.txt"
SCAN_TIME=$(date -Iseconds)

if [ ! -f "$ALLOWED_FILE" ]; then
    echo "Error: Allowed MAC file not found at $ALLOWED_FILE"
    exit 1
fi

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# 1. Run local ping/ARP scan (requires root/sudo to see MAC addresses)
# -sn skips port scanning, making this extremely fast (seconds)
nmap -sn "$TARGET" -oN "$TMP_SCAN" > /dev/null 2>&1

if [ ! -f "$TMP_SCAN" ]; then
    exit 1
fi

# 2. Parse the Nmap output using a robust state loop
current_ip=""
current_mac=""
current_vendor=""

# Patterns extracted into variables to prevent Bash evaluation glitches
report_pattern="^Nmap scan report for (.+)"
ip_in_parentheses="\(([^)]+)\)"
mac_pattern="^MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)"

while read -r line; do
    # Extract IP address
    if [[ "$line" =~ $report_pattern ]]; then
        matched="${BASH_REMATCH[1]}"
        if [[ "$matched" =~ $ip_in_parentheses ]]; then
            current_ip="${BASH_REMATCH[1]}"
        else
            current_ip="$matched"
        fi
    fi

    # Extract MAC and Vendor
    if [[ "$line" =~ $mac_pattern ]]; then
        current_mac=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
        current_vendor="${BASH_REMATCH[2]}"

        # Check if this MAC is in the allowed file (ignoring case and comments)
        if ! grep -qsi "^${current_mac}" "$ALLOWED_FILE"; then
            # Rogue device detected! Write structured JSON to the log file
            echo "{\"integration\":\"nmap_shadow_it\",\"scan_time\":\"$SCAN_TIME\",\"host_ip\":\"$current_ip\",\"mac_address\":\"$current_mac\",\"vendor\":\"$current_vendor\",\"status\":\"unauthorized\"}" >> "$LOG_FILE"
        fi

        # Reset variables for the next host block
        current_ip=""
        current_mac=""
        current_vendor=""
    fi
done < "$TMP_SCAN"

# Cleanup
rm -f "$TMP_SCAN"