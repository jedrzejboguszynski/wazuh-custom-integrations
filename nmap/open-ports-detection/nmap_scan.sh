#!/bin/bash

# Target configuration - can be passed as an argument (e.g., host or subnet)
if [ -z "$1" ]; then
    echo "Usage: $0 <target_or_subnet>"
    exit 1
fi

TARGET="$1"
LOG_FILE="/var/ossec/logs/nmap_scans.log"
SCAN_TIME=$(date -Iseconds)

# Run nmap scan and output to grepable format (-oG -) directly to memory/pipe
nmap -sT -p- --open "$TARGET" -oG - | while read -r line; do
    # Filter only lines containing host status and port information
    if echo "$line" | grep -q "Ports:"; then
        # Extract IP address
        host_ip=$(echo "$line" | awk '{print $2}')
        # Extract hostname if available (or empty)
        hostname=$(echo "$line" | awk '{print $3}' | tr -d '()')

        # Extract the ports section and split them by comma
        ports_str=$(echo "$line" | sed -e 's/.*Ports: //')

        IFS=',' read -ra ADDR <<< "$ports_str"
        for port_info in "${ADDR[@]}"; do
            # Trim leading/trailing whitespace
            port_info=$(echo "$port_info" | xargs)

            # Format in grepable output is: port/state/protocol/owner/service/rpcinfo/version
            # Example: 80/open/tcp//http//
            IFS='/' read -ra PORT_FIELDS <<< "$port_info"

            port="${PORT_FIELDS[0]}"
            state="${PORT_FIELDS[1]}"
            protocol="${PORT_FIELDS[2]}"
            service="${PORT_FIELDS[4]}"

            # Write structured JSON to the log file (using nmap_service_port to avoid mapping conflicts)
            echo "{\"integration\":\"nmap\",\"scan_time\":\"$SCAN_TIME\",\"host\":\"$host_ip\",\"hostname\":\"$hostname\",\"protocol\":\"$protocol\",\"nmap_service_port\":$port,\"state\":\"$state\",\"service\":\"$service\"}" >> "$LOG_FILE"
        done
    fi
done