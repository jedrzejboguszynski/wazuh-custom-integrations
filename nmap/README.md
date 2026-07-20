# Wazuh Security Integrations

A collection of 3 lightweight integrations for the Wazuh agent designed to automate security monitoring and local network vulnerability detection.

## Repository Content

1. **Integration 1: Open Ports Audit**
   * Monitors active open ports and alerts on insecure or unauthorized port exposures.
2. **Integration 2: System Vulnerability Scanning**
   * Leverages Nmap scripting engine (NSE) to map system vulnerabilities and forwards results directly to the Wazuh Manager.
3. **Integration 3: Rogue Host Detection (Shadow IT)**
   * Scans subnets using Nmap and matches discovered MAC addresses against a whitelist (`allowed_macs.txt`).