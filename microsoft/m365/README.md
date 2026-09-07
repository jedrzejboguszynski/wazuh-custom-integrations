# Wazuh Custom Rules

A collection of custom rules for detecting various attack patterns in Microsoft 365, designed to work with Wazuh's built-in Microsoft 365 Management API integration rules and decoders.

# Overview
The included XML file contains rules to detect:
- Malicious redirection rules in Exchange Online
- Privilege escalation (assignment of the Global Administrator role to a user)
- Mass data exfiltration from OneDrive and SharePoint
- Consent phishing (users granting permissions to external SaaS applications)