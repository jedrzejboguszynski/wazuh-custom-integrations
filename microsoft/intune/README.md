# Microsoft Intune Compliance Monitoring via Wazuh `<ms-graph>`

This folder contains a custom rule and configuration snippet for monitoring **Microsoft Intune** device compliance status (`Compliant` vs `Noncompliant`) using Wazuh's native `<ms-graph>` integration module.

> ⚠️ **Disclaimer: Proof of Concept (PoC)**  
> This implementation is provided primarily as a **Proof of Concept (PoC)** and an experimental showcase. Because Intune inventory data is fetched via periodic polling rather than event-driven streaming, non-compliant endpoints will re-trigger alerts on every polling interval. Before using this in production, ensure you adjust the polling interval and apply appropriate rule frequency/suppression logic to prevent alert fatigue.