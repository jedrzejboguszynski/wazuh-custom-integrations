# Wazuh & Microsoft Defender XDR / Azure Integration Rules

This repository contains custom Wazuh rules and configuration snippets designed to enhance the integration between **Wazuh SIEM** and the **Microsoft Ecosystem** (Microsoft Defender XDR and Defender for Cloud). 

These rules help bridge the gap between Microsoft telemetry and Wazuh, allowing for **1:1 severity mapping** and direct portal deep-linking.

---

## 📁 Repository Structure

* **`defender_incidents.xml`**  
  Custom rules for mapping **Microsoft Defender Incidents** to Wazuh alert severity levels (1:1 mapping), including dynamic deep-links directly to the Defender XDR Incident portal.

* **`defender_alerts.xml`**  
  Custom rules for standalone **Microsoft Defender Alerts** severity mapping (1:1), designed for environments focusing on granular alert-level ingestion instead of correlated incidents.

* **`defender_for_cloud.xml`**  
  Custom rules built on top of native Wazuh decoders to map severity levels for **Microsoft Defender for Cloud** logs ingested via **Azure Log Analytics Workspace (LAW)**.

* **`ossec.conf`**  
  Configuration snippet for the `<ms-graph>` module in `wazuh-manager`.