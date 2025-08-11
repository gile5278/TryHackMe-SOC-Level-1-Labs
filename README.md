# TryHackMe – SOC Level 1 Labs

This repository is my **Security Operations Center (SOC) analyst training portfolio**, containing completed labs from the **TryHackMe SOC Level 1** path.  
Each lab simulates real-world attack scenarios, requiring log analysis, threat hunting, and incident response.

---

## 📌 Skills Practiced
- SIEM investigation with **Splunk**, **Elastic Stack**, and **Wazuh**
- Writing and optimizing search queries
- Decoding and analyzing obfuscated payloads
- Identifying persistence, privilege escalation, and credential dumping techniques
- Correlating events to reconstruct attack timelines

---

## 🛠 Tools & Technologies
- **SIEMs**: Splunk, Elastic Stack, Wazuh  
- **Logging**: Sysmon, Windows Event Logs  
- **Analysis Tools**: CyberChef, PowerShell, KQL/SPL queries  

---

## 📂 Labs Included
| Lab Name | SIEM Used | Key Focus |
|----------|-----------|-----------|
| [Boogeyman 3 (Elastic)](Tryhackme%20Boogeyman%203%20(Elastic)/Document.md) | Elastic Stack | Detecting persistence & malicious PowerShell |
| [Monday Monitor (Wazuh)](Tryhackme%20Monday%20Monitor%20(Wazhu)/Document.md) | Wazuh | Endpoint monitoring & Base64 payload decoding |
| [Inversitgating with Splunk](Tryhackme%20Investigating%20with%20Splunk/Document.md) | Splunk | Suspicious account creation & network IOC hunting |

---

## 📸 Evidence
Each lab folder contains:
- `Document.md` – Step-by-step investigation notes
- `Document_Images/` – Screenshots of SIEM dashboards, queries, and decoded artifacts

---

> **Disclaimer:** All labs are simulated exercises from TryHackMe for educational purposes only. No real systems were harmed.
