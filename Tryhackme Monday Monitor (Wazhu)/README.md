# TryHackMe – Monday Monitor (SOC Level 1 Lab)

This repository contains my investigation walkthrough for the **Monday Monitor** challenge on TryHackMe's SOC Level 1 path.  
The lab focuses on detecting and analyzing endpoint activity using **Wazuh** and **Sysmon**.

---

## 📌 Scenario
Swiftspend Finance is enhancing its cybersecurity posture by deploying **Wazuh** for endpoint monitoring.  
On **April 29, 2024 (12:00–20:00)**, a simulated attack was executed to evaluate detection capabilities.  
As the SOC analyst, my task was to investigate suspicious logs, identify attack techniques, and document findings.

---

## 🔍 Skills Practiced
- SIEM investigation using Wazuh
- Filtering and analyzing security events
- Decoding Base64 payloads
- Identifying persistence mechanisms
- Recognizing credential dumping activity

---

## 🛠 Tools & Technologies
- **SIEM**: Wazuh  
- **Logging**: Sysmon  
- **Analysis**: CyberChef, Command-line investigation  

---

## 📄 Summary of Findings
| Task | Finding | Technique |
|------|---------|-----------|
| Initial access | `SwiftSpend_Financial_Expenses.xlsm` downloaded via PowerShell | T1566 – Phishing Attachment |
| Persistence | Scheduled task created to execute Base64-encoded PowerShell payload | T1053.005 – Scheduled Task |
| Command & Control | Decoded payload: `ping www.youarevulnerable.thm` | T1027 – Obfuscated Files |
| Privilege abuse | Guest account password set to `I_AM_M0NIT0R1NG` | T1078 – Valid Accounts |
| Credential dumping | `memotech.exe` (renamed Mimikatz) used on LSASS dump | T1003.001 – LSASS Memory Dumping |

---
