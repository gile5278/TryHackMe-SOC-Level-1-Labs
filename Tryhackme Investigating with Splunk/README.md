## TryHackMe – SOC Level 1 Labs
This repository contains walkthroughs of SOC Level 1 hands-on labs from TryHackMe, focusing on SIEM investigations, log analysis, and incident response.
Each lab documents the investigation process, queries used, evidence gathered, and final answers.

## 🔍 Skills Practiced
 - Using Splunk for security investigations
 - Crafting and optimizing search queries
 - Identifying malicious behavior in logs
 - Decoding and analyzing obfuscated scripts
 - Correlating events to reconstruct attack timelines

## 🛠 Tools & Technologies
 - SIEMs: Splunk, Elastic Stack (future labs)
 - Techniques: Event log analysis, PowerShell investigation, registry analysis
 - Formats: Windows Event Logs, encoded scripts, command-line artifacts


## 📄 Example Lab – Investigating with Splunk
**Scenario**: SOC analyst investigates suspicious log activity on Windows endpoints, identifying a backdoor account creation, registry modification, malicious PowerShell execution, and C2 web requests.

## Highlights:
 - Detected backdoor user: A1berto
 - Registry key modified for persistence:
```HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto```
 - Malicious remote account creation via WMIC
 - Decoded malicious PowerShell to reveal C2 URL:
```hxxp[://]10[.]10[.]10[.]5/news[.]php```
