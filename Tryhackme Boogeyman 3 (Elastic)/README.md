# TryHackMe: Boogeyman 3 (Elastic) – SOC Investigation

This repository contains my detailed investigation and analysis of the "Boogeyman 3" incident response lab from TryHackMe, using Elastic SIEM.

## Overview
A simulated targeted attack on Quick Logistics LLC was analyzed using Elastic Stack to trace the intrusion from phishing to ransomware staging. The investigation covers the full attack chain, including:

- **Initial access** via phishing email with malicious `.hta` payload.
- **Payload execution** and **file implantation** via `xcopy.exe` and `rundll32.exe`.
- **Persistence** through scheduled tasks.
- **Privilege escalation** using `fodhelper.exe`.
- **Credential dumping** with Mimikatz.
- **Lateral movement** via Pass-the-Hash and PowerShell Remoting.
- **Data access** on remote file shares.
- **DCSync attack** on the domain controller.
- **Ransomware staging** via remote file download.

## Skills Demonstrated
- Threat hunting in **Elastic SIEM (Kibana)**
- Querying logs using **KQL** and **Lucene**
- Analyzing **Windows event logs** and process creation events
- Identifying **LOLBins** and common attacker tradecraft
- Mapping attack steps to **MITRE ATT&CK**

## Tools & Technologies
Elastic SIEM, Kibana, Windows Event Logs, PowerShell, Mimikatz
