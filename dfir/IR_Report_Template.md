# Incident Response Report: Operation PurpleLock (Simulated Ransomware Incident)

| Incident Reference | IR-2026-1025-01 | Incident Classification | High / Ransomware Impact |
| :--- | :--- | :--- | :--- |
| **Lead Investigator** | Vemula Moksha | **Target Scope** | `WS01.corp.purpleforge.local` (10.10.10.20) |
| **First Event Time** | 2026-10-25 03:10:00 UTC | **Containment Time** | 2026-10-25 03:11:42 UTC |
| **MTTD** | 38 seconds | **MTTR** | 64 seconds |
| **Case Status** | Contained & Remediated | **DFIR-IRIS Case ID** | `IRIS-2026-0042` |

---

## 1. Executive Summary

On October 25, 2026 at 03:10:00 UTC, the PurpleForge automated purple team platform initiated a simulated ransomware attack against workstation `WS01.corp.purpleforge.local`. The attack chain emulated an adversary establishing execution via PowerShell, inhibiting system recovery through Volume Shadow Copy deletion (`T1490`), and executing mass file encryption across 200 financial records (`T1486`).

Within **38 seconds** of the initial Volume Shadow Copy deletion, OpenSearch Alerting monitors triggered high-fidelity alerts based on compiled Sigma rules `win_vssadmin_shadowcopy_delete.yml` and `win_ransomware_mass_file_rename.yml`. 

The Shuffle SOAR automation engine processed the alert, queried Threat Intelligence sources (VirusTotal, AbuseIPDB, Shodan), calculated a composite risk score of **94/100 (CRITICAL)**, and alerted the on-duty security analyst via an interactive approval gate. Upon approval, Wazuh Active Response executed `custom_active_response_isolate.cmd` on `WS01`, isolating the host via Windows Advanced Firewall rules in **64 seconds**. 

Velociraptor automatically acquired KAPE triage targets and physical memory for Volatility 3 deep-dive forensic analysis. No lateral movement or data exfiltration to external domains occurred.

---

## 2. Attack Execution Timeline

| Timestamp (UTC) | Source / Component | Event Description | MITRE Technique | Telemetry Channel |
| :--- | :--- | :--- | :--- | :--- |
| **03:10:00** | Adversary (`CORP\redteam`) | PowerShell cradle downloads payload to `$env:TEMP\beacon.exe`. | `T1059.001` / `T1105` | Sysmon EID 1 / PS 4104 |
| **03:10:15** | Adversary (`CORP\redteam`) | Inhibit System Recovery: `vssadmin.exe delete shadows /all /quiet`. | `T1490` | Sysmon EID 1 (Parent: `powershell.exe`) |
| **03:10:25** | Adversary (`CORP\redteam`) | Mass file encryption of 200 documents in `C:\Users\Public\Documents\Finance_Share`. Extension changed to `.purplelocked`. | `T1486` | Sysmon EID 11 / EID 1 |
| **03:10:35** | Adversary (`CORP\redteam`) | Ransom note `README_DECRYPT.txt` dropped in target share. | `T1486` | Sysmon EID 11 |
| **03:10:38** | OpenSearch Alerting | Monitor `PurpleForge - T1490 Shadow Copy Delete` and `T1486 Ransomware` trigger webhook. | Detection Gate | `wazuh-archives-*` Index |
| **03:10:48** | Shuffle SOAR | Field normalization complete; VirusTotal and AbuseIPDB queries dispatched. | Threat Intel Node | SOAR Ingestion |
| **03:10:55** | Shuffle SOAR | Risk Score calculated: **94.0 / 100 (CRITICAL)**. | Risk Engine | `risk_score_calculator.py` |
| **03:11:15** | SOC Analyst | Slack/Discord Interactive Approval Gate: Analyst reviews evidence and clicks **[APPROVE ISOLATION]**. | Human Gate | SOAR Slack Node |
| **03:11:42** | Wazuh Active Response | `isolate-host.cmd` executes on `WS01`. All network ports blocked except SECOPS IP (`100.64.0.10`). | Active Response | Wazuh Agent (`001`) |
| **03:12:00** | Velociraptor | Hunt `PurpleForge_Incident_Triage_Hunt` dispatched. KAPE triage files and memory dump acquired. | Forensic Triage | Velociraptor Client |
| **03:15:30** | Volatility 3 | Automated memory triage (`windows.pslist`, `windows.cmdline`, `windows.malfind`) confirms process termination and memory bounds. | Deep Forensics | `volatility3_triage.sh` |

---

## 3. Root Cause Analysis (RCA)

1. **Initial Vector:** A simulated initial execution via PowerShell script block utilizing an unapproved external download cradle.
2. **Defensive Posture Failure:** In the un-tuned v1 baseline, `vssadmin.exe` execution was often dismissed as backup administrative maintenance, and file rename events were lost due to absence of Sysmon Event ID 11 ingestion in SIEM.
3. **Detection Breakthrough:** The tuned v2 DaC Sigma rule `win_vssadmin_shadowcopy_delete.yml` specifically filtered out legitimate backup software service accounts (e.g., `VeeamBackup`, `SYSTEM` running during scheduled backup windows) while triggering immediately on interactive command shells (`powershell.exe`, `cmd.exe`) executing shadow deletion commands.

---

## 4. Volatility 3 Memory Forensics Evidence

Memory analysis conducted on `WS01_memory.raw` using Volatility 3 revealed the following evidence:

### A. Process Tree & Command Line Execution (`windows.cmdline`)
```text
PID: 1040 | Process: powershell.exe | PPID: 872
CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File C:\temp\ransom_sim.ps1

PID: 2184 | Process: vssadmin.exe | PPID: 1040
CommandLine: "vssadmin.exe" delete shadows /all /quiet

PID: 3412 | Process: cmd.exe | PPID: 1040
CommandLine: "cmd.exe" /c echo PURPLEFORGE_LOCK > README_DECRYPT.txt
```

### B. Injected Memory Artifacts (`windows.malfind`)
Analysis of `windows.malfind` detected suspicious VAD allocations marked with `PAGE_EXECUTE_READWRITE` permissions inside PID `1040` containing standard reflective DLL loader stubs (`MZ` header present at base memory offset `0x1e490000`).

---

## 5. Indicators of Compromise (IOCs)

| IOC Type | Value / Description | Attribution / Purpose |
| :--- | :--- | :--- |
| **SHA256** | `44d88612fea8a8f36de82e1278abb02f1a23847589dbe829ef11200192ab3450` | Simulated Ransomware Binary |
| **IPv4** | `198.51.100.45` | Adversary Staging Server / C2 |
| **Port** | `8443 / TCP` | Non-Browser C2 Communication Port |
| **File Path** | `C:\Users\Public\Documents\Finance_Share\*.purplelocked` | Encrypted Ransomware Canary Files |
| **File Path** | `C:\Users\Public\Documents\Finance_Share\README_DECRYPT.txt` | Ransomware Dropped Note |
| **Registry** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\PurpleForgeTestKey` | Simulated Persistence Run Key |

---

## 6. Containment & Remediation Actions

1. **Automated Containment:** Host network isolation enforced via Windows Firewall (`netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound`) within 64 seconds of alert generation.
2. **Management Access Retention:** Wazuh Agent and Velociraptor maintained connectivity via dedicated firewall rules allowing traffic to the `SECOPS` Tailscale IP (`100.64.0.10`).
3. **Sandbox Recovery:** Canary files reverted and sanitized using `python scripts/emulation/ransomware_simulator_safe.py --cleanup`.
4. **Threat Intelligence Dissemination:** All IOCs automatically formatted and pushed to MISP community via Shuffle SOAR MISP node.

---

## 7. Lessons Learned & Detection Engineering Tuning (v1 -> v2)

| Issue Identified in v1 Baseline | Detection Engineering Fix in v2 DaC | Verification Metric |
| :--- | :--- | :--- |
| High alert volume from legitimate IT backup software using `vssadmin` or WMI. | Added `filter_legitimate_backup` checking for verified backup executables and machine service accounts. | **0 False Positives** in 14-day observation window. |
| Ingestion delay of Sysmon FileCreate events into OpenSearch. | Enabled `logall_json` in Wazuh manager and tuned Filebeat flush interval to 1 second. | MTTD reduced from **184.5s** down to **38.4s**. |
| Alert fatigue causing analyst delays during manual Slack triaging. | Added automated TI enrichment (VT, AbuseIPDB, Shodan) and composite risk scoring directly in notification body. | MTTR reduced from **40.8 minutes** down to **64 seconds**. |
