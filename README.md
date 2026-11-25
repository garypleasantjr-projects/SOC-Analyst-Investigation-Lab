# SOC Analyst Investigation Lab

## Overview

This hands-on SOC lab uses Wazuh to monitor a Windows 11 endpoint, investigate security alerts, and correlate evidence from Windows event logs and Sysmon. Each investigation documents the activity, supporting evidence, findings, and final analyst assessment.

## Completed Investigations

| Investigation | Focus | Key Evidence |
|---|---|---|
| [01 — Windows Authentication Failure](investigations/01-windows-authentication-failure/README.md) | Failed local authentication and alert analysis | Windows Event ID 4625, Wazuh Rule 60122 |
| [02 — Remote SSH Authentication and Privilege Change](investigations/02-remote-ssh-authentication-privilege-change/README.md) | Remote authentication, administrator group membership, and account modification | OpenSSH logs, Windows Event IDs 4624, 4732, 4672, 4738 |
| [03 — Sysmon Process Execution and Discovery](investigations/03-sysmon-process-execution-and-discovery/README.md) | Process creation, parent-child correlation, and account discovery | Sysmon Event ID 1, process GUIDs, Wazuh Rule 92031, MITRE ATT&CK T1087 |

All three investigations were conducted as authorized testing and classified as benign activity. Each linked report includes its supporting evidence.

## Lab Environment

| Component | Technology |
|---|---|
| Monitored endpoint | Windows 11 Pro |
| Endpoint telemetry | Windows Event Logs, Microsoft Sysmon, OpenSSH |
| SIEM server | Ubuntu Server |
| SIEM platform | Wazuh Manager, Indexer, and Dashboard |
| Virtualization | VMware Fusion |
| Administration | PowerShell, Command Prompt, Linux terminal |

### Architecture

```text
Windows 11 Pro
  ├── Windows Event Logs
  ├── Sysmon
  └── OpenSSH logs
          ↓
     Wazuh Agent
          ↓
     Wazuh Manager
          ↓
     Wazuh Indexer
          ↓
     Wazuh Dashboard
```

## Skills Demonstrated

- SIEM deployment, endpoint monitoring, and alert triage
- Windows authentication and privilege-change analysis
- Remote SSH authentication and source-address correlation
- Sysmon process creation and parent-child process analysis
- Event ID, process ID, and process GUID correlation
- MITRE ATT&CK classification and detection rule interpretation
- Windows, Linux, and network troubleshooting
- Evidence-based investigation and technical documentation

## Investigation Workflow

```text
Generate controlled activity
          ↓
Review endpoint telemetry and SIEM alerts
          ↓
Correlate evidence and assess activity
          ↓
Classify and document findings
```

## Planned Expansion

- Active Directory and domain authentication
- Domain account lockout and group membership investigations
- Sysmon network connection telemetry
- Multi-system security event correlation

## Disclaimer

All activity is conducted within an isolated, personally owned virtual lab for educational and defensive cybersecurity purposes. No testing is performed against systems without authorization.
