# SOC Analyst Investigation Lab

## Overview

This repository documents my hands-on **Security Operations Center (SOC) Analyst lab**, where I am building practical experience with **SIEM monitoring, alert triage, Windows security logs, endpoint telemetry, event correlation, threat detection, and incident investigation**.

The lab uses **Wazuh** as the SIEM platform, a **Windows 11 Pro virtual machine** as the monitored endpoint, and an **Ubuntu Server virtual machine** as the centralized Wazuh server.

The purpose of this project is to practice the full SOC investigation process:

```text
Generate activity
      ↓
Collect security telemetry
      ↓
Detect and review alerts
      ↓
Analyze event data
      ↓
Correlate evidence
      ↓
Determine what happened
      ↓
Classify and document the incident
```

Each investigation in this repository focuses on a specific security scenario and documents the evidence, analysis, findings, and analyst conclusion.

---

## Lab Environment

### Windows 11 Endpoint

The Windows 11 Pro VM acts as the monitored endpoint.

The **Wazuh Agent** collects security telemetry from the system, including Windows Security Event Log activity, and forwards it to the centralized Wazuh infrastructure.

### Ubuntu Wazuh Server

The Ubuntu Server VM hosts the Wazuh security stack:

- **Wazuh Manager** — analyzes incoming security events and applies detection rules
- **Wazuh Indexer** — stores and indexes security telemetry
- **Wazuh Dashboard** — provides the browser-based interface used for alert triage and investigation

### Architecture

```text
Windows 11 Pro Endpoint
        |
        | Security Events
        v
     Wazuh Agent
        |
        v
   Wazuh Manager
        |
        v
   Wazuh Indexer
        |
        v
  Wazuh Dashboard
        |
        v
   SOC Investigation
```

---

## SOC Analyst Skills

This lab is focused on developing practical experience with:

- **Security Information and Event Management (SIEM)**
- **Security Monitoring**
- **SOC Alert Triage**
- **Windows Security Event Logs**
- **Endpoint Telemetry**
- **Log Analysis**
- **Authentication Monitoring**
- **Event Correlation**
- **Threat Detection**
- **Incident Investigation**
- **Incident Response Fundamentals**
- **MITRE ATT&CK**
- **PowerShell**
- **Windows Administration**
- **Linux Administration**
- **Network Security Analysis**
- **Technical Incident Documentation**

---

## Investigation Methodology

Each investigation follows a structured SOC workflow.

### 1. Generate Controlled Activity

Security-related activity is intentionally generated inside the isolated lab environment.

### 2. Identify Endpoint Evidence

Relevant Windows or system logs are reviewed to determine what telemetry was generated.

### 3. Review SIEM Alerts

Wazuh is used to identify detection rules, alert severity, affected accounts, hosts, processes, IP addresses, and other relevant fields.

### 4. Correlate Evidence

Events are compared using information such as:

- Timestamps
- User accounts
- Hostnames
- Source and destination IP addresses
- Event IDs
- Processes
- Authentication methods
- Detection rules

### 5. Perform Analyst Assessment

The activity is classified based on the available evidence.

Possible dispositions include:

```text
Benign
Expected Activity
Suspicious
Malicious
Needs Further Investigation
Needs Escalation
```

### 6. Document Findings

Each investigation records the scenario, evidence, analysis, conclusion, and recommended response.

---

## Current Investigations

### [Investigation 01 — Windows Authentication Failure](investigations/01-windows-authentication-failure/README.md)

The first completed investigation focuses on failed local authentication attempts against a Windows endpoint.

The investigation includes:

- Windows Security Event ID **4625**
- Failed password attempts
- Local account activity
- Interactive logon analysis
- Wazuh Rule **60122**
- SIEM alert review
- Endpoint and account identification
- Source-address analysis
- Timestamp correlation
- Analyst classification

The activity was intentionally generated within the lab and successfully detected by Wazuh.

**Final disposition:** Authorized Testing / Benign Activity

### [Investigation 02 — Remote SSH Authentication and Privilege Change](investigations/02-remote-ssh-authentication-privilege-change/README.md)

The second investigation focuses on remote SSH authentication against the Windows endpoint and the security events generated when the test account was later added to the local Administrators group.

The investigation includes:

- Failed and successful SSH authentication
- Windows Security Event ID **4624**
- OpenSSH source-address evidence
- Windows Security Event ID **4732**
- Windows Security Event ID **4672**
- Windows Security Event ID **4738**
- Authentication versus authorization
- Privilege-change correlation
- Wazuh SIEM analysis

**Final disposition:** Authorized Testing / Benign Activity

### [Investigation 03 — Sysmon Process Execution and Discovery](investigations/03-sysmon-process-execution-and-discovery/README.md)

The third investigation focuses on Sysmon process creation telemetry, parent-child process correlation, and discovery activity detected in Wazuh.

The investigation includes:

- Sysmon Event ID **1**
- Process IDs and process GUIDs
- Multi-generation process tree reconstruction
- Local account, administrator group, and account policy discovery
- Wazuh Rule **92031**, level **3**
- MITRE ATT&CK **T1087** (Wazuh rule mapping)
- Endpoint telemetry versus SIEM alerts

**Final disposition:** Authorized Testing / Benign Activity

---

## Technologies

| Area | Technology |
|---|---|
| SIEM | Wazuh |
| Endpoint | Windows 11 Pro |
| Server | Ubuntu Server |
| Virtualization | VMware Fusion |
| Windows Logging | Windows Security Event Log, Sysmon |
| Investigation | Wazuh Dashboard |
| Administration | PowerShell |
| Networking | TCP/IP |
| Security Framework | MITRE ATT&CK |
| Documentation | GitHub |

---

## Repository Structure

As the project grows, investigations will be organized individually.

```text
SOC-Analyst-Investigation-Lab/
│
├── README.md
├── .gitignore
│
├── investigations/
│   ├── 01-windows-authentication-failure/
│   │   └── README.md
│   ├── 02-remote-ssh-authentication-privilege-change/
│   │   └── README.md
│   └── 03-sysmon-process-execution-and-discovery/
│       ├── README.md
│       └── evidence/
│
└── screenshots/
```

Each investigation will contain its own documentation and supporting evidence.

---

## Project Goals

The goal of this repository is to build practical SOC Analyst experience by repeatedly working through realistic security-monitoring scenarios.

Future investigations will expand into additional areas such as:

- Windows endpoint activity
- Sysmon telemetry
- Authentication monitoring
- Process analysis
- Network connections
- SSH activity
- Suspicious account behavior
- Security event correlation

The focus of the project is not only detecting alerts, but understanding the underlying evidence and making an informed analyst decision.

---

## Disclaimer

All activity in this repository is performed within an isolated, personally owned virtual lab environment for educational and defensive cybersecurity purposes.

No testing is performed against systems without authorization.
