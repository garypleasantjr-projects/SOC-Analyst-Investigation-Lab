# SOC Analyst Investigation Lab

## Overview

This repository documents my hands-on **Security Operations Center (SOC) Analyst lab** focused on developing practical experience with **SIEM monitoring, security alert triage, log analysis, endpoint security monitoring, event correlation, incident investigation, and incident response fundamentals**.

The lab uses **Wazuh as a Security Information and Event Management (SIEM) platform**, with a monitored **Windows 11 endpoint** and an **Ubuntu Server** hosting the centralized Wazuh security infrastructure.

The objective of this project is to move beyond theoretical cybersecurity knowledge by generating controlled security events, collecting endpoint telemetry, investigating alerts, analyzing evidence, and documenting findings using workflows similar to those performed by SOC analysts.

As the lab develops, this repository will contain multiple security investigations involving authentication activity, Windows security events, endpoint telemetry, network activity, and other SOC-focused scenarios.

---

## SOC Skills Demonstrated

This project is designed to develop and demonstrate practical experience in:

- **Security Information and Event Management (SIEM)**
- **SOC Alert Triage**
- **Security Event Monitoring**
- **Windows Security Event Log Analysis**
- **Endpoint Monitoring**
- **Log Analysis**
- **Authentication Monitoring**
- **Security Event Correlation**
- **Incident Investigation**
- **Incident Response Fundamentals**
- **Threat Detection and Analysis**
- **MITRE ATT&CK Interpretation**
- **Network Security Monitoring**
- **Security Telemetry Analysis**
- **PowerShell**
- **Windows and Linux Administration**
- **Virtualized Security Lab Environments**
- **Technical Incident Documentation**

---

## Lab Architecture

```text
                    SOC Analyst
                         |
                         v
                  Wazuh Dashboard
                         |
                         v
                   Wazuh Indexer
                         |
                         v
                   Wazuh Manager
                         |
                 Ubuntu Server VM
                         ^
                         |
                  Security Events
                         |
                    Wazuh Agent
                         |
                         ^
                Windows 11 Pro VM
                Monitored Endpoint
```

### Monitored Endpoint

**Windows 11 Pro**

The Windows virtual machine acts as the monitored enterprise-style endpoint.

The Wazuh agent collects supported endpoint and security telemetry from the system and forwards relevant events to the centralized Wazuh infrastructure for analysis.

Current monitoring includes the **Windows Security Event Log**, allowing authentication and other Windows security activity to be investigated through the SIEM.

### SIEM Infrastructure

**Ubuntu Server + Wazuh**

The Ubuntu Server virtual machine hosts the centralized Wazuh environment:

- **Wazuh Manager** — analyzes incoming security telemetry and applies detection rules.
- **Wazuh Indexer** — stores and indexes security event data.
- **Wazuh Dashboard** — provides the browser-based interface used for alert triage, event searching, and security investigations.

---

## Investigation Workflow

The general SOC workflow used throughout this repository is:

```text
Controlled Security Activity
          |
          v
Endpoint Generates Telemetry
          |
          v
Windows / System Logs
          |
          v
Wazuh Agent
          |
          v
Wazuh Manager
          |
          v
Detection Rule / Alert
          |
          v
SIEM Investigation
          |
          v
Evidence Correlation
          |
          v
Analyst Assessment
          |
          v
Incident Classification / Disposition
          |
          v
Investigation Documentation
```

Each investigation is intended to answer questions commonly encountered during SOC alert triage:

- **What happened?**
- **When did it happen?**
- **Which user, host, process, or IP address was involved?**
- **What evidence supports the alert?**
- **Was the activity expected, suspicious, or malicious?**
- **Does the activity require escalation?**
- **What response or remediation would be appropriate?**

---

## Current Investigations

### 01 — Windows Authentication Failure Investigation

The first investigation examines intentionally generated failed authentication attempts against a local Windows account.

The investigation includes:

- Windows **Security Event ID 4625**
- Failed authentication analysis
- Wazuh alert detection
- **Wazuh Rule 60122**
- Account and host identification
- Logon type analysis
- Source-address analysis
- SIEM event correlation
- Alert classification
- Incident disposition

The controlled activity was successfully detected by Wazuh and investigated through the SIEM dashboard.

**Disposition:** Benign / Authorized Testing

---

## Tools & Technologies

| Category | Technology |
|---|---|
| SIEM / Security Monitoring | Wazuh |
| Endpoint | Windows 11 Pro |
| Server | Ubuntu Server |
| Virtualization | VMware Fusion |
| Windows Logging | Windows Security Event Log |
| Administration / Investigation | PowerShell |
| Networking | TCP/IP |
| Security Framework | MITRE ATT&CK |
| Version Control / Documentation | Git & GitHub |

---

## Current Lab Capabilities

The environment currently provides a working endpoint-to-SIEM monitoring pipeline:

```text
Windows Endpoint
      ↓
Security Event Generation
      ↓
Windows Security Event Log
      ↓
Wazuh Agent
      ↓
Wazuh Manager
      ↓
Detection Rules
      ↓
Wazuh Indexer
      ↓
Wazuh Dashboard
      ↓
SOC Investigation
```

The first investigation has validated that Windows authentication failures can be generated, collected, transmitted, detected, searched, and analyzed through the environment.

---

## Repository Goals

This repository will expand as additional SOC investigations are completed.

Future investigations will build on the current SIEM environment and introduce additional forms of endpoint and network telemetry while maintaining a focus on:

- Alert triage
- Evidence-based analysis
- Event correlation
- Threat detection
- Incident investigation
- Analyst decision-making
- Clear technical documentation

The goal is not simply to generate alerts, but to understand **why an alert occurred, what the underlying evidence shows, and how a SOC analyst should respond to it**.

---

## Disclaimer

All security activity documented in this repository is performed within an isolated, personally owned virtual lab environment for educational and defensive cybersecurity purposes.

No testing is performed against systems without authorization.
