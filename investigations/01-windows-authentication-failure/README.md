# Investigation 01 — Windows Authentication Failure

## Executive Summary

This investigation validates the endpoint-to-SIEM monitoring pipeline in the SOC Analyst lab by generating controlled failed logon attempts against a local Windows 11 account and tracing the resulting security telemetry through Windows Event Viewer and Wazuh.

The Windows endpoint generated **Security Event ID 4625** for failed authentication attempts against the local account `TestUser`. The Wazuh agent collected the Windows Security events, forwarded them to the Wazuh server, and triggered **Wazuh Rule 60122 — "Logon Failure - Unknown user or bad password."**

Six matching Wazuh alerts were identified and reviewed.

**Final disposition:** Benign / Authorized Testing

---

## Investigation Objective

Confirm that a SOC analyst can trace a known authentication event through the complete monitoring workflow:

```text
Failed logon attempt
        ↓
Windows Security Event Log
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Wazuh Detection Rule
        ↓
Wazuh Dashboard
        ↓
Analyst Triage and Assessment
```

---

## Lab Environment

| Component | Role |
|---|---|
| Windows 11 Pro VM | Monitored endpoint |
| Wazuh Agent v4.14.10 | Endpoint telemetry collection |
| Ubuntu Server VM | Wazuh server |
| Wazuh Manager | Event analysis and rule evaluation |
| Wazuh Indexer | Security-event storage and search |
| Wazuh Dashboard | SIEM investigation and alert triage |
| VMware Fusion | Virtualized lab environment |

---

## Test Scenario

A local Windows account named `TestUser` was used to generate controlled authentication failures.

Several incorrect passwords were intentionally entered at the Windows sign-in screen. The activity was performed inside an isolated, personally owned lab environment.

This created a known event that could be followed from the endpoint through the SIEM.

---

## Detection Summary

| Field | Observed Value |
|---|---|
| Endpoint | `Windows11EndpointVM` |
| Windows Event ID | **4625** |
| Target Account | `TestUser` |
| Target Domain | `DESKTOP-8J27DEL` |
| Logon Type | **2 — Interactive** |
| Source Address | `127.0.0.1` |
| Authentication Package | `Negotiate` |
| Logon Process | `User32` |
| Failure Reason | Unknown user name or bad password |
| Wazuh Rule | **60122** |
| Wazuh Rule Level | **5** |
| Wazuh Alerts Observed | **6** |
| Analyst Disposition | **Benign / Authorized Testing** |

---

## 1. Verify Windows Logon Auditing

Windows auditing was checked from an Administrator PowerShell session:

```powershell
auditpol /get /subcategory:"Logon"
```

The policy showed:

```text
Logon    Success and Failure
```

This confirmed that the endpoint was configured to record both successful and failed logon activity.

---

## 2. Validate the Endpoint Event

The Windows Security log was queried for failed logons:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-30)} |
Select-Object TimeCreated, Id, Message
```

Multiple **Event ID 4625** entries were returned.

Event Viewer was then filtered for Event ID 4625, confirming that the failed authentication attempts were present in the local Windows Security log and associated with `TestUser`.

![Windows Event Viewer filtered for Event ID 4625](evidence/windows-event-viewer-4625.webp)

*Windows Event Viewer confirming failed logon events for the local test account.*

### Endpoint Finding

The evidence confirmed that the event existed **before** Wazuh processing. This separated endpoint logging from SIEM collection and helped isolate the monitoring pipeline during troubleshooting.

---

## 3. Verify Wazuh Security-Log Collection

The Windows Wazuh agent configuration was checked to verify that the Security event channel was enabled:

```xml
<localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
</localfile>
```

This confirmed that the Wazuh agent was configured to collect Windows Security Event Log data.

---

## 4. Locate the SIEM Alert

The Wazuh Threat Hunting interface was searched for the authentication-related rules:

```text
rule.id:(60122 OR 60204)
```

The search returned **six alerts**, all associated with:

```text
Rule ID: 60122
Rule Level: 5
Description: Logon Failure - Unknown user or bad password
Agent: Windows11EndpointVM
```

The endpoint event had therefore successfully traveled through the monitoring pipeline and become searchable SIEM telemetry.

![Wazuh Threat Hunting showing Rule 60122 alerts](evidence/wazuh-rule-60122-alerts.webp)

*Wazuh Threat Hunting showing six Rule 60122 failed-logon alerts from Windows11EndpointVM.*

---

## 5. Analyze the Alert

The Wazuh document details provided additional context about the authentication failure.

![Wazuh event details showing TestUser and Event ID 4625](evidence/wazuh-document-details-4625.webp)

*Wazuh document details correlating the target account, endpoint, Security channel, and Windows Event ID 4625.*

### Target Account

```text
TestUser
```

### Windows Event

```text
Event ID: 4625
Channel: Security
```

### Logon Type

```text
2
```

**Logon Type 2** represents an interactive logon. This is consistent with the controlled sign-in attempt performed locally at the Windows endpoint.

### Source Address

```text
127.0.0.1
```

`127.0.0.1` is the IPv4 loopback address. Combined with Logon Type 2, the evidence is consistent with a local authentication attempt rather than a remote network login.

### Failure Information

```text
Failure reason: Unknown user name or bad password
Status: 0xC000006D
Substatus: 0xC000006A
```

The failure information is consistent with the intentionally incorrect password used during the test.

---

## Event Correlation

The investigation correlated three views of the same activity:

```text
Known analyst action
        ↓
Windows Event ID 4625
        ↓
Wazuh Rule 60122
```

The shared account, host, event type, and timing allowed the endpoint evidence to be correlated with the centralized SIEM alert.

---

## Timestamp Observation

A time difference was observed between timestamps displayed by Windows and the Wazuh dashboard.

The underlying Windows event data included a UTC system timestamp, while the interfaces displayed timestamps using different local/time-zone interpretations.

This became an additional troubleshooting lesson: **timestamp normalization and time-zone awareness are important when correlating security events across multiple systems.**

---

## MITRE ATT&CK Context

Wazuh included MITRE ATT&CK metadata with the alert.

Automated ATT&CK mappings provide useful context, but they do not replace analyst validation. In this investigation, the activity was a controlled local password-failure test and did not demonstrate a real malicious account-access-removal event.

This reinforces an important SOC principle:

> A detection rule or framework mapping is evidence to evaluate, not a conclusion to accept automatically.

---

## Analyst Assessment

### Classification

**Benign / Expected Activity**

### Rationale

The failed authentication attempts were intentionally generated as part of an authorized lab exercise. The evidence matched the known test activity:

- Expected endpoint
- Expected test account
- Interactive logon type
- Local loopback source
- Expected failed-password condition

There was no evidence in this scenario of unauthorized remote access or malicious activity.

### Disposition

**Closed — Authorized Testing**

---

## Skills Demonstrated

- Security Information and Event Management (**SIEM**)
- SOC alert triage
- Windows Security Event Log analysis
- Windows Event ID 4625 investigation
- Authentication monitoring
- Endpoint telemetry analysis
- Wazuh Threat Hunting
- Wazuh rule analysis
- Event correlation
- PowerShell event-log querying
- Detection validation
- Incident classification
- Timestamp/time-zone troubleshooting
- Technical incident documentation

---

## Evidence Captured

The `evidence/` directory contains the screenshots used directly in the investigation:

- [Windows Event Viewer — Event ID 4625](evidence/windows-event-viewer-4625.webp)
- [Wazuh Threat Hunting — Rule 60122](evidence/wazuh-rule-60122-alerts.webp)
- [Wazuh Event ID 4625 document details](evidence/wazuh-document-details-4625.webp)

These images are stored as WebP files so they render directly in the GitHub investigation. Credential-bearing setup material is excluded from the public evidence set.

---

## Conclusion

The first investigation successfully validated the complete Windows endpoint-to-Wazuh SIEM workflow.

The lab demonstrated that a controlled authentication failure could be generated, recorded locally, collected by the Wazuh agent, analyzed by the Wazuh manager, indexed, detected by a Wazuh rule, and triaged through the browser-based dashboard.

This establishes the baseline monitoring environment for future SOC investigations involving richer endpoint and network telemetry.
