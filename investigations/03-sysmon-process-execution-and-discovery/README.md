# Investigation 03 — Sysmon Process Execution and Discovery

## Executive Summary

This investigation examined process creation on a Windows 11 endpoint using Microsoft Sysmon Event ID 1 and Wazuh. Controlled commands were executed to identify the current user, computer, network configuration, local accounts, administrator group membership, and account policies.

Process identifiers and process GUIDs were correlated to reconstruct parent-child relationships. Wazuh evidence confirmed that a PowerShell process launched Command Prompt, which launched multiple discovery commands. One of these commands, `net localgroup Administrators`, also created a `net1.exe` child process.

Wazuh classified the captured administrator-group discovery event as **Discovery activity executed**, Rule 92031, level 3, with MITRE ATT&CK technique T1087 (Account Discovery).

**Final disposition:** Benign / Authorized Testing

---

## Investigation Objective

Identify the processes and commands executed on the endpoint, correlate related process instances, evaluate Wazuh's detection classification, and distinguish recorded endpoint activity from SIEM alerts.

## Lab Environment

| Component | Role |
|---|---|
| Windows 11 Pro VM | Monitored endpoint |
| Microsoft Sysmon | Process creation telemetry |
| Windows Event Viewer | Local endpoint evidence |
| Wazuh Agent | Collects Sysmon events |
| Ubuntu Server VM | Hosts Wazuh |
| Wazuh Dashboard | SIEM alert review and correlation |
| VMware Fusion | Virtualization |

The Sysmon event channel examined was `Microsoft-Windows-Sysmon/Operational`. The investigation used Sysmon's default configuration and Wazuh's existing detection rules and alert threshold.

---

## 1. Review Endpoint Process Creation

The first controlled test generated the following commands from Command Prompt. Event Viewer recorded each as Sysmon **Event ID 1 — Process Create**.

| Command | Purpose | Logged time (endpoint display, Nov 24, 2026) |
|---|---|---|
| `whoami` | Identify the current user | 1:49:34 PM |
| `hostname` | Identify the computer | 1:49:39 PM |
| `ipconfig /all` | Obtain network configuration | 1:49:44 PM |
| `net user` | Enumerate local user accounts | 1:49:47 PM |
| `notepad.exe` | Launch Notepad | 1:50:07 PM |

Each captured event contained the same parent information:

| Field | Observed value |
|---|---|
| ParentImage | `C:\Windows\System32\cmd.exe` |
| ParentProcessId | 660 |
| ParentProcessGuid | `{fd61dfed-0669-6b06-1717-000000000600}` |
| User | `DESKTOP-8J27DEL\newth` |
| LogonId | `0x3DFF40D` |
| TerminalSessionId | 4 |
| IntegrityLevel | High |

The matching parent process ID and GUID establish that all five observed process creation events referenced the same Command Prompt instance. High integrity indicates elevated execution, even though some commands do not require administrator privileges.

## 2. Identify the Command Prompt Process in Wazuh

After Sysmon collection was configured in Wazuh, a separate Command Prompt instance was observed in the SIEM. Its process creation event showed:

| Field | Observed value |
|---|---|
| Image | `C:\Windows\System32\cmd.exe` |
| ProcessId | 9244 |
| ProcessGuid | `{fd61dfed-1119-6b06-d417-000000000600}` |
| ParentImage | `powershell.exe` |
| ParentProcessId | 7640 |
| ParentProcessGuid | `{fd61dfed-c9e4-6b00-d20f-000000000600}` |
| Event Record ID | 1273 |
| UTC Time | 2026-11-24 22:35:05.355 |

This event identifies PowerShell as the recorded parent of CMD. PID 9244 is a separate process instance from PID 660 in the earlier Event Viewer test.

## 3. Investigate Discovery Activity in Wazuh

The following process creation events were identified in the Wazuh alert index.

| UTC time (Nov 24, 2026) | Image | Command or action | PID | Parent PID | Event record ID |
|---|---|---|---:|---:|---:|
| 22:35:05.355 | cmd.exe | Launch Command Prompt | 9244 | 7640 | 1273 |
| 22:35:15.777 | net.exe | `net user` | 11776 | 9244 | 1288 |
| 23:04:17.788 | net.exe | `net localgroup Administrators` | 8656 | 9244 | 1508 |
| 23:04:17.834 | net1.exe | `net1 localgroup Administrators` | 10404 | 8656 | 1509 |
| 23:04:21.357 | net.exe | `net accounts` | 3136 | 9244 | 1512 |

The three discovery commands reveal different types of information:

- `net user` — local account enumeration.
- `net localgroup Administrators` — local administrator group membership enumeration.
- `net accounts` — password and account lockout policy information.

All five Wazuh process creation records identify the same user and logon session and show High integrity.

## 4. Correlate Parent-Child Process Relationships

The `ProcessId` and `ProcessGuid` of CMD were compared with the `ParentProcessId` and `ParentProcessGuid` fields of the three `net.exe` events.

The shared parent GUID was:

```text
{fd61dfed-1119-6b06-d417-000000000600}
```

The administrator group discovery event additionally identified `net.exe` as PID 8656, with ProcessGuid:

```text
{fd61dfed-17f1-6b06-4818-000000000600}
```

The `net1.exe` creation event contained that same value as its ParentProcessGuid, with ParentProcessId 8656. This confirms the additional process generation.

### Reconstructed Wazuh process tree

```text
powershell.exe (PID 7640)
└── cmd.exe (PID 9244)
    ├── net.exe (PID 11776) — net user
    ├── net.exe (PID 8656) — net localgroup Administrators
    │   └── net1.exe (PID 10404) — localgroup Administrators
    └── net.exe (PID 3136) — net accounts
```

The process GUID comparison is stronger than relying on the executable name or PID alone, because Windows may reuse process IDs.

## 5. Review Wazuh Detection

The exported Wazuh alert for `net localgroup Administrators` provides the following detection metadata:

| Field | Observed value |
|---|---|
| Agent | Windows11EndpointVM (001) |
| Endpoint IP | 172.16.121.128 |
| Rule ID | 92031 |
| Rule level | 3 |
| Rule description | Discovery activity executed |
| Rule groups | sysmon, sysmon_eid1_detections, windows |
| MITRE ATT&CK ID | T1087 |
| MITRE tactic | Discovery |
| MITRE technique | Account Discovery |
| Decoder | windows_eventchannel |

The MITRE mapping above is the classification assigned by the captured Wazuh rule. It describes discovery behavior, not proof of malicious intent.

## 6. Endpoint Telemetry Versus SIEM Alerts

The earlier endpoint test recorded five child process creation events. During the later Wazuh investigation, searching for the specific CMD parent GUID initially returned the `net user` alert but did not reveal every expected command.

The manager configuration showed:

```xml
<logall>no</logall>
<logall_json>no</logall_json>
<log_alert_level>3</log_alert_level>
```

The alert index therefore cannot be assumed to contain every received event. Missing alerts do not by themselves prove that the agent failed to collect the corresponding telemetry. No raw-event archive was enabled to verify whether the missing events reached the manager.

Instead of changing the alert threshold or enabling full event archiving, additional authorized discovery commands were generated and the existing Wazuh alerts were examined.

### Investigation queries

```text
data.win.system.channel: "Microsoft-Windows-Sysmon/Operational" AND data.win.system.eventID: "1"
data.win.eventdata.processId: "9244"
data.win.eventdata.parentProcessGuid: "{fd61dfed-1119-6b06-d417-000000000600}"
data.win.eventdata.processId: "8656"
data.win.eventdata.parentProcessGuid: "{fd61dfed-17f1-6b06-4818-000000000600}"
```

---

## Analyst Assessment

**Classification:** Benign / Expected Activity

The observed commands were intentionally executed in an authorized lab. They are legitimate administrative utilities but can also be used to discover information during a compromise. Process creation telemetry establishes execution and relationships; it does not independently establish malicious intent or prove that each command successfully returned its intended output.

In an enterprise environment, comparable activity would require validation of the user, execution context, authorization, and surrounding events.

**Disposition:** Closed — Authorized Testing

## Skills Demonstrated

- Sysmon deployment and Windows Event ID 1 analysis
- Wazuh endpoint telemetry integration and alert review
- Process and parent process identification
- PID and process GUID correlation
- Multi-generation process tree reconstruction
- Account and group discovery analysis
- MITRE ATT&CK rule interpretation
- Distinguishing endpoint telemetry from SIEM alerts
- Evidence-based technical documentation

## Evidence Captured

[Evidence register and observed event fields](evidence/README.md) — transcription of the original Event Viewer screenshots, Wazuh screenshots, and exported Wazuh alert document.

## Conclusion

This investigation demonstrated how process creation telemetry can be used to reconstruct execution relationships and identify discovery activity in a SIEM. It also established the importance of distinguishing the endpoint's event log from the SIEM's alert index.
