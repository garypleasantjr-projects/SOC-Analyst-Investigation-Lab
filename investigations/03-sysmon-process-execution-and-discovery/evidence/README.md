# Evidence Register — Investigation 03

The following entries transcribe relevant fields from the original evidence captured on November 24, 2026. These entries are transcriptions of the evidence images in this directory, not exported event JSON.

## E01–E05 — Windows Event Viewer

Source: five Sysmon Operational screenshots (2:07:56, 2:08:50, 2:09:23, 2:09:47 and 2:11:18 PM screenshot filenames).

All five show Event ID 1, parent image `C:\Windows\System32\cmd.exe`, parent PID 660, parent GUID `{fd61dfed-0669-6b06-1717-000000000600}`, user `DESKTOP-8J27DEL\newth`, logon ID `0x3DFF40D`, terminal session ID 4 and High integrity.

| Evidence | CommandLine | Logged time |
|---|---|---|
| E01 | whoami | 1:49:34 PM |
| E02 | hostname | 1:49:39 PM |
| E03 | ipconfig /all | 1:49:44 PM |
| E04 | net user | 1:49:47 PM |
| E05 | notepad.exe | 1:50:07 PM |

## E06–E10 — Wazuh process creation events

Source: Wazuh event detail screenshots and Wazuh3.pdf (three-page export). All records below are Sysmon Event ID 1 on DESKTOP-8J27DEL. GUIDs are reproduced from the evidence.

| Evidence | Record ID | Image | Process ID | Process GUID | Parent ID | Parent GUID |
|---|---:|---|---:|---|---:|---|
| E06 | 1273 | cmd.exe | 9244 | fd61dfed-1119-6b06-d417-000000000600 | 7640 | fd61dfed-c9e4-6b00-d20f-000000000600 |
| E07 | 1288 | net.exe | 11776 | fd61dfed-1123-6b06-dc17-000000000600 | 9244 | fd61dfed-1119-6b06-d417-000000000600 |
| E08 | 1508 | net.exe | 8656 | fd61dfed-17f1-6b06-4818-000000000600 | 9244 | fd61dfed-1119-6b06-d417-000000000600 |
| E09 | 1509 | net1.exe | 10404 | fd61dfed-17f1-6b06-4918-000000000600 | 8656 | fd61dfed-17f1-6b06-4818-000000000600 |
| E10 | 1512 | net.exe | 3136 | fd61dfed-17f5-6b06-4a18-000000000600 | 9244 | fd61dfed-1119-6b06-d417-000000000600 |

| Evidence | Original source | UTC time | Command |
|---|---|---|---|
| E06 | Wazuh CMD screenshot | 22:35:05.355 | cmd.exe |
| E07 | Wazuh NET screenshot | 22:35:15.777 | net user |
| E08 | Wazuh3.pdf, pp. 1–3 | 23:04:17.788 | net localgroup Administrators |
| E09 | Wazuh NET1 screenshot | 23:04:17.834 | net1 localgroup Administrators |
| E10 | Wazuh NET accounts screenshot | 23:04:21.357 | net accounts |

## E08 — Exported Wazuh detection metadata

Wazuh3.pdf, page 3:

```text
decoder.name: windows_eventchannel
rule.description: Discovery activity executed
rule.id: 92031
rule.level: 3
rule.groups: sysmon, sysmon_eid1_detections, windows
rule.mitre.id: T1087
rule.mitre.tactic: Discovery
rule.mitre.technique: Account Discovery
```

The event metadata on pages 1–2 identifies agent 001, Windows11EndpointVM, process ID 8656 and parent process ID 9244. Its ProcessGuid matches the ParentProcessGuid in E09.

## Evidence scope

The first five entries belong to CMD PID 660. The later Wazuh entries belong to the distinct CMD PID 9244 execution tree. They must not be merged into a single process instance. No command output or complete raw-event archive was captured in these records.

## Evidence images

- [01-event-viewer-whoami.webp](01-event-viewer-whoami.webp)
- [02-event-viewer-hostname.webp](02-event-viewer-hostname.webp)
- [03-event-viewer-ipconfig.webp](03-event-viewer-ipconfig.webp)
- [04-event-viewer-net-user.webp](04-event-viewer-net-user.webp)
- [05-event-viewer-notepad.webp](05-event-viewer-notepad.webp)
- [06-wazuh-cmd.webp](06-wazuh-cmd.webp)
- [07-wazuh-net-user.webp](07-wazuh-net-user.webp)
- [08-wazuh-net1.webp](08-wazuh-net1.webp)
- [09-wazuh-net-accounts.webp](09-wazuh-net-accounts.webp)
- [10-wazuh-net-localgroup-page-1.webp](10-wazuh-net-localgroup-page-1.webp)
- [10-wazuh-net-localgroup-page-2.webp](10-wazuh-net-localgroup-page-2.webp)
- [10-wazuh-net-localgroup-page-3.webp](10-wazuh-net-localgroup-page-3.webp)
