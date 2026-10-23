---
name: defensive-detect-initial-access
description: "Detection pack for MITRE ATT&CK Initial Access (TA0001): phishing attachments and links (T1566), drive-by and malvertising (T1189), exploitation of public-facing applications and edge devices (T1190), external remote services VPN/RDP/Citrix (T1133), valid accounts incl. cloud (T1078), trusted relationships and MSP access (T1199), supply chain compromise (T1195), replication via removable media (T1091), and hardware additions (T1200). Telemetry, Sigma/SPL/KQL detections, false positives, and triage pivots. Use when building or reviewing initial access detections."
---

# Detection Pack — Initial Access (TA0001)

Initial access is the cheapest place to stop an intrusion and the hardest to see: much of it looks like normal logins, email, and web traffic. Combine identity anomalies, email telemetry, edge-device logs, and the first suspicious child process.

## Quick Workflow

1. Confirm telemetry: email gateway/M365, IdP sign-ins, VPN/edge logs, web server/WAF, EDR process tree
2. Deploy the detections below in log-only mode
3. Tune against known-good (IT tools, VPN egress, partners)
4. Promote; link each to a triage guide

---

## 1. Technique → Telemetry

| Technique | Primary telemetry |
|---|---|
| T1566.001/.002 Phishing attachment/link | Email gateway, `EmailEvents`/`EmailAttachmentInfo`/`UrlClickEvents`, EDR child processes of mail/Office/browser |
| T1566.004 Spearphishing voice | Help desk tickets, IdP MFA resets, new device registrations |
| T1189 Drive-by | Proxy/DNS, browser child processes, downloads from new domains |
| T1190 Exploit public-facing app | WAF/web logs, edge device logs, web server process spawning shells |
| T1133 External remote services | VPN/RDP Gateway/Citrix logs, 4624 type 10 from external IPs |
| T1078 Valid accounts | IdP sign-ins (new ASN/country/device), impossible travel, dormant account logons |
| T1199 Trusted relationship | MSP/RMM tool sessions, partner federated sign-ins |
| T1195 Supply chain | Software update processes spawning unusual children; new binaries from updaters |
| T1091 / T1200 Removable media / hardware | Device install events (6416, PnP), USB mounts, new HID devices |

---

## 2. Detections

### Office / mail client / browser spawning script hosts (T1566 → T1204)

```yaml
title: Office or Mail Client Spawns Script Interpreter
logsource: { product: windows, category: process_creation }
detection:
  parent:
    ParentImage|endswith: ['\WINWORD.EXE','\EXCEL.EXE','\POWERPNT.EXE','\OUTLOOK.EXE','\ONENOTE.EXE','\MSACCESS.EXE']
  child:
    Image|endswith: ['\powershell.exe','\pwsh.exe','\cmd.exe','\wscript.exe','\cscript.exe','\mshta.exe','\rundll32.exe','\regsvr32.exe','\certutil.exe','\bitsadmin.exe']
  condition: parent and child
level: high
tags: [attack.initial-access, attack.t1566.001, attack.execution, attack.t1204.002]
```

### Execution from mounted ISO / archive extraction paths

```kql
DeviceProcessEvents
| where FolderPath matches regex @"^[D-Z]:\\" and InitiatingProcessFileName =~ "explorer.exe"
| where FileName endswith ".exe" or FileName in~ ("cmd.exe","wscript.exe","rundll32.exe")
| join kind=leftsemi (DeviceEvents | where ActionType has "Mount") on DeviceId
```

(Adapt: many environments record ISO mounts differently — validate the mount telemetry first; LNK execution from `%TEMP%\*\` archive extraction folders is a related signal.)

### Web server spawning shells (T1190 → web shell)

```spl
index=edr (parent_process_name IN ("w3wp.exe","httpd","nginx","php-fpm","java","tomcat*.exe","sqlservr.exe","node"))
  process_name IN ("cmd.exe","powershell.exe","sh","bash","whoami","id","uname","certutil.exe","curl","wget")
| stats count values(process) by host parent_process_name process_name
```

### Edge device / VPN anomalies (T1133, T1190)

| Signal | Source |
|---|---|
| Successful VPN login from new country/ASN or hosting provider | VPN logs + GeoIP/ASN enrichment |
| VPN login for account without prior VPN use | VPN logs vs 90-day baseline |
| Same account VPN sessions from 2+ countries within hours | VPN logs |
| Edge appliance spawning unusual processes / new files in web dirs | Vendor integrity tools, syslog, EDR if supported |
| Config changes or new admin accounts on edge device | Device config/audit logs |
| Exploit attempt signatures for current KEV edge CVEs | WAF/IPS |

### Valid accounts (T1078)

```kql
SigninLogs
| where ResultType == "0"
| summarize Countries = make_set(tostring(LocationDetails.countryOrRegion)), ASNs = make_set(AutonomousSystemNumber) by UserPrincipalName, bin(TimeGenerated, 1d)
| where array_length(Countries) > 1
```

Dormant account reactivated:

```spl
index=wineventlog EventCode=4624 Logon_Type IN (2,3,10)
| stats latest(_time) as last by user
| join type=inner user [ search index=wineventlog EventCode=4624 earliest=-90d latest=-30d | stats count by user | where count=0 ]
```

(Simpler: maintain a lookup of last-logon per account and alert when gap > 60 days.)

### Help desk / MFA reset abuse (T1566.004 → T1556.006)

```kql
AuditLogs
| where OperationName in ("User registered security info","Reset password (by admin)","Admin registered security info","User deleted security info")
| summarize ops = make_set(OperationName), n = count() by TargetUser = tostring(TargetResources[0].userPrincipalName), bin(TimeGenerated, 1h)
| where n >= 2
```

Correlate with help desk ticket: reset without verified ticket → investigate.

### Removable media / hardware (T1091, T1200)

- Windows 6416 (new external device recognized, needs Audit PNP Activity), Sysmon 1 executions from removable drive letters
- Unknown HID keyboards (BadUSB): new keyboard device + immediate PowerShell from `explorer.exe`

---

## 3. False Positives

| Detection | Common FP | Tune by |
|---|---|---|
| Office child processes | Add-ins, document management, legal tools | Signer + path + parent cmdline |
| Web server child processes | Health checks, admin scripts, CGI apps | Specific script paths, service account |
| VPN geo anomalies | Travel, mobile carriers, cloud egress | Travel calendar, known egress, device ID |
| Help desk resets | Legitimate onboarding | Ticket correlation |

---

## 4. Triage Pivots

1. What delivered it? (email message ID, URL, VPN session, exploit request)
2. First process after access — parent/child chain
3. Same sender/URL/IP across tenant; same exploit pattern on other servers
4. Credentials used afterwards from new locations?
5. Persistence created within 24 h? → `defensive-detect-persistence`

---

## Engagement Cheatsheet

```text
email+IdP+VPN+web+EDR telemetry → Office/browser child procs → mounted/extracted exec → web shell parent
→ VPN/IdP anomalies → MFA/helpdesk changes → USB/HID → tune → triage pivots
```

---

## Key References

- MITRE ATT&CK TA0001 (v18 Detection Strategies per technique)
- CISA/FBI Scattered Spider advisory (July 2025 update) — help desk social engineering
- CISA BOD 26-02 (Feb 2026) — unsupported edge devices
- Related: `defensive-phishing-triage`, `defensive-incident-response`, `defensive-threat-hunting`
