---
name: defensive-defender-xdr
description: "Microsoft Defender XDR operations: Defender for Endpoint (onboarding, sensor health, ASR rules, tamper protection, EDR in block mode, device isolation, live response), Defender for Office 365 (Safe Links/Attachments, ZAP, Threat Explorer, AIR), Defender for Identity (sensors on DCs/AD CS/ADFS/Entra Connect, lateral movement paths), Defender for Cloud Apps, unified incidents, Advanced Hunting KQL schema (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents, EmailEvents, UrlClickEvents, IdentityLogonEvents, IdentityQueryEvents, CloudAppEvents, AlertEvidence), custom detection rules, automated investigation levels, the unified SecOps portal with Sentinel, and API automation. Use when hunting, responding, or configuring Microsoft Defender XDR."
---

# Microsoft Defender XDR

Defender XDR correlates endpoint, email, identity, and cloud app signals into **incidents**. Defenders live in **Advanced Hunting (KQL)**, **incident triage**, and **response actions** — increasingly inside the unified Defender portal alongside Sentinel.

## Quick Workflow

1. Coverage: MDE onboarding %, sensor health, MDI sensors on all identity servers
2. Hardening: ASR rules, tamper protection, EDR in block mode, network protection
3. Triage incidents (attack story, evidence, impacted assets)
4. Hunt with KQL; convert to custom detections
5. Respond: isolate, restrict app execution, collect package, live response, disable user, purge email

---

## 1. Endpoint Hardening Settings

| Setting | Recommendation |
|---|---|
| Tamper protection | On (tenant-wide) |
| EDR in block mode | On (even with third-party AV) |
| Network protection | Block mode |
| Cloud-delivered protection / block at first sight | High; extended cloud check |
| PUA protection | Block |
| ASR rules | Block mode for: Office child processes, Office injecting into processes, executable content from email/webmail, obfuscated scripts, Win32 API calls from macros, credential stealing from LSASS, untrusted/unsigned USB processes, WMI event subscription persistence, PSExec/WMI process creations (servers: test first), executables unless they meet prevalence/age/trusted list, advanced ransomware protection, abuse of exploited vulnerable signed drivers |
| Controlled folder access | Audit → block for high-risk roles |
| Attack disruption | Enabled (automatic containment of compromised users/devices in human-operated attacks) |

```kql
DeviceEvents
| where ActionType startswith "Asr" and Timestamp > ago(7d)
| summarize count() by ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by count_ desc
```

---

## 2. Advanced Hunting Schema (core)

| Table | Content |
|---|---|
| `DeviceProcessEvents` | Process creation (+ initiating process fields) |
| `DeviceNetworkEvents` | Connections, `RemoteUrl`, `RemoteIP`, `ActionType` |
| `DeviceFileEvents` | Create/modify/rename/delete |
| `DeviceRegistryEvents` | Registry changes |
| `DeviceLogonEvents` | Logons with `LogonType`, `RemoteIP` |
| `DeviceImageLoadEvents` | DLL loads |
| `DeviceEvents` | Misc (ASR, AMSI, named pipes, WMI, USB, firewall, etc.) |
| `DeviceInfo` / `DeviceNetworkInfo` | Inventory |
| `DeviceTvmSoftwareVulnerabilities` | Vulnerabilities |
| `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents` | MDO |
| `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents` | MDI |
| `CloudAppEvents` | MDA / M365 activity |
| `AlertInfo`, `AlertEvidence` | Alerts and entities |
| `EntraIdSignInEvents` / `AADSignInEventsBeta` (legacy name) | Entra sign-ins (P2) |

Retention in Advanced Hunting: 30 days (longer via Sentinel / data lake).

---

## 3. Hunting Queries

```kql
// Phish click → process execution within 10 min on same user's device
let clicks = UrlClickEvents | where Timestamp > ago(1d) and ActionType == "ClickAllowed" | project ClickTime = Timestamp, AccountUpn, Url;
DeviceProcessEvents
| where Timestamp > ago(1d) and InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","outlook.exe")
| join kind=inner (clicks) on $left.AccountUpn == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 10m)
| project Timestamp, DeviceName, AccountUpn, Url, FileName, ProcessCommandLine
```

```kql
// LSASS access by unusual processes (Defender records OpenProcessApiCall)
DeviceEvents
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","MsSense.exe","svchost.exe","csrss.exe","wininit.exe")
| summarize count() by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
```

```kql
// Identity: LDAP reconnaissance burst (MDI)
IdentityQueryEvents
| where Timestamp > ago(1d) and Protocol == "Ldap"
| summarize Queries = count(), Distinct = dcount(QueryTarget) by DeviceName, AccountName, bin(Timestamp, 15m)
| where Queries > 300
```

```kql
// Email: delivered messages with attachments from new external senders
EmailEvents
| where Timestamp > ago(1d) and EmailDirection == "Inbound" and DeliveryAction == "Delivered" and AttachmentCount > 0
| join kind=leftanti (EmailEvents | where Timestamp between (ago(30d) .. ago(1d)) | distinct SenderFromAddress) on SenderFromAddress
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId
```

---

## 4. Custom Detections

Advanced Hunting query → Create detection rule: frequency (continuous/NRT for supported tables, or every 1–24 h), required columns (`Timestamp`, `ReportId`, plus entity columns like `DeviceId`, `AccountObjectId`), impacted entities mapping, automated actions (isolate device, collect investigation package, run AV scan, restrict app execution, disable user via MDI, soft-delete email).

---

## 5. Response Actions

| Entity | Actions |
|---|---|
| Device | Isolate (full/selective), restrict app execution, AV scan, collect investigation package, live response (`connect`, `processes`, `getfile`, `putfile`, `run`, `remediate`), offboard |
| File | Stop and quarantine, add indicator (block/allow), deep analysis |
| User | Disable in AD/Entra (via MDI/Entra), require reset, revoke sessions (Entra) |
| Email | Soft/hard delete, move to junk, block sender/URL via Tenant Allow/Block List |
| Indicators | IP/URL/domain/hash/certificate indicators (alert/block) |

Live response library: upload signed scripts (KAPE/Velociraptor collectors). Unsigned script execution requires setting — keep disabled except for IR.

---

## 6. Automated Investigation (AIR)

Device groups with automation level: **Full — remediate threats automatically** (recommended for most), Semi (approval for some folders), None. Review Action Center for pending/completed actions.

---

## 7. Defender for Identity Coverage

Sensors on every DC, AD CS, ADFS, and Entra Connect server; health alerts for sensor stopped/auditing missing; review "Lateral movement paths" and Identity Security Posture assessments (unconstrained delegation, weak cipher usage, NTLM, dormant admins).

---

## Engagement Cheatsheet

```text
coverage (MDE %, MDI on DC/ADCS/ADFS/Connect) → tamper + EDR block + network protection + ASR block → attack disruption on
→ incidents → AH KQL (Device*/Email*/Identity*/CloudAppEvents) → custom detections with entity mapping + auto actions
→ isolate / restrict / package / live response / disable user / purge email → AIR full remediation → posture recommendations
```

---

## Key References

- Microsoft Defender XDR Advanced Hunting schema reference; ASR rules reference; Defender for Identity docs
- Related: `defensive-sentinel`, `defensive-query-languages`, `defensive-edr-tuning`, `defensive-entra-id`
