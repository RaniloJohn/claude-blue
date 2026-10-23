---
name: defensive-sentinel
description: "Microsoft Sentinel and Defender XDR unified SecOps: data connectors and Data Collection Rules (DCR/AMA), Log Analytics tables, analytics rule types (scheduled, NRT, Microsoft security, Fusion/ML), entity mapping, watchlists, ASIM parsers, UEBA, Sentinel data lake tier, Content Hub solutions, automation rules and Logic Apps playbooks, Defender XDR advanced hunting and custom detections, incident correlation, and the Azure-portal-to-Defender-portal transition (Azure portal management retires 31 March 2027). Use for Sentinel/Defender detection engineering, tuning, and investigation."
---

# Microsoft Sentinel & Defender XDR

Sentinel (SIEM) and Defender XDR now operate as one SecOps surface in the Defender portal with a shared incident model. Sentinel management in the Azure portal retires **31 March 2027** (extended from July 2026); new tenants are onboarded to the Defender portal by default.

## Quick Workflow

1. Connect data (Defender XDR connector, Entra ID, Azure Activity, AMA/DCR for servers, CEF/Syslog)
2. Verify tables populate and costs (Analytics vs Basic vs data lake tiers)
3. Enable Content Hub solutions → analytics rules matching your data
4. Write custom scheduled/NRT rules with entity mapping
5. Automation rules for triage; playbooks for actions
6. Hunt in Advanced Hunting (unified KQL across XDR + Sentinel tables)

---

## 1. Data Connectors & Tables

| Connector | Tables |
|---|---|
| Microsoft Defender XDR | `DeviceProcessEvents`, `DeviceNetworkEvents`, `EmailEvents`, `IdentityLogonEvents`, `CloudAppEvents`, `AlertInfo`, `AlertEvidence` |
| Entra ID | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`, `AADRiskyUsers`, `AADUserRiskEvents` |
| Azure Activity | `AzureActivity` |
| Office 365 | `OfficeActivity` |
| Windows Security Events via AMA | `SecurityEvent` (filtered by DCR XPath) |
| Windows Forwarded / Sysmon via AMA | `WindowsEvent` / `Event` |
| Syslog / CEF via AMA | `Syslog`, `CommonSecurityLog` |
| AWS S3 | `AWSCloudTrail`, `AWSGuardDuty`, `AWSVPCFlow` |

DCR XPath filter example (collect only key Security events):

```text
Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4698 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776 or EventID=1102)]]
```

The legacy HTTP Data Collector API is retired in favor of the Logs Ingestion API (DCR-based).

---

## 2. Analytics Rule Types

| Type | Notes |
|---|---|
| Scheduled | KQL on interval (5 min–14 d), lookback up to 14 d |
| NRT | Near-real-time, ~1 min, limited query features |
| Microsoft security | Create incidents from Defender/Entra alerts |
| Fusion / ML | Multistage correlation (Defender portal correlation engine supersedes in unified mode) |
| Threat intelligence | Match TI indicators |
| Anomaly | UEBA/ML anomalies |

Defender XDR **custom detections** (advanced hunting) run on XDR + Sentinel tables in the unified portal and can take device/user actions.

---

## 3. Scheduled Rule Template

```kql
// Rule: New inbox rule forwarding externally
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("New-InboxRule","Set-InboxRule")
| extend P = tostring(Parameters)
| where P has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo")
| extend Target = extract(@"(?i)(ForwardTo|RedirectTo|ForwardAsAttachmentTo)\W+Value\W+([^""]+)", 2, P)
| where Target !endswith "@contoso.com"
| project TimeGenerated, UserId, ClientIP, Operation, Target
```

Entity mapping: Account → `UserId`; IP → `ClientIP`; MailMessage/Mailbox as applicable. Without entity mapping, incident correlation and UEBA don't work.

Settings: query frequency 1 h, lookback 1 h (+ overlap for ingestion delay), alert grouping by entity, suppression window.

---

## 4. Watchlists & ASIM

```kql
let Protected = _GetWatchlist('ProtectedAssets') | project SearchKey;
DeviceLogonEvents
| where DeviceName in (Protected)
```

ASIM parsers normalize across vendors:

```kql
_Im_ProcessCreate(starttime=ago(1d), endtime=now())
| where ActingProcessName endswith "\\winword.exe" and TargetProcessName endswith "\\powershell.exe"
```

Schemas: `_Im_Authentication`, `_Im_NetworkSession`, `_Im_Dns`, `_Im_WebSession`, `_Im_ProcessEvent`, `_Im_FileEvent`, `_Im_RegistryEvent`, `_Im_AuditEvent`.

---

## 5. Identity Detections (Entra)

```kql
// Successful sign-in after MFA fatigue (many MFA denials)
let denies = SigninLogs | where TimeGenerated > ago(1d) and ResultType == "500121"
  | summarize Denies=count() by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| join kind=inner denies on UserPrincipalName
| where Denies >= 5
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Denies

// Credentials added to service principal
AuditLogs
| where OperationName has_any ("Add service principal credentials","Update application – Certificates and secrets management")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName)
```

ResultType: `0` success, `50126` bad creds, `50053` locked, `50074/50076` MFA required, `500121` MFA failed, `53003` blocked by Conditional Access.

---

## 6. UEBA & Data Lake

- UEBA: `BehaviorAnalytics`, `IdentityInfo`, `UserPeerAnalytics` tables; investigation priority scores
- Sentinel data lake tier: low-cost long retention for high-volume logs; query via KQL jobs/notebooks; promote subsets to analytics tier for detections
- Basic/Auxiliary logs: cheaper, limited query/alerting — not for real-time detections

---

## 7. Automation

- Automation rules: run on incident create/update; assign, tag, change severity, run playbook
- Playbooks (Logic Apps): Managed Identity auth; actions such as isolate device (Defender API), disable user / revoke sessions (Graph), block IP (firewall API)
- Keep destructive actions manual-trigger; see `defensive-soar-automation`

---

## 8. Cost & Health

```kql
Usage | where TimeGenerated > ago(30d) | summarize GB = sum(Quantity)/1024 by DataType | sort by GB desc
SentinelHealth | where Status != "Success" | summarize count() by SentinelResourceName, Status, Description
```

---

## Engagement Cheatsheet

```text
Connectors/DCRs → table checks → Content Hub → custom rules + entity mapping
→ watchlists/ASIM → automation rules → playbooks (manual for destructive)
→ Advanced Hunting in Defender portal → cost/health review monthly
```

---

## Key References

- Microsoft Sentinel docs; "Microsoft Sentinel in the Azure portal retirement" (sunset 31 Mar 2027)
- Defender XDR advanced hunting schema reference
- Azure-Sentinel GitHub (detections, hunting queries, parsers)
- Related: `defensive-entra-id`, `defensive-bec-response`, `defensive-query-languages`
