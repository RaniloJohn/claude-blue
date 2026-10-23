---
name: defensive-detect-collection
description: "Detection pack for MITRE ATT&CK Collection (TA0009): data staging and archiving (7-Zip, WinRAR, tar, makecab, compressed archives in staging folders), data from local systems, network shares and SharePoint/OneDrive mass access, email collection (mailbox export, eDiscovery search, Graph mail reads, forwarding rules, MailItemsAccessed), screen capture, clipboard, keylogging, audio/video capture, browser data, cloud storage object access (S3 GetObject bursts, Azure blob, GCS), code repository cloning, database dumps, and automated collection scripts. Detections, thresholds, FPs. Use when building collection detections or scoping data access."
---

# Detection Pack — Collection (TA0009)

Collection is the last chance before data leaves. Look for **volume anomalies** (one account reading far more than normal), **staging** (archives in odd places), and **bulk-access APIs** (mailbox export, eDiscovery, repo clone).

## Quick Workflow

1. Baseline per-user data access volume (files, mail items, objects, rows)
2. Detect staging artifacts and archiver execution with passwords/splitting
3. Detect bulk export features being used by unexpected admins
4. Feed results into exfiltration correlation (`defensive-detect-exfiltration`)

---

## 1. Staging & Archiving (T1074, T1560)

```yaml
title: Archiver With Password Or Volume Split In Staging Path
logsource: { product: windows, category: process_creation }
detection:
  img:
    - Image|endswith: ['\7z.exe','\7za.exe','\7zr.exe','\rar.exe','\WinRAR.exe','\tar.exe','\makecab.exe']
    - OriginalFileName: ['7z.exe','7za.exe','Rar.exe','WinRAR.exe']
  flags:
    CommandLine|contains: [' -p',' -hp',' -v',' -mhe=on','-r ']
  paths:
    CommandLine|contains: ['\ProgramData\','\Users\Public\','\PerfLogs\','\Windows\Temp\','$Recycle.Bin','\AppData\Local\Temp\']
  condition: img and (flags or paths)
level: medium
tags: [attack.collection, attack.t1560.001, attack.t1074.001]
```

Other staging signals: large `.zip/.7z/.rar` files (Sysmon 11 + size via EDR) in `C:\PerfLogs`, `C:\ProgramData`, recycle bin; `robocopy /MIR` to unusual destinations; Linux `tar czf` in `/tmp`, `/dev/shm`.

---

## 2. File Shares & SharePoint/OneDrive (T1039, T1213)

```spl
index=wineventlog EventCode=5145 Accesses="*ReadData*"
| bin _time span=1h
| stats dc(Relative_Target_Name) as files dc(Share_Name) as shares by Account_Name Source_Address _time
| eventstats avg(files) as avgf stdev(files) as sdf by Account_Name
| where files > 1000 AND files > avgf + 4*sdf
```

```kql
OfficeActivity
| where Operation in ("FileDownloaded","FileSyncDownloadedFull","FileAccessed")
| summarize Files = dcount(OfficeObjectId), Sites = dcount(Site_Url) by UserId, ClientIP, bin(TimeGenerated, 1h)
| where Files > 500
```

Also: `FileSyncDownloadedFull` from unmanaged devices, SharePoint search queries for `password`, `confidential`, `vpn`, `salary`.

---

## 3. Email Collection (T1114)

| Behavior | Signal |
|---|---|
| Mailbox export | `New-MailboxExportRequest`, `New-ComplianceSearchAction -Export` |
| eDiscovery abuse | `New-ComplianceSearch` / Purview Content Search by non-legal accounts |
| Mass mail reads | `MailItemsAccessed` (Purview Audit Standard for all licenses since 2024 rollout — verify tenant) bursts; Graph `Mail.Read` app access |
| Forwarding (T1114.003) | `New-InboxRule`/`Set-InboxRule` with `ForwardTo`/`RedirectTo`; `Set-Mailbox -ForwardingSmtpAddress`; transport rules |
| Delegation | `Add-MailboxPermission FullAccess`, `Add-RecipientPermission SendAs` |
| EWS/Graph by malicious OAuth app | Consent grant → app reads many mailboxes (`ApplicationImpersonation` role retired; check Graph app perms) |

```kql
CloudAppEvents
| where ActionType == "MailItemsAccessed"
| extend Count = toint(RawEventData.OperationCount)
| summarize Items = sum(Count) by AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where Items > 1000
```

---

## 4. Input & Screen Capture (T1113, T1115, T1056, T1123, T1125)

- Screen capture tools / `CopyFromScreen` in 4104, frequent PNG/JPG writes to temp folders by non-image apps
- Clipboard: `Get-Clipboard` loops, `GetClipboardData` API (EDR)
- macOS TCC: new `kTCCServiceScreenCapture`, `kTCCServiceMicrophone`, `kTCCServiceCamera`, `kTCCServiceAccessibility` grants (`tcc_modify` ESF event, macOS 15.4+)
- Linux: `xwd`, `import`, `scrot`, `arecord` by unexpected users

---

## 5. Cloud Storage & Repositories (T1530, T1213.003)

| Source | Signal |
|---|---|
| S3 | Data events: `GetObject` count per principal per hour vs baseline; `ListObjects` then mass `GetObject`; access from new IP/ASN |
| Azure Blob | `StorageBlobLogs` `GetBlob` volume; SAS token generation (`listKeys`, `generateSasToken`) |
| GCS | Data Access logs `storage.objects.get` bursts |
| GitHub/GitLab | `git.clone` audit events across many repos by one user/token; org-wide `repo.download_zip`; new PAT with `repo` scope |
| Databases | `SELECT *` on sensitive tables without `WHERE`, `mysqldump`/`pg_dump`/`bcp`/`sqlcmd -Q` exports, `BACKUP DATABASE` to unusual paths |

```sql
-- Athena: S3 GetObject anomaly (requires data events)
SELECT useridentity.arn, sourceipaddress, count(*) AS gets, count(DISTINCT json_extract_scalar(requestparameters,'$.bucketName')) AS buckets
FROM cloudtrail_logs
WHERE eventname = 'GetObject' AND eventtime > date_format(current_timestamp - interval '1' hour, '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1, 2 HAVING count(*) > 5000;
```

---

## 6. False Positives

Backup/sync agents, DLP/eDiscovery legal holds, migrations, search indexers, data engineers' ETL jobs, build systems cloning repos. Tune by service identity and change tickets; keep a "bulk-access approved" list with expiry.

---

## Engagement Cheatsheet

```text
baseline per-user volume → archiver w/ -p/-v/staging paths → share/SharePoint download spikes → mailbox export/eDiscovery/forwarding/MailItemsAccessed
→ screen/clipboard/TCC → S3/Blob/GCS data events → repo clone bursts → DB dumps → correlate with egress
```

---

## Key References

- MITRE ATT&CK TA0009; Microsoft Purview Audit docs (MailItemsAccessed)
- Related: `defensive-detect-exfiltration`, `defensive-bec-response`, `defensive-entra-id`, `defensive-cspm`
