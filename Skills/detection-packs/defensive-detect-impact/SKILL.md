---
name: defensive-detect-impact
description: "Detection pack for MITRE ATT&CK Impact (TA0040): data encrypted for impact (ransomware file activity, mass renames, ransom notes, entropy spikes), inhibit system recovery (vssadmin/wmic shadowcopy delete, wbadmin delete catalog, bcdedit recoveryenabled no, backup service stops), service stop and process kill sprees, data destruction and wipers, disk wipe/MBR overwrite, defacement, account access removal (mass password resets, MFA removal, admin lockout), resource hijacking and cryptomining, endpoint/network DoS, financial theft, ESXi/hypervisor encryption (esxcli vm process kill, vmdk encryption), and cloud destruction (bucket/backup/key deletion, KMS key scheduling). Detections, canaries, auto-containment, FPs. Use when building ransomware/impact detections."
---

# Detection Pack — Impact (TA0040)

By the time impact starts, minutes matter. Detect the **pre-encryption** steps (recovery inhibition, service killing, backup deletion) and auto-contain. Encryption detection itself must trigger automated isolation, not a ticket.

## Quick Workflow

1. Recovery-inhibition and backup tampering rules → **automated host isolation**
2. File-activity analytics (mass rename/modify, ransom note names, canary files)
3. Hypervisor and cloud destructive actions → page on-call immediately
4. Rehearse the response (`defensive-ransomware-response`)

---

## 1. Inhibit System Recovery (T1490)

```yaml
title: Shadow Copy or Backup Catalog Deletion
logsource: { product: windows, category: process_creation }
detection:
  vss:
    CommandLine|contains|all: ['shadow', 'delete']
  wmic:
    CommandLine|contains|all: ['shadowcopy', 'delete']
  resize:
    CommandLine|contains|all: ['vssadmin', 'resize', 'shadowstorage']
  wbadmin:
    CommandLine|contains|all: ['wbadmin', 'delete']
  bcd:
    CommandLine|contains: ['recoveryenabled no','bootstatuspolicy ignoreallfailures']
  ps:
    CommandLine|contains|all: ['Win32_ShadowCopy', 'Delete']
  condition: 1 of them
level: critical
tags: [attack.impact, attack.t1490]
```

Also: `diskshadow` scripts with `delete shadows all`, VSS service disabled, Windows RE disabled (`reagentc /disable`), Veeam/backup services stopped, backup console logins from unusual hosts, Veeam CVE exploitation for credential theft.

---

## 2. Service Stop / Process Kill Sprees (T1489)

```spl
index=sysmon EventCode=1 (process_name IN ("net.exe","net1.exe","sc.exe","taskkill.exe") OR (process_name="powershell.exe" AND CommandLine="*Stop-Service*"))
  (CommandLine="* stop *" OR CommandLine="*config*disabled*" OR CommandLine="*/f /im*" OR CommandLine="*Stop-Service*")
| bin _time span=5m
| stats count dc(CommandLine) as uniq values(CommandLine) by host user _time
| where uniq >= 5
```

Targets typically: SQL, Exchange, Veeam, backup agents, AV/EDR, VSS, `MSExchange*`, `vmms`, Oracle, `sophos*`.

---

## 3. Encryption Activity (T1486)

| Signal | Source |
|---|---|
| Mass file modifications/renames by one process (> 100 files/min) | EDR file events, Sysmon 11/2/23/26, Windows 4663 with SACLs |
| Unknown extension appended across many files | File events, share audit 5145 |
| Ransom note filenames (`README*.txt`, `*RESTORE*`, `HOW_TO_DECRYPT*`, `*.hta`) in many directories | Sysmon 11 |
| Canary file touched | Canary files in share roots / user folders (FSRM file screens or deception) |
| Entropy jump in written files | EDR/NDR (SMB writes with high entropy) |
| SMB write storms from one client to file servers | Zeek `smb_files.log`, file server 5145 |
| Wallpaper change + note | Registry `Control Panel\Desktop\Wallpaper` |

```kql
DeviceFileEvents
| where ActionType in ("FileRenamed","FileModified")
| summarize Files = dcount(FileName), Exts = dcount(tostring(split(FileName, ".")[-1])), Folders = dcount(FolderPath) by DeviceName, InitiatingProcessFileName, InitiatingProcessId, bin(Timestamp, 1m)
| where Files > 200 and Folders > 20
```

FSRM file screen on file servers (passive tripwire):

```powershell
New-FsrmFileGroup -Name "RansomNotes" -IncludePattern @("*README*.txt","*DECRYPT*","*RESTORE*FILES*","*.locked","*.encrypted")
New-FsrmFileScreen -Path "D:\Shares" -Template "Monitor Executable and System Files" -IncludeGroup "RansomNotes" -Active:$false
```

---

## 4. Destruction / Wipers (T1485, T1561)

`cipher /w`, `sdelete -z`, `format` commands, raw disk writes to `\\.\PhysicalDrive0` (Sysmon 9 on non-backup processes), driver-based wipers (RawDisk/EldoS driver loads), `dd if=/dev/zero of=/dev/sda`, `shred`, `rm -rf --no-preserve-root`, mass `Remove-Item -Recurse` on shares.

---

## 5. Account Access Removal (T1531)

Mass password resets or account disables by one admin, MFA method deletion, removal of Global Admins, changing break-glass credentials, AD `Domain Admins` membership cleared, Entra `Delete user` bursts.

```kql
AuditLogs
| where OperationName in ("Reset password (by admin)","Disable account","Delete user","Remove member from role","Delete authentication method")
| summarize n = count(), Targets = dcount(tostring(TargetResources[0].userPrincipalName)) by Actor = tostring(InitiatedBy.user.userPrincipalName), bin(TimeGenerated, 15m)
| where Targets >= 10
```

---

## 6. Hypervisor (ESXi / vCenter)

| Signal | Source |
|---|---|
| `esxcli vm process kill`, `vim-cmd vmsvc/power.off` bursts | ESXi `shell.log`, `hostd.log` |
| SSH/ESXi Shell enabled outside change window | `hostd.log`, vCenter events |
| `esxcli system settings advanced set -o /User/execInstalledOnly -i 0` | `shell.log` — disabling execInstalledOnly is pre-ransomware |
| Files `.vmdk`/`.vmx` renamed with new extensions; ransom note in datastore | Datastore browsing, `vmkernel.log` |
| New local ESXi admins; AD `ESX Admins` group created (CVE-2024-37085) | ESXi auth logs, AD 4727/4728 |

---

## 7. Cloud Destruction

| Platform | Signal |
|---|---|
| AWS | `DeleteBucket`, mass `DeleteObject(s)`, `PutBucketLifecycleConfiguration` expiring all, `DeleteBackupVault`/`DeleteRecoveryPoint`, `ScheduleKeyDeletion`/`DisableKey` (KMS), `TerminateInstances` bursts, S3 SSE-C re-encryption with attacker key (Codefinger pattern — `CopyObject` with SSE-C headers) |
| Azure | Resource group deletes, Recovery Services vault soft-delete disable, Key Vault purge, storage account deletion |
| GCP | Project deletion, bucket deletion, KMS key version destroy |
| Resource hijacking (T1496) | GPU/large instance launches in unused regions; Kubernetes pods running xmrig; CPU saturation + mining pool DNS (`*.pool.*`, `stratum+tcp`) |

---

## 8. Automated Response

| Trigger | Action |
|---|---|
| Recovery inhibition (critical) | EDR isolate host, disable user, page on-call |
| Encryption analytics | Isolate host; block SMB from host at file servers; snapshot file servers |
| ESXi kill spree | Disable vCenter accounts in use, isolate management network |
| Cloud destruction | Revoke principal sessions (`aws iam put-role-policy` deny-all / Entra revoke), enable deletion protection |

---

## 9. False Positives

Backup software rotating shadow copies (`vssadmin delete shadows /oldest` by backup agent), patching/maintenance stopping services, archival jobs renaming files, admins cleaning test VMs, legitimate mass offboarding. Tune by signed parent + service account + change window — but **never fully suppress** recovery-inhibition rules.

---

## Engagement Cheatsheet

```text
T1490 shadow/backup/bcdedit/wbadmin → auto-isolate | service-kill spree ≥5/5m | mass rename/modify + ransom notes + canaries + FSRM
→ wipers (raw disk, cipher /w) → mass account removal → ESXi kill/execInstalledOnly/ESX Admins → cloud delete/KMS/SSE-C → cryptomining
```

---

## Key References

- MITRE ATT&CK TA0040; CISA #StopRansomware Guide; CISA ESXi ransomware advisories
- Related: `defensive-ransomware-response`, `defensive-cyber-resilience`, `defensive-cloud-ir`
