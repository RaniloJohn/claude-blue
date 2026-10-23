---
name: defensive-detect-privilege-escalation
description: "Detection pack for MITRE ATT&CK Privilege Escalation (TA0004): exploitation for privilege escalation incl. kernel and driver exploits (T1068), UAC bypass (T1548.002), sudo/setuid abuse (T1548.001/.003), access token manipulation and Potato-family attacks (T1134), process injection into privileged processes (T1055), DLL search order hijacking and service permission weaknesses (T1574), valid account privilege abuse, group membership changes, AD privilege escalation (RBCD, ADCS, GPO), container escape (T1611), and cloud IAM escalation. Detections, FPs, and triage. Use when writing or reviewing privilege escalation detections."
---

# Detection Pack — Privilege Escalation (TA0004)

Look for integrity/privilege transitions that shouldn't happen: a medium-integrity process spawning a SYSTEM shell, a service account becoming a domain admin, a container process touching the host, a cloud principal granting itself more rights.

## Quick Workflow

1. Telemetry with integrity level / user context (Sysmon 1 `IntegrityLevel`, 4688 `TokenElevationType`, 4672), group changes, cloud IAM events
2. Deploy transition-based detections
3. Baseline admin tooling and installers
4. Escalate any confirmed privilege gain to IR

---

## 1. Windows

| Technique | Signal |
|---|---|
| UAC bypass (T1548.002) | High-integrity child of auto-elevating binaries (`fodhelper.exe`, `computerdefaults.exe`, `eventvwr.exe`, `sdclt.exe`, `wsreset.exe`) with registry changes under `HKCU\Software\Classes\ms-settings\shell\open\command` or `mscfile` |
| Token impersonation / Potato (T1134) | Service accounts (`IIS APPPOOL\*`, `NT SERVICE\MSSQL*`, `NETWORK SERVICE`) spawning processes as SYSTEM; named pipe creation by web/SQL process |
| Service permission abuse (T1574.010/.011) | Sysmon 13 changing `ImagePath` of existing services; `sc config ... binpath=` by non-admin |
| DLL hijacking (T1574.001/.002) | Signed binaries loading DLLs from their own non-standard directory or user-writable paths (Sysmon 7, `Signed=false`) |
| Kernel/driver exploit (T1068) | Vulnerable driver loads (Sysmon 6 hashes on LOLDrivers), crashes followed by SYSTEM processes |
| Named pipe impersonation | Sysmon 17/18 pipes by low-priv processes followed by SYSTEM children |
| Scheduled task as SYSTEM by non-admin | 4698 with `RunLevel` HighestAvailable / SYSTEM principal created by unexpected user |

```yaml
title: UAC Bypass via ms-settings or mscfile Handler Hijack
logsource: { product: windows, category: registry_set }
detection:
  sel:
    TargetObject|contains:
      - '\Software\Classes\ms-settings\shell\open\command'
      - '\Software\Classes\mscfile\shell\open\command'
      - '\Software\Classes\exefile\shell\open\command'
  condition: sel
level: high
tags: [attack.privilege-escalation, attack.t1548.002]
```

```spl
index=sysmon EventCode=1 IntegrityLevel=System
  (ParentUser="*IIS APPPOOL*" OR ParentUser="*MSSQL*" OR ParentUser="*NETWORK SERVICE*" OR ParentUser="*LOCAL SERVICE*")
| table _time host ParentImage ParentUser Image CommandLine User
```

(Sysmon 1 lacks ParentUser natively on older versions — derive from parent's own event via ProcessGuid join, or use EDR fields.)

---

## 2. Linux

| Technique | Signal |
|---|---|
| sudo abuse (T1548.003) | `sudo` to shells/editors/interpreters (GTFOBins) by users not in admin groups; sudo failures then success |
| SUID abuse (T1548.001) | Execution of unusual SUID binaries; new SUID bits (`chmod u+s`, auditd `fchmodat`) |
| Capabilities | `setcap` to `cap_setuid`/`cap_sys_admin` |
| Kernel exploit | Unprivileged process → uid 0 shell without sudo/su; kernel oops logs |
| `pkexec`/polkit | Unexpected `pkexec` executions |
| Writable cron/systemd run as root | FIM on root-owned job files modified by non-root |

```text
auditd: -a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k priv_exec
```

Alert on `priv_exec` where parent isn't `sudo`/`su`/known management agents.

---

## 3. Active Directory

| Path | Signal |
|---|---|
| Privileged group add | 4728/4732/4756 to admin groups |
| RBCD | 5136 `msDS-AllowedToActOnBehalfOfOtherIdentity`; 4741 new computer |
| AD CS (ESC1/ESC8/…) | 4887 cert issued with SAN for privileged user to unprivileged requester |
| GPO abuse | 5136 on GPOs linked to privileged OUs |
| ACL abuse | 5136 DACL changes (`nTSecurityDescriptor`) on users/groups/domain |
| Kerberos delegation abuse | 4769 with `Transited services`/S4U patterns from non-standard hosts |

---

## 4. Containers & Cloud

| Platform | Signal |
|---|---|
| Containers (T1611) | Privileged/hostPID/hostPath pods; `nsenter`; writes to host paths; `release_agent`/`core_pattern` writes (Falco default rules) |
| AWS | `AttachUserPolicy`/`PutRolePolicy` granting admin; `CreatePolicyVersion --set-as-default`; `PassRole` + `RunInstances`/`CreateFunction`; `UpdateAssumeRolePolicy` |
| Azure | Role assignment writes (Owner/UAA); Entra role activation outside PIM; `elevateAccess` (Global Admin → User Access Administrator at root) |
| GCP | `SetIamPolicy` granting owner/editor; `iam.serviceAccounts.actAs` + compute create; `GenerateAccessToken` chains |

```kql
AuditLogs | where OperationName == "Add member to role" and TargetResources has_any ("Global Administrator","Privileged Role Administrator")
AzureActivity | where OperationNameValue =~ "Microsoft.Authorization/elevateAccess/action"
```

---

## 5. False Positives

Installers/updaters elevating via UAC, IT admin tools, SQL/IIS maintenance jobs, Ansible/Chef running as root, PIM activations. Tune by approved tooling, change windows, and accounts.

---

## Engagement Cheatsheet

```text
integrity transitions (UAC, Potato, service/DLL hijack, drivers) → Linux sudo/SUID/caps/uid0 exec
→ AD group/ACL/RBCD/ADCS/GPO → container escape → cloud IAM self-grants → tune → IR on confirmation
```

---

## Key References

- MITRE ATT&CK TA0004; UACME (UAC bypass catalog, for detection research); GTFOBins; LOLDrivers
- Rhino Security Labs AWS IAM privesc methods; Microsoft "elevate access" docs
- Related: `defensive-ad-detection`, `defensive-k8s-security`, `defensive-aws-security`, `defensive-windows-hardening`
