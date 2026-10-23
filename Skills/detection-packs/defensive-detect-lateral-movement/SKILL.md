---
name: defensive-detect-lateral-movement
description: "Detection pack for MITRE ATT&CK Lateral Movement (TA0008): SMB/admin shares and PsExec-style service execution, WMI and WinRM/PowerShell remoting, RDP and RDP hijacking, DCOM (MMC20, ShellWindows, Excel), scheduled tasks remote, pass-the-hash, pass-the-ticket, overpass-the-hash, SSH lateral movement and key reuse, remote management/RMM tools, internal spearphishing, taint shared content, software deployment tools (SCCM, Intune, PDQ), cloud lateral movement (SSM, serial console, cross-account role assumption, Azure Run Command), and ESXi/vCenter pivots. Source+destination correlation, logon type analysis, network detections, FPs. Use when building lateral movement detections."
---

# Detection Pack — Lateral Movement (TA0008)

Lateral movement is seen best by **correlating both ends**: the source host's outbound connection/process and the destination's logon + child process. Network telemetry (Zeek SMB/DCE-RPC/RDP logs) closes gaps where endpoint logs are missing.

## Quick Workflow

1. Destination: 4624 (type 3/10) + 4672 + process creation within seconds
2. Source: outbound 445/135/5985/5986/3389/22 from workstation → server/workstation
3. Network: Zeek `smb_files`, `dce_rpc`, `rdp`, `ssh`, `kerberos`, `ntlm`
4. Baseline admin paths (jump hosts, PAW, management servers) — alert on anything else

---

## 1. Method → Evidence

| Method | Destination evidence | Source evidence | Network |
|---|---|---|---|
| PsExec / service exec (T1569.002 + T1021.002) | 4624 t3, 4672, 7045 `PSEXESVC` or random svc, 5145 `ADMIN$` write | `psexec.exe`, Impacket `smbexec/psexec` | SMB write to `ADMIN$`, `svcctl` DCE-RPC |
| WMI (T1047) | `WmiPrvSE.exe` child process, 4624 t3 | `wmic /node:`, `Invoke-WmiMethod -ComputerName` | DCE-RPC `IWbemServices` / port 135 + dynamic |
| WinRM / PS Remoting (T1021.006) | `wsmprovhost.exe` child, WinRM Operational 91, 4624 t3 | `Enter-PSSession`, `Invoke-Command`, `winrs` | 5985/5986 |
| RDP (T1021.001) | 4624 t10, 4778/4779, RCM 1149, LSM 21/22/25 | `mstsc.exe`, `TerminalServer-Client` 1024 | 3389, Zeek `rdp.log` |
| RDP hijack (T1563.002) | `tscon.exe` run as SYSTEM | — | — |
| DCOM (T1021.003) | `mmc.exe -Embedding`, `explorer.exe`/`excel.exe` children via DCOM | PowerShell `[Activator]::CreateInstance([type]::GetTypeFromProgID(...,"host"))` | 135 + dynamic |
| Remote scheduled task (T1053.005) | 4698 with remote source, TaskScheduler 106 | `schtasks /s` | `atsvc`/`ITaskSchedulerService` RPC |
| Pass-the-Hash (T1550.002) | 4624 t3 NTLM, `KeyLength=0`; t9 `seclogo` on source | `sekurlsa::pth` → 4624 t9 on source | NTLM where Kerberos expected |
| Pass-the-Ticket (T1550.003) | 4624 Kerberos with no preceding 4768 for that host/user | — | TGS without TGT from that IP |
| Overpass-the-hash | 4768 RC4 for account that normally uses AES | — | — |
| SSH (T1021.004) | `sshd` accepted publickey/password; new `authorized_keys` | `ssh` from servers/workstations not normally used | Zeek `ssh.log` |
| RMM tools (T1219) | AnyDesk/ScreenConnect/TeamViewer/Atera/Splashtop installs | — | RMM vendor domains (LOLRMM) |
| SCCM/Intune/PDQ (T1072) | Unexpected deployments, `CcmExec` children | Admin console activity from unusual accounts | — |

---

## 2. Detections

### Remote service creation (PsExec / Impacket)

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend Svc = tostring(AdditionalFields.ServiceName), Path = tostring(AdditionalFields.ServiceStartType)
| join kind=inner (DeviceLogonEvents | where LogonType == "Network") on DeviceId
| where abs(datetime_diff('second', Timestamp, Timestamp1)) < 30
| project Timestamp, DeviceName, Svc, RemoteIP, AccountName
```

```yaml
title: Admin Share Write Followed By Service Install
logsource: { product: windows, service: security }
detection:
  share:
    EventID: 5145
    ShareName|endswith: ['\ADMIN$','\C$']
    AccessMask|contains: ['0x2','0x6']
    RelativeTargetName|endswith: ['.exe','.dll','.bat','.ps1']
  condition: share
level: medium
tags: [attack.lateral-movement, attack.t1021.002]
```

Pair with 7045 on the same host within 60 s (correlation rule).

### WinRM child process

```spl
index=sysmon EventCode=1 ParentImage="*\\wsmprovhost.exe"
| stats count values(CommandLine) by host User
```

### Workstation-to-workstation admin (most valuable single rule)

```spl
index=wineventlog EventCode=4624 Logon_Type IN (3,10) Account_Name!="*$" Account_Name!="ANONYMOUS LOGON"
| lookup asset_inventory ip as Source_Network_Address OUTPUT role as src_role
| lookup asset_inventory host as host OUTPUT role as dst_role
| where src_role="workstation" AND dst_role="workstation"
| stats count values(host) as dests by Source_Network_Address Account_Name
```

### Pass-the-Hash heuristics

```kql
SecurityEvent
| where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
| where Account !endswith "$" and Account !has "ANONYMOUS"
| where KeyLength == 0 or LmPackageName == "NTLM V1"
| summarize Hosts = dcount(Computer), make_set(Computer, 20) by Account, IpAddress, bin(TimeGenerated, 1h)
| where Hosts >= 3
```

Also: 4624 type 9 (`NewCredentials`) with `LogonProcessName=seclogo` on source host — `runas /netonly` or `sekurlsa::pth`.

### RDP from unexpected sources

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| lookup rdp_allowed_sources ip as Source_Network_Address OUTPUT allowed
| where isnull(allowed)
| table _time host Account_Name Source_Network_Address
```

### Zeek network view

```bash
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -Ei 'svcctl|atsvc|ITaskSchedulerService|IWbemServices|drsuapi'
zeek-cut ts id.orig_h id.resp_h path name action < smb_files.log | grep -i 'ADMIN\$'
```

---

## 3. Linux / ESXi / Cloud

| Platform | Signal |
|---|---|
| Linux SSH | `Accepted publickey` from internal hosts not in jump-host list; `ssh` with `-A` agent forwarding from servers; same key fingerprint across many hosts |
| ESXi / vCenter | SSH enabled (`hostd`/`shell.log`), new local accounts, `esxcli system` from shell, vCenter logins from non-admin networks |
| AWS | `ssm:StartSession`/`SendCommand` from unusual principals; `ec2-instance-connect:SendSSHPublicKey`; `AssumeRole` chains into other accounts |
| Azure | `Microsoft.Compute/virtualMachines/runCommand/action`, VM extension installs, serial console |
| GCP | `compute.instances.setMetadata` (ssh-keys), OS Login grants, `iap.tunnelInstances.accessViaIAP` |

---

## 4. False Positives

Admin jump hosts, PAWs, SCCM/management servers, backup servers mounting `C$`, vulnerability scanners using authenticated scans, helpdesk RDP tools. Maintain an **admin source inventory** (lookup) and alert on everything outside it.

---

## 5. Triage

1. Source host — how did the account get there? (initial access chain)
2. Credential type — password, hash, ticket, key? Where was it stolen?
3. Everything that account touched in the window (fan-out)
4. Process tree on each destination
5. Contain source and destinations together; reset the credential

---

## Engagement Cheatsheet

```text
destination: 4624 t3/t10 + 4672 + child proc/7045/5145 | source: outbound admin ports + tool cmdline | network: Zeek dce_rpc/smb/rdp/ssh
→ PsExec/WMI/WinRM/RDP/DCOM/tasks → PtH (NTLM KeyLength 0, t9 seclogo) / PtT → workstation↔workstation → cloud SSM/RunCommand → admin-source lookup
```

---

## Key References

- MITRE ATT&CK TA0008; JPCERT "Detecting Lateral Movement through Tracking Event Logs"; LOLRMM
- Related: `defensive-detect-credential-access`, `defensive-hunt-windows`, `defensive-zeek`, `defensive-network-segmentation`
