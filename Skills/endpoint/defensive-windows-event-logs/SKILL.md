---
name: defensive-windows-event-logs
description: "Windows Event Log reference and analysis for detection and IR: Security, System, PowerShell, Task Scheduler, WMI-Activity, TerminalServices, WinRM, BITS, Defender, NTLM, Kerberos (KDCSVC) channels; key event IDs (4624/4625 logon types, 4648, 4672, 4688, 4697, 4698, 4720, 4728/4732/4756, 4740, 4662 DCSync GUIDs, 4768/4769/4771/4776, 5136, 5140/5145, 1102, 7045, 4104); Kerberos and NTLM authentication analysis; RPC and named pipes; ETW providers and AMSI; and parsing with EvtxECmd, Hayabusa, Chainsaw, Get-WinEvent. Use when interpreting Windows logs or choosing which events to collect."
---

# Windows Event Logs

Know which channel holds the answer, what the fields mean, and which events require extra audit policy. Most "we have no logs" moments are audit policy gaps, not retention gaps.

## Quick Workflow

1. Identify question → channel + event ID
2. Confirm audit policy produces it (see `defensive-log-sources`)
3. Query (SIEM or `Get-WinEvent` / EvtxECmd)
4. Correlate on `LogonId`, `ProcessId`, `TargetLogonId`, `ActivityID`
5. Interpret with field semantics below

---

## 1. Security Channel

| ID | Meaning | Key fields / notes |
|---|---|---|
| 4624 | Logon success | `LogonType`, `TargetUserName`, `IpAddress`, `WorkstationName`, `LogonProcessName`, `AuthenticationPackageName`, `TargetLogonId`, `ElevatedToken` |
| 4625 | Logon failure | `Status`/`SubStatus`: `0xC000006A` bad password, `0xC0000064` no such user, `0xC0000234` locked, `0xC0000072` disabled, `0xC000006F` outside hours, `0xC0000071` expired |
| 4634 / 4647 | Logoff / user-initiated logoff | Pair with 4624 via `TargetLogonId` |
| 4648 | Explicit credentials used | runas, lateral tooling, scheduled tasks with creds |
| 4672 | Special privileges assigned | Admin-equivalent logon |
| 4688 | Process creation | `NewProcessName`, `CommandLine` (needs GPO), `ParentProcessName`, `TokenElevationType` |
| 4697 | Service installed | `ServiceFileName` |
| 4698 / 4699 / 4700 / 4701 / 4702 | Task created / deleted / enabled / disabled / updated | Task XML in event |
| 4719 | System audit policy changed | Defense evasion |
| 4720 / 4722 / 4725 / 4726 / 4738 | User created / enabled / disabled / deleted / changed | |
| 4724 | Password reset attempt | By another account |
| 4728 / 4732 / 4756 | Member added to global / local / universal group | Watch Domain Admins, Enterprise Admins, Administrators, Backup Operators, DnsAdmins |
| 4740 | Account locked out | `CallerComputerName` = source |
| 4741 / 4742 | Computer account created / changed | RBCD, machine-account abuse |
| 4662 | Operation on directory object | DCSync GUIDs below |
| 4663 / 4656 | Object access | Needs SACL |
| 4657 | Registry value modified | Needs SACL |
| 4768 | Kerberos TGT requested | `TicketEncryptionType`, `PreAuthType` (0 = no preauth), `IpAddress` |
| 4769 | Kerberos service ticket requested | `ServiceName`, `TicketEncryptionType` (0x17 = RC4, 0x12 = AES256) |
| 4770 | TGT renewed | |
| 4771 | Kerberos pre-auth failed | `FailureCode` 0x18 = bad password |
| 4776 | NTLM credential validation | `Workstation`, `Status` |
| 4765 / 4766 | SID History added / failed | |
| 4794 | DSRM password set attempt | |
| 5136 | Directory object modified | GPO, ACL, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink` (shadow credentials) |
| 5140 / 5145 | Share accessed / file share object checked | `ShareName`, `RelativeTargetName` (named pipes) |
| 5156 / 5157 | WFP allowed / blocked connection | Very noisy |
| 1102 | Security log cleared | |
| 4886 / 4887 | Certificate requested / issued (ADCS) | Needs CA auditing |

### Logon Types

| Type | Name | Notes |
|---|---|---|
| 2 | Interactive | Console |
| 3 | Network | SMB, WMI, WinRM, PsExec — no reusable creds left on target (except delegation) |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service accounts |
| 7 | Unlock | |
| 8 | NetworkCleartext | Basic auth (IIS), creds sent in clear |
| 9 | NewCredentials | `runas /netonly`; with `LogonProcessName=seclogo` → pass-the-hash pattern |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Offline DC |

### DCSync GUIDs (4662 `Properties`)

- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c` DS-Replication-Get-Changes-In-Filtered-Set

Alert when the subject is not a domain controller computer account.

---

## 2. Other Channels

| Channel | IDs | Use |
|---|---|---|
| System | 7045 service installed; 7036 state change; 7040 start type changed; 104 log cleared; 6005/6006 log service start/stop (boot) | Persistence, evasion |
| Microsoft-Windows-PowerShell/Operational | 4103 module, 4104 script block, 4105/4106 start/stop | Script content |
| Windows PowerShell | 400 / 403 engine start/stop (`EngineVersion` 2.0 = downgrade), 600 provider | Downgrade attacks |
| TaskScheduler/Operational | 106 registered, 140 updated, 141 deleted, 200 action started, 201 completed | Task execution |
| WMI-Activity/Operational | 5857 provider load, 5860 temporary, 5861 permanent subscription | WMI persistence |
| TerminalServices-LocalSessionManager | 21 logon, 22 shell start, 24 disconnect, 25 reconnect | RDP sessions |
| TerminalServices-RemoteConnectionManager | 1149 network auth success | RDP source IP |
| TerminalServices-RDPClient | 1024, 1102 | Outbound RDP (source host) |
| WinRM/Operational | 6 client session, 91 server shell | PS Remoting |
| Bits-Client/Operational | 3, 59, 60 | BITS jobs (URL in event) |
| Windows Defender/Operational | 1116 detected, 1117 action, 5001 RTP disabled, 5007 config changed (exclusions) | AV state |
| NTLM/Operational | 8001–8004 outgoing/incoming NTLM, blocked | NTLM audit/restriction |
| System (KDCSVC) | 201–209 (Jan 2026+) | RC4 usage audit during Kerberos RC4 deprecation |
| CodeIntegrity/Operational | 3076/3077 (audit/block) | WDAC |
| AppLocker | 8002–8007 | Allow/block |

---

## 3. Kerberos & NTLM Analysis

| Attack | Signal |
|---|---|
| Kerberoasting (T1558.003) | 4769 `TicketEncryptionType=0x17`, service ≠ krbtgt, not ending `$`, many SPNs per requester. Since 2026 KDC defaults are AES-only (CVE-2026-20833 rollout; enforcement July 2026), RC4 tickets now indicate explicit RC4-enabled accounts or downgrade attempts — high signal |
| AS-REP roasting (T1558.004) | 4768 `PreAuthType=0` |
| Password spray (T1110.003) | 4771 0x18 / 4625 across many users from one source, few per user |
| Golden ticket (T1558.001) | Service use with no matching 4768; anomalous ticket lifetimes; TGT for nonexistent/disabled user |
| Silver ticket (T1558.002) | Service logon with no 4769 on any DC |
| Pass-the-hash (T1550.002) | 4624 type 3 NTLM, `KeyLength=0`, across many hosts; 4624 type 9 `seclogo` on source |
| Overpass-the-hash | 4768 with RC4 from host where user uses AES |
| NTLM relay (T1557.001) | 4624 NTLM where `WorkstationName` mismatches source IP; machine account authenticating from non-owner IP |
| Shadow credentials | 5136 modifying `msDS-KeyCredentialLink`; 4768 with PKINIT for that account |

NTLM: Microsoft plans network NTLM disabled by default in the next major Windows Server release; NTLMv1 SSO blocked by default from Oct 2026. Enable NTLM auditing now to find dependencies.

---

## 4. RPC & Named Pipes

5145 `RelativeTargetName` on `IPC$`:

| Pipe | Interface | Abuse |
|---|---|---|
| `svcctl` | Service Control Manager | PsExec, remote service creation |
| `atsvc` | Task Scheduler | Remote tasks |
| `samr` | SAM | Enumeration |
| `lsarpc` | LSA | Enumeration, SID lookup |
| `netlogon` | Netlogon | Zerologon-class |
| `winreg` | Remote Registry | Remote reg read/write |
| `srvsvc` | Server service | Share/session enumeration |
| `drsuapi` (over TCP) | Directory replication | DCSync |
| `spoolss` | Print spooler | PrinterBug coercion |
| `efsrpc` / `lsarpc` EFS | EFSRPC | PetitPotam coercion |

---

## 5. ETW & AMSI

| Provider | Value |
|---|---|
| Microsoft-Windows-Threat-Intelligence | Kernel-sourced API telemetry (PPL-only consumers; EDRs) |
| Microsoft-Windows-DotNETRuntime | Assembly loads (in-memory .NET) |
| Microsoft-Windows-Kernel-Process / -File / -Network | Low-level activity |
| Microsoft-Antimalware-Scan-Interface | AMSI scan content |
| Microsoft-Windows-PowerShell | Script blocks |

Tools: SilkETW, `logman query providers`, `logman start <session> -p <provider> -ets`.
Tampering signals: 4104 containing `AmsiScanBuffer`, `amsiInitFailed`, `EtwEventWrite`, `NtTraceEvent`; per-host provider volume drops; `logman stop EventLog-*`.

---

## 6. Querying

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-1)} |
  Where-Object { $_.Properties[8].Value -eq 10 } |
  Select TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[18].Value}}

Get-WinEvent -Path .\Security.evtx -FilterXPath "*[System[EventID=4769] and EventData[Data[@Name='TicketEncryptionType']='0x17']]"
```

```bash
EvtxECmd.exe -d ./evtx --csv out/
hayabusa csv-timeline -d ./evtx -o hayabusa.csv
chainsaw search "mimikatz" ./evtx
```

---

## Engagement Cheatsheet

```text
Question → channel/ID → audit policy present? → query → correlate LogonId/ProcessId
→ logon type semantics → Kerberos/NTLM patterns → pipes/RPC → ETW/AMSI tamper checks
```

---

## Key References

- Microsoft: Advanced security auditing FAQ; event ID documentation
- Microsoft KB5073381 (Kerberos RC4 / CVE-2026-20833); "Advancing Windows security: Disabling NTLM by default" (Jan 2026)
- SANS Windows Forensic poster; Ultimate Windows Security event encyclopedia
- Related: `defensive-sysmon`, `defensive-ad-detection`, `defensive-hunt-windows`
