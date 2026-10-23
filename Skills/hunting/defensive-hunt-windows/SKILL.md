---
name: defensive-hunt-windows
description: "Windows endpoint threat hunting playbooks with ready queries (SPL, KQL, EQL) over Sysmon, Security EVTX, PowerShell 4104, and EDR telemetry. Covers anomalous parent-child process lineage, LOLBins (rundll32, regsvr32, mshta, certutil, bitsadmin, msbuild, installutil, wmic), encoded/obfuscated PowerShell, persistence (Run keys, services, scheduled tasks, WMI subscriptions, COM hijacking, IFEO), credential access (LSASS, SAM, NTDS, DPAPI, browser stores), process injection and unbacked memory, DLL sideloading, BYOVD drivers, lateral movement artifacts, and defense evasion (log clearing, Defender exclusions, AMSI/ETW tampering)."
---

# Windows Hunting Playbooks

Hunt Windows by behavior and lineage. Tools rename; parent-child relationships, access masks, and persistence locations don't.

## Quick Workflow

1. Confirm telemetry (Sysmon/EDR process + network + registry + image load)
2. Pick a playbook below
3. Stack and review the long tail
4. Validate each outlier against change records and second sources
5. Convert stable patterns into detections

---

## 1. Expected Process Lineage

| Process | Expected parent | Notes |
|---|---|---|
| `smss.exe` | `System` | Single session-0 instance persists |
| `csrss.exe`, `wininit.exe` | `smss.exe` (exits) | |
| `services.exe`, `lsass.exe` | `wininit.exe` | Exactly one `lsass.exe` in `System32` |
| `svchost.exe` | `services.exe` | Always `-k <group>` |
| `explorer.exe` | `userinit.exe` (exits) | One per interactive user |
| `taskhostw.exe` | `svchost.exe` | |
| `RuntimeBroker.exe` | `svchost.exe` | |

Hunt: these names from wrong path or wrong parent.

```kql
DeviceProcessEvents
| where FileName in~ ("lsass.exe","svchost.exe","csrss.exe","services.exe","smss.exe","wininit.exe")
| where FolderPath !startswith @"C:\Windows\System32" and FolderPath !startswith @"C:\Windows\SysWOW64"
```

---

## 2. Suspicious Lineage

| Parent | Child | Meaning |
|---|---|---|
| Office apps, Outlook | powershell, cmd, mshta, wscript, rundll32 | Macro/OLE execution |
| `w3wp.exe`, `httpd`, `tomcat`, `sqlservr.exe` | cmd, powershell, whoami | Web shell / SQL xp_cmdshell |
| `WmiPrvSE.exe` | cmd, powershell | WMI remote exec |
| `wsmprovhost.exe` | anything unusual | PS Remoting |
| `services.exe` | cmd /c, random-name EXE | PsExec / Impacket service |
| `explorer.exe` | `rundll32` with no DLL | Shellcode loaders |
| `mshta.exe`, `wscript.exe` | powershell | Script-chain |

```spl
index=sysmon EventCode=1 (ParentImage="*\\w3wp.exe" OR ParentImage="*\\sqlservr.exe" OR ParentImage="*\\tomcat*.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\whoami.exe" OR Image="*\\net.exe")
| stats count values(CommandLine) by host ParentImage Image
```

---

## 3. LOLBins

```eql
process where event.type == "start" and (
  (process.name : "certutil.exe" and process.args : ("-urlcache","/urlcache","-decode","/decode","-encode")) or
  (process.name : "bitsadmin.exe" and process.args : ("/transfer","/addfile")) or
  (process.name : "mshta.exe" and process.args : ("http*","javascript:*","vbscript:*")) or
  (process.name : "regsvr32.exe" and process.args : ("/i:http*","-i:http*","scrobj.dll")) or
  (process.name : "rundll32.exe" and process.args : ("*javascript:*","*url.dll*","*zipfldr*","*,#*")) or
  (process.name : ("msbuild.exe","installutil.exe","regasm.exe","regsvcs.exe") and process.parent.name : ("cmd.exe","powershell.exe","explorer.exe","wscript.exe"))
)
```

Reference: LOLBAS project.

---

## 4. PowerShell

Use 4104 script blocks:

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*DownloadString*"
   OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*AmsiScanBuffer*"
   OR ScriptBlockText="*amsiInitFailed*" OR ScriptBlockText="*VirtualAlloc*" OR ScriptBlockText="*Reflection.Assembly*")
| stats count values(ScriptBlockText) by host UserID
```

Downgrade: Windows PowerShell log EID 400 with `EngineVersion=2.0`. Decode `-enc`: Base64 → UTF-16LE.

---

## 5. Persistence Stacks

| Mechanism | Telemetry | Stack by |
|---|---|---|
| Run/RunOnce | Sysmon 13 `TargetObject` contains `\CurrentVersion\Run` | Details (value) |
| Services | System 7045, Security 4697 | ImagePath |
| Scheduled tasks | 4698, TaskScheduler 106/200 | Task XML command |
| WMI subscriptions | Sysmon 19/20/21, WMI-Activity 5861 | Consumer command |
| COM hijack | Sysmon 13 `HKCU\Software\Classes\CLSID\*\InprocServer32` | DLL path |
| IFEO / SilentProcessExit | Sysmon 13 `Image File Execution Options\*\Debugger` | Debugger value |
| Startup folder | Sysmon 11 `\Start Menu\Programs\Startup\` | File |
| Winlogon | Sysmon 13 `Winlogon\Userinit`, `Winlogon\Shell` | Value |
| LSA packages | Sysmon 13 `Control\Lsa\Security Packages`, `Notification Packages` | Value |

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\Image File Execution Options", @"\Winlogon", @"\Control\Lsa")
| summarize count(), Hosts=dcount(DeviceName) by RegistryKey, RegistryValueName, RegistryValueData
| where Hosts < 3
```

Autoruns (Sysinternals) snapshot diffs are the offline equivalent.

---

## 6. Credential Access

| Behavior | Signal |
|---|---|
| LSASS memory read | Sysmon 10 `TargetImage=*\lsass.exe`, `GrantedAccess` 0x1010/0x1410/0x1438/0x143a/0x1fffff, `CallTrace` with `UNKNOWN(` |
| MiniDump via comsvcs | `rundll32 ... comsvcs.dll, MiniDump` |
| SAM/SYSTEM hive save | `reg save HKLM\SAM`, `reg save HKLM\SYSTEM` |
| NTDS | `ntdsutil "ac i ntds" ifm`, `vssadmin create shadow`, raw read (Sysmon 9) on DC |
| DPAPI / browser | Non-browser process reading `Login Data`, `Cookies`, `Local State` |
| Kerberoast | 4769 RC4 (0x17) bursts — note RC4 defaults removed in 2026 KDC updates, so remaining RC4 requests are higher signal |

```kql
DeviceFileEvents
| where FileName in~ ("Login Data","Cookies","Local State","key4.db","logins.json")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
```

---

## 7. Injection & Memory

- Sysmon 8 CreateRemoteThread into unrelated processes
- Sysmon 10 with `CallTrace` containing `UNKNOWN(` (unbacked)
- Sysmon 25 ProcessTampering (hollowing/herpaderping)
- Sysmon 7: `clr.dll`/`clrjit.dll` loaded into non-.NET processes (`notepad.exe`, `rundll32.exe`) → in-memory .NET assembly
- Signed binary loading DLL from user-writable path (sideloading)

```spl
index=sysmon EventCode=7 (ImageLoaded="*\\clr.dll" OR ImageLoaded="*\\clrjit.dll")
  (Image="*\\rundll32.exe" OR Image="*\\notepad.exe" OR Image="*\\svchost.exe" OR Image="*\\werfault.exe")
| stats count by host Image
```

---

## 8. Drivers (BYOVD)

Sysmon 6 DriverLoad: unsigned or signer revoked; hash in loldrivers.io list; driver loaded from temp/user paths. Enable Microsoft Vulnerable Driver Blocklist / HVCI.

---

## 9. Defense Evasion

| Behavior | Signal |
|---|---|
| Log cleared | Security 1102, System 104 |
| Audit policy change | 4719; `auditpol /clear` |
| Defender tampering | Defender 5001 (RTP off), 5007 (config/exclusion change); `Set-MpPreference -ExclusionPath` |
| Sysmon tampering | Sysmon 4, 16; service stop |
| ETW/AMSI patching | 4104 strings; sudden provider volume drop per host |
| Timestomp | Sysmon 2 |
| Event log service stop | 7036 for EventLog |

---

## 10. Lateral Movement Artifacts (destination side)

| Technique | Destination evidence |
|---|---|
| PsExec/smbexec | 4624 type 3, 5145 `ADMIN$`, 7045 service, Sysmon 17 pipe |
| WMI | 4624 type 3, `WmiPrvSE.exe` children |
| WinRM | 4624 type 3, WinRM 91, `wsmprovhost.exe` children |
| RDP | 4624 type 10, RemoteConnectionManager 1149 |
| Scheduled task (remote) | 4698 + 4624 type 3 same `LogonId` window |
| DCOM | `mmc.exe`/`excel.exe` spawning shells with no user interaction |

---

## Engagement Cheatsheet

```text
Lineage anomalies → LOLBins → PowerShell 4104 → persistence stacks
→ credential access → injection/.NET in memory → drivers → evasion → lateral artifacts
```

---

## Key References

- LOLBAS — https://lolbas-project.github.io ; LOLDrivers — https://www.loldrivers.io
- SANS "Hunt Evil" poster; Sysmon event documentation
- Microsoft Defender XDR advanced hunting schema
- Related: `defensive-sysmon`, `defensive-windows-event-logs`, `defensive-ad-detection`, `defensive-memory-forensics`
