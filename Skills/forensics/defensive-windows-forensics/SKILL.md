---
name: defensive-windows-forensics
description: "Windows disk and artifact forensics: what each artifact proves (execution vs existence vs access), parsing with KAPE and Eric Zimmerman tools (MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, LECmd, JLECmd, EvtxECmd, SrumECmd, Timeline Explorer), $MFT and $UsnJrnl:$J, timestomping detection ($SI vs $FN), Prefetch, Amcache, Shimcache, BAM/DAM, UserAssist, ShellBags, LNK/Jump Lists, SRUM, registry hives, Recycle Bin, Volume Shadow Copies, browser history, and EVTX. Use for host-based DFIR, execution validation, and root cause analysis on Windows."
---

# Windows Forensics

The core question is always: did it **exist**, did it **execute**, who **accessed** it, and **when**. Each artifact answers some of these — never all. Corroborate execution with at least two artifacts.

## Quick Workflow

1. Acquire (triage image via KAPE/Velociraptor or full E01); hash
2. Parse with EZ Tools (or KAPE `!EZParser` module)
3. Anchor on known-bad (alert time, hash, filename)
4. Build timeline around anchors (± hours/days)
5. Validate execution claims with artifact semantics
6. Identify initial access, persistence, lateral movement, exfil
7. Extract indicators with source artifact for each

---

## 1. Artifact Semantics

| Artifact | Location | Proves | Does NOT prove | Caveats |
|---|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\*.pf` | Execution; run count; last 8 run times; files/dirs referenced | — | Disabled by default on Windows Server; 1,024 file cap on Win10+ |
| Amcache | `C:\Windows\appcompat\Programs\Amcache.hve` | File presence + SHA-1 + metadata | Execution (on its own) | Inventory entries can be written without run |
| Shimcache (AppCompatCache) | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | File seen by shim engine | Execution on Win10+ | Written at shutdown; order ≠ time |
| BAM/DAM | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` | Execution + last time per user | — | ~7-day retention |
| UserAssist | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | GUI execution, count, last time | CLI execution | ROT13 names |
| RecentApps / Jump Lists | `AutomaticDestinations`, `CustomDestinations` | Files opened per app | — | |
| LNK files | `%APPDATA%\Microsoft\Windows\Recent` | File/folder opened; target MAC times, volume serial, device | — | Survive target deletion |
| ShellBags | `NTUSER.DAT` + `UsrClass.dat` `BagMRU` | Folder browsed (incl. USB, network, ZIP) | File access | Persist after folder deletion |
| $MFT | Volume root | File existence, MACB times (`$SI`, `$FN`), resident data | Execution | `$SI` easily timestomped |
| $UsnJrnl:$J | `$Extend\$UsnJrnl` | Create/rename/delete/overwrite sequence | Content | Rolls over (size-bound) |
| $LogFile | Volume root | Recent metadata transactions | | Short window |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Per-app network bytes, energy, ~30 d | — | Hourly granularity |
| Zone.Identifier ADS | `file:Zone.Identifier` | Downloaded; `ReferrerUrl`, `HostUrl` | — | Lost on non-NTFS copy |
| Recycle Bin | `$Recycle.Bin\<SID>\$I*` | Deleted file original path + time | — | |
| VSS | Shadow copies | Historical file/registry state | — | Often deleted by ransomware |
| EVTX | `winevt\Logs` | Per event ID | — | Retention by size; check 1102/104 |
| Browser | Chrome/Edge `History` SQLite, Firefox `places.sqlite` | Visits, downloads | — | |
| PowerShell history | `PSReadLine\ConsoleHost_history.txt` | Interactive commands typed | Scripts run non-interactively | Per user |
| Scheduled tasks | `C:\Windows\System32\Tasks\*` XML | Task definition | Execution (use TaskScheduler log) | |
| WMI repository | `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` | Persistent subscriptions | | Parse with `PyWMIPersistenceFinder` / Velociraptor |

---

## 2. Parsing Commands

```powershell
MFTECmd.exe -f "E:\C\$MFT" --csv D:\case\mft
MFTECmd.exe -f "E:\C\$Extend\$J" -m "E:\C\$MFT" --csv D:\case\usn
PECmd.exe -d "E:\C\Windows\Prefetch" --csv D:\case\prefetch
AmcacheParser.exe -f "E:\C\Windows\appcompat\Programs\Amcache.hve" -i --csv D:\case\amcache
AppCompatCacheParser.exe -f "E:\C\Windows\System32\config\SYSTEM" --csv D:\case\shimcache
RECmd.exe -d "E:\C\Windows\System32\config" --bn BatchExamples\Kroll_Batch.reb --csv D:\case\reg
RECmd.exe -d "E:\C\Users" --bn BatchExamples\Kroll_Batch.reb --csv D:\case\reg_user
SBECmd.exe -d "E:\C\Users\jdoe" --csv D:\case\shellbags
LECmd.exe -d "E:\C\Users" --csv D:\case\lnk
JLECmd.exe -d "E:\C\Users" --csv D:\case\jumplists
EvtxECmd.exe -d "E:\C\Windows\System32\winevt\Logs" --csv D:\case\evtx
SrumECmd.exe -f "E:\C\Windows\System32\sru\SRUDB.dat" -r "E:\C\Windows\System32\config\SOFTWARE" --csv D:\case\srum
RBCmd.exe -d "E:\C\$Recycle.Bin" --csv D:\case\recycle
```

Open CSVs in Timeline Explorer; filter by time window and keywords.

---

## 3. Timestomping Detection

| Check | Indicator |
|---|---|
| `$SI` Created < `$FN` Created | `$SI` was backdated |
| `$SI` times with `.0000000` sub-seconds | Tool-set timestamps |
| USN `FileCreate` time ≠ `$SI` Created | Backdating |
| Sysmon EID 2 | File creation time changed |
| File older than its parent directory in a fresh install path | Suspicious |

MFTECmd outputs `SI<FN` and `uSecZeros` flags.

---

## 4. Execution Validation Matrix

| Claim | Minimum corroboration |
|---|---|
| "evil.exe ran" | Prefetch OR BAM OR Sysmon 1/4688 + one of (Amcache, SRUM, UserAssist) |
| "User opened file X" | LNK/Jump List + ShellBags/RecentDocs |
| "Data was exfiltrated" | SRUM bytes / proxy logs + staging artifacts (archives in USN) |
| "Attacker deleted tool" | USN `FileDelete` + Recycle/Amcache residual + Sysmon 23/26 |

---

## 5. Registry Quick Map

| Hive | Key | Artifact |
|---|---|---|
| SYSTEM | `Select\Current` | Current control set |
| SYSTEM | `ControlSet00x\Services` | Services (persistence) |
| SYSTEM | `ControlSet00x\Enum\USBSTOR` | USB devices |
| SYSTEM | `ControlSet00x\Control\ComputerName` | Hostname |
| SYSTEM | `ControlSet00x\Control\TimeZoneInformation` | Timezone |
| SOFTWARE | `Microsoft\Windows\CurrentVersion\Run` | Persistence |
| SOFTWARE | `Microsoft\Windows NT\CurrentVersion\NetworkList` | Networks joined |
| SOFTWARE | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | IFEO persistence |
| SAM | `Domains\Account\Users` | Local accounts, last logon |
| NTUSER.DAT | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`, `TypedPaths`, `RunMRU`, `WordWheelQuery` | User activity |
| NTUSER.DAT | `Software\Microsoft\Terminal Server Client\Servers` | Outbound RDP targets |

Account for transaction logs (`.LOG1/.LOG2`) — RECmd replays dirty hives.

---

## 6. EVTX Priorities

Security: 4624/4625/4648/4672/4688/4697/4698/4720/4732/1102. System: 7045/7036/104. PowerShell: 4104. TaskScheduler: 106/200. RDP: LocalSessionManager 21/22/25, RemoteConnectionManager 1149. Defender: 1116/1117/5001/5007. Fast triage: Hayabusa / Chainsaw with Sigma.

---

## Engagement Cheatsheet

```text
KAPE !SANS_Triage + !EZParser → anchor → Timeline Explorer (MFT+USN+Prefetch+Amcache+EVTX+LNK)
→ validate execution (2 artifacts) → persistence (Run, services, tasks, WMI) → lateral (4624 types, RDP) → IOCs
```

---

## Key References

- SANS FOR500 "Windows Forensic Analysis" poster
- Eric Zimmerman's tools — https://ericzimmerman.github.io
- KAPE (Kroll)
- Related: `defensive-timeline-analysis`, `defensive-memory-forensics`, `defensive-live-response`
