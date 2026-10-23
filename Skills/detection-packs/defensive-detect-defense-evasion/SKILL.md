---
name: defensive-detect-defense-evasion
description: "Detection pack for MITRE ATT&CK Defense Evasion / Stealth (TA0005): impairing defenses (disable or modify tools, EDR killing, Defender exclusions, firewall changes, log clearing, audit policy changes, ETW/AMSI tampering, safe mode boot), indicator removal (timestomp, file deletion, clear history), masquerading (renamed binaries, double extensions, right-to-left override), obfuscated/encoded payloads, signed binary proxy execution (LOLBins: rundll32, regsvr32, mshta, msiexec, InstallUtil, MSBuild), process injection and hollowing, DLL side-loading, BYOVD, rootkits, hidden artifacts, and cloud logging evasion. Detections, FPs, triage. Use when building evasion detections."
---

# Detection Pack — Defense Evasion (TA0005)

Evasion attempts are often louder than the attack they hide: disabling a sensor, clearing a log, or renaming a binary leaves its own trail. Collect from sources the attacker can't easily silence (kernel telemetry, off-host logs, network).

## Quick Workflow

1. Ensure tamper-resistant telemetry: EDR tamper protection, remote log forwarding, Sysmon 4/16 monitoring
2. Deploy "impair defenses" detections at high severity
3. Deploy masquerading and LOLBin proxy detections
4. Add silence/volume-drop detection per host and per source

---

## 1. Impair Defenses (T1562)

| Behavior | Signal |
|---|---|
| Defender disabled / exclusions | Defender 5001 (RTP off), 5007 (config incl. exclusions), `Set-MpPreference -Disable*`, `-ExclusionPath` |
| EDR/Sysmon stopped | 7036/7040 service state; Sysmon 4; `sc stop/delete`, `fltmc unload`; sensor offline alerts |
| BYOVD to kill EDR | Sysmon 6 vulnerable driver; 7045 kernel driver service |
| Firewall rules to block EDR cloud | 4946/4947; `netsh advfirewall`; `New-NetFirewallRule` with EDR process paths |
| Audit policy cleared | 4719; `auditpol /clear` or `/remove` |
| Event log cleared | 1102 (Security), 104 (System); `wevtutil cl` |
| Event log service tampering | EventLog service stop; thread suspension (Phant0m) — volume drop |
| ETW/AMSI tampering | 4104 strings `AmsiScanBuffer`, `amsiInitFailed`, `EtwEventWrite`; provider volume drop |
| Safe mode boot | `bcdedit /set {current} safeboot` |
| PowerShell downgrade | Windows PowerShell 400 `EngineVersion=2.0` |
| Linux | `auditctl -D`, `systemctl stop auditd`, `setenforce 0`, `history -c`, `unset HISTFILE`, log truncation |
| Cloud | CloudTrail `StopLogging`/`DeleteTrail`/`PutEventSelectors`; GuardDuty `DeleteDetector`; Azure diagnostic setting delete; GCP sink delete |

```yaml
title: Security Tool or Log Tampering Commands
logsource: { product: windows, category: process_creation }
detection:
  sel:
    CommandLine|contains:
      - 'Set-MpPreference'
      - 'Add-MpPreference -Exclusion'
      - 'wevtutil cl'
      - 'wevtutil clear-log'
      - 'auditpol /clear'
      - 'auditpol /remove'
      - 'fltmc unload'
      - 'bcdedit /set'
      - 'vssadmin delete shadows'
  filter_benign:
    CommandLine|contains: 'Set-MpPreference -SignatureUpdate'
  condition: sel and not filter_benign
level: high
tags: [attack.defense-evasion, attack.t1562.001, attack.t1070.001]
```

Silence detection (SIEM):

```kql
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer
| join kind=inner (DeviceInfo | summarize LastEDR = max(Timestamp) by DeviceName) on $left.Computer == $right.DeviceName
| where LastSeen > ago(30m) and LastEDR < ago(2h)   // host alive per agent A but silent in EDR
```

---

## 2. Masquerading (T1036)

| Behavior | Signal |
|---|---|
| Renamed system binaries | `OriginalFileName` ≠ `Image` name (e.g., `OriginalFileName=psexec.c` as `svchost.exe`) |
| System names in wrong paths | `svchost.exe`, `lsass.exe` outside System32 |
| Double extensions | `invoice.pdf.exe`, `.docx.lnk` |
| RTLO character | U+202E in filenames |
| Typosquat process names | `scvhost.exe`, `lsasss.exe` |

```yaml
title: Renamed Binary Masquerading
logsource: { product: windows, category: process_creation }
detection:
  sel:
    OriginalFileName: ['PsExec.exe','procdump','AnyDesk.exe','NTDSAudit.EXE','7z.exe','nc.exe','plink.exe']
  filter:
    Image|endswith: ['\PsExec.exe','\PsExec64.exe','\procdump.exe','\procdump64.exe','\AnyDesk.exe','\7z.exe','\plink.exe']
  condition: sel and not filter
level: high
```

(Verify exact `OriginalFileName` values per tool/build. Go/Rust tools such as rclone often lack PE version info entirely — catch those with hash, imphash, or command-line patterns instead.)

---

## 3. System Binary Proxy Execution (T1218, T1127)

| Binary | Abuse pattern |
|---|---|
| `rundll32.exe` | No DLL arg, `javascript:`, `url.dll,OpenURL`, ordinal exports from user paths |
| `regsvr32.exe` | `/i:http`, `scrobj.dll` (Squiblydoo) |
| `mshta.exe` | HTTP URLs, `javascript:`/`vbscript:` |
| `msiexec.exe` | `/q /i http...` remote MSI |
| `InstallUtil.exe`, `RegAsm.exe`, `RegSvcs.exe` | Executing user-path assemblies |
| `MSBuild.exe` | Building inline tasks from `.xml`/`.csproj` in user paths |
| `certutil.exe` | `-urlcache`, `-decode` |
| `cmstp.exe` | `/au` with INF |
| `odbcconf.exe`, `pcalua.exe`, `forfiles.exe` | Indirect execution |

---

## 4. Injection, Side-loading, Rootkits

- Sysmon 8 / 10 with `CallTrace` `UNKNOWN(` / 25 ProcessTampering
- Signed binary + unsigned DLL in same non-standard folder (side-loading) — Sysmon 7 `Signed=false`
- `clr.dll` loaded into non-.NET processes (in-memory assemblies)
- Linux: `/etc/ld.so.preload`, hidden modules (`lsmod` vs `/sys/module` diff), process hiding (ps vs /proc)

---

## 5. Indicator Removal (T1070)

Timestomping (Sysmon 2; `$SI` < `$FN`), mass deletion of tools (Sysmon 23/26), `fsutil usn deletejournal`, `cipher /w`, `sdelete`, shell history clearing, cloud resource deletion after use.

---

## 6. Obfuscation (T1027)

High-entropy command lines, long Base64 strings (> 200 chars), `-bxor`, `char()` concatenation, environment variable substring tricks (`%COMSPEC:~-16,1%`), excessive `^` carets.

```spl
index=sysmon EventCode=1
| eval carets=mvcount(split(CommandLine,"^"))-1, len=len(CommandLine)
| where carets > 10 OR len > 2000 OR match(CommandLine, "[A-Za-z0-9+/]{200,}={0,2}")
```

---

## 7. False Positives

Admin troubleshooting (log clears in labs), legitimate Defender exclusion management via Intune (check initiating process/account), installers using `msiexec`/`rundll32`, software with renamed redistributables. Tune by management accounts, change windows, signer.

---

## Engagement Cheatsheet

```text
tamper-proof telemetry → impair-defenses rules (high sev) → silence/volume-drop alerts → masquerading (OriginalFileName)
→ LOLBin proxy rules → injection/sideloading → indicator removal → obfuscation heuristics → tune by admin context
```

---

## Key References

- MITRE ATT&CK TA0005 (named "Stealth" for some objects in recent versions — verify current label); LOLBAS; LOLDrivers
- Related: `defensive-edr-tuning`, `defensive-sysmon`, `defensive-hunt-windows`, `defensive-windows-hardening`
