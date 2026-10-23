---
name: defensive-edr-tuning
description: "EDR operations and resilience: sensor coverage and health, tamper protection, exclusion governance and review (dangerous path/process exclusions), detecting EDR evasion and killing (BYOVD drivers, service stops, uninstall attempts, firewall rules blocking EDR cloud, WFP filters, ETW/AMSI patching, direct/indirect syscalls, unhooking), telemetry gap analysis, prevention vs detection modes, custom IOAs/indicators, and live response governance for Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend, and similar. Use when tuning an EDR, reviewing exclusions, or investigating EDR blind spots."
---

# EDR Tuning & Resilience

An EDR is only as good as its coverage, its exclusions, and its ability to survive an attacker who is trying to blind it. Most real-world EDR bypasses are configuration problems — overly broad exclusions, sensors in detect-only mode, or unprotected uninstall.

## Quick Workflow

1. Measure coverage (every asset has a healthy sensor)
2. Enforce tamper protection and uninstall protection
3. Audit exclusions; remove broad ones
4. Move policies from audit/detect to prevent where tested
5. Detect EDR-blinding attempts with independent telemetry
6. Review custom detections and live-response permissions

---

## 1. Coverage & Health

```kql
// Defender: devices not reporting in 24 h
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName, OSPlatform, SensorHealthState
| where LastSeen < ago(24h) or SensorHealthState != "Active"
```

Compare EDR inventory against AD/Entra/CMDB/cloud inventory — unmanaged assets are where attackers stage.

---

## 2. Exclusion Governance

| Exclusion | Risk |
|---|---|
| Folder: `C:\Users\*\AppData\*`, `C:\Temp`, `C:\ProgramData` | Attackers write there — never exclude |
| Process: `powershell.exe`, `cmd.exe`, `rundll32.exe`, `python.exe` | Excludes everything they run |
| Wildcard extensions (`*.exe`) | Disables scanning |
| Entire drive / share | Blind spot |
| Dev folders (`C:\src`) | Common attacker landing zone in dev shops |

Rules:
- Exclude by **signed hash or certificate + full path**, never by name alone
- Each exclusion: owner, reason, ticket, expiry
- Quarterly review; alert on new exclusions (Defender 5007; `Set-MpPreference -ExclusionPath` in 4104/4688)

```powershell
Get-MpPreference | Select ExclusionPath, ExclusionProcess, ExclusionExtension
```

On non-admin context, Defender hides exclusions from local enumeration on recent builds — still review centrally.

---

## 3. Tamper Protection

- Enable vendor tamper protection; require uninstall token/password
- Restrict who can change policies; MFA on console; audit console actions
- Separate EDR admin accounts from domain admin

---

## 4. Detecting EDR Blinding

| Technique | Independent signal |
|---|---|
| Service stop/uninstall | System 7036/7040; 4688 `sc stop`, `sc delete`, vendor uninstaller; EDR "sensor offline" alerts |
| BYOVD (vulnerable driver to kill EDR) | Sysmon 6 DriverLoad with hash on loldrivers.io; new service type kernel (7045 `ServiceType=kernel mode driver`); ASR "Block abuse of exploited vulnerable signed drivers" |
| Blocking EDR cloud comms | New Windows Firewall rules (4946/4947, `netsh advfirewall`, `New-NetFirewallRule`), WFP filter changes (5447), hosts file edits to EDR domains |
| ETW patching / AMSI bypass | 4104 strings (`AmsiScanBuffer`, `EtwEventWrite`); provider event volume drop |
| Unhooking / direct syscalls | Kernel-sourced telemetry (Threat-Intelligence ETW) still sees memory ops; user-mode hook gaps — rely on kernel callbacks |
| Safe-mode boot | `bcdedit /set safeboot`; 4688 `bcdedit` |
| Process suspension of sensor | Access to sensor process with suspend rights (Sysmon 10 target = EDR process) |
| Sensor silence | Host stops reporting while network/AD logs show activity |

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("sc stop","sc delete","sc config","net stop","taskkill")
| where ProcessCommandLine has_any ("Sense","WinDefend","MsMpEng","CSFalcon","SentinelAgent","elastic-agent","sysmon")
```

Cross-check: a host present in DHCP/AD/firewall logs but silent in EDR is a priority investigation.

---

## 5. Prevention Modes

- Pilot prevention (block) policies on representative groups; measure business impact
- Microsoft Defender: EDR in block mode (when third-party AV primary), network protection, ASR rules (audit → block), cloud-delivered protection high, PUA blocking
- CrowdStrike/SentinelOne: graduated prevention policies, ML sliders, exploit mitigations — avoid running servers in detect-only indefinitely

---

## 6. Custom Detections & Indicators

- Custom IOAs/indicators for org-specific threats; version-control them like other detections
- Hash/certificate allow-indicators instead of path exclusions when software is falsely blocked
- Test custom detections with Atomic Red Team in a lab group

---

## 7. Live Response Governance

- Limit live-response/RTR to IR roles; require justification; log and review sessions
- Disable unsigned script execution in live response where configurable
- Treat EDR console compromise as Tier 0 incident — it is remote code execution on every endpoint

---

## Engagement Cheatsheet

```text
coverage vs inventory → tamper/uninstall protection → exclusion audit (remove broad)
→ prevention modes piloted → blinding detections (driver/service/firewall/ETW/silence)
→ custom detections in Git → RTR governance
```

---

## Key References

- Microsoft Defender for Endpoint: tamper protection, exclusions best practices, ASR rules reference
- LOLDrivers — https://www.loldrivers.io
- Vendor hardening guides (CrowdStrike, SentinelOne, Elastic)
- Related: `defensive-windows-hardening`, `defensive-sysmon`, `defensive-hunt-windows`
