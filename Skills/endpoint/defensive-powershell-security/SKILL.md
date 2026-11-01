---
name: defensive-powershell-security
description: "PowerShell defense end to end: logging (script block 4104, module 4103, transcription, Protected Event Logging with CMS certificates), Windows PowerShell 5.1 vs PowerShell 7 log channels and powershell.config.json, PowerShell 2.0 removal from Windows 11 24H2/Server 2025 and downgrade-attack checks (event 400 EngineVersion), Constrained Language Mode enforced by App Control/AppLocker, AMSI and Defender ASR obfuscated-script rule, JEA endpoints (role capability, virtual accounts, gMSA), execution policy limits, remoting/WinRM hardening, PowerShell 7 lifecycle (7.6 LTS; 7.4/7.5 EOS 2026-11-10), detection queries (KQL, SPL, Sigma) for encoded commands, download cradles, AMSI bypass and log tampering. Use when hardening, logging, hunting, or investigating PowerShell."
---

# PowerShell Security

PowerShell is the attacker's favorite built-in tool and the defender's best telemetry source. You can't remove it. Make it **observable** (script block logging everywhere), **constrained** (CLM via App Control), and **delegated** (JEA instead of admin rights).

## Quick Workflow

1. Inventory engines: Windows PowerShell 5.1, PowerShell 7.x versions, and PowerShell 2.0 on older OS builds
2. Turn on script block + module logging for **both** 5.1 and 7; ship both channels to the SIEM
3. Remove or disable PowerShell 2.0 wherever it still exists
4. Enforce Constrained Language Mode through App Control/AppLocker (not by hand)
5. Keep AMSI intact; enable the Defender ASR obfuscated-script rule
6. Replace standing admin access with JEA endpoints for routine tasks
7. Harden remoting (WinRM over HTTPS, restricted source IPs)
8. Deploy detections for encoded commands, cradles, AMSI tampering, and log clearing

---

## 1. Know Your Engines

| Engine | Ships with | Log channel | Policy registry root |
|--------|-----------|-------------|----------------------|
| Windows PowerShell 5.1 (`powershell.exe`) | Windows (Windows lifecycle) | `Microsoft-Windows-PowerShell/Operational` + classic `Windows PowerShell` | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell` |
| PowerShell 7 (`pwsh.exe`) | Separate install (.NET) | `PowerShellCore/Operational` | `HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore` |
| PowerShell 2.0 | Optional feature, older builds only | Classic log only, **no script block logging, no AMSI** | — |

**PowerShell 7 lifecycle (as of Oct 2026)** — only the latest patch of each release is supported:

| Release | .NET | End of support |
|---------|------|----------------|
| 7.6 LTS (released 2026-03-18) | .NET 10 | 2028-11-14 |
| 7.5 Stable | .NET 9 | **2026-11-10** |
| 7.4 LTS | .NET 8 | **2026-11-10** |
| 7.2 / 7.3 | — | Retired |

Move fleets to 7.6 LTS now. Unsupported `pwsh` installs bundled by vendors are a common blind spot, so hunt for `pwsh.exe` by version.

```powershell
$PSVersionTable.PSVersion
[System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
Get-ChildItem 'C:\Program Files\PowerShell' -Directory   # side-by-side installs
```

---

## 2. PowerShell 2.0 & Downgrade Attacks

PowerShell 2.0 predates AMSI and script block logging, so `powershell -Version 2` used to be a standard evasion trick.

- **Removed** from Windows 11 24H2 starting with the August 2025 update (KB5065506), and from Windows Server 2025 starting with the September 2025 update. On those builds `-Version 2` runs 5.1.
- **Still present** on Windows 10, Server 2016/2019/2022 and older Windows 11 builds where the optional feature is enabled.

```powershell
# Check & remove on older builds
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
# Server
Uninstall-WindowsFeature PowerShell-V2
```

Detection: classic `Windows PowerShell` log event **400** (engine start) with `EngineVersion=2.0` or `HostVersion=2.0`, or a process command line containing `-version 2` / `-v 2`. Block the 2.0 engine with App Control as well, since it needs .NET 2.0/3.5.

---

## 3. Logging

| Event ID | Channel | Meaning |
|----------|---------|---------|
| 4104 | PS Operational / PowerShellCore Operational | Script block text (de-obfuscated at compile time) |
| 4103 | same | Module/pipeline execution detail |
| 4105 / 4106 | same | Script block invocation start/stop (very noisy; leave off unless needed) |
| 400 / 403 | Windows PowerShell (classic) | Engine start/stop: version, host application |
| 800 | Windows PowerShell (classic) | Pipeline execution detail |

Even with logging off, PowerShell 5+ automatically logs script blocks containing suspicious keywords as **4104 Warning**. Don't rely on that alone.

### Windows PowerShell 5.1 (GPO)

`Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`:
- Turn on Module Logging → module names `*`
- Turn on PowerShell Script Block Logging (leave invocation logging off)
- Turn on PowerShell Transcription → output directory on a write-only share; include invocation headers

### PowerShell 7

GPO templates live under `Administrative Templates > PowerShell Core` (install the ADMX shipped in `$PSHOME`). The event provider must be registered, or 4104 events never appear:

```powershell
& "$PSHOME\RegisterManifest.ps1"          # unregister before upgrading pwsh, re-register after

$base = 'HKLM:\Software\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
if (-not (Test-Path $base)) { $null = New-Item $base -Force }
Set-ItemProperty $base -Name EnableScriptBlockLogging -Value 1
```

Cross-platform (Linux/macOS, or Windows without GPO): set `powershell.config.json` in `$PSHOME`. On Windows, Group Policy overrides it. **Invalid JSON stops interactive sessions from starting**, so validate before you deploy.

```json
{
  "PowerShellPolicies": {
    "ScriptBlockLogging": { "EnableScriptBlockLogging": true },
    "ModuleLogging": { "EnableModuleLogging": true, "ModuleNames": ["*"] },
    "Transcription": { "EnableTranscripting": true, "EnableInvocationHeader": true,
                       "OutputDirectory": "C:\\PSTranscripts" }
  }
}
```

On non-Windows systems the logs go to syslog / os_log (keys `LogChannels`, `LogLevel`, `LogIdentity`).

### Protected Event Logging

Script blocks capture secrets that admins paste into scripts. Encrypt them with CMS so only the collector can read them:

1. Issue a certificate with the **Document Encryption EKU (1.3.6.1.4.1.311.80.1)**; deploy only the public key to endpoints
2. GPO: `Windows Components > Event Logging > Enable Protected Event Logging` → paste the certificate
3. Decrypt on the collector, which holds the private key:

```powershell
Get-WinEvent Microsoft-Windows-PowerShell/Operational |
  Where-Object Id -eq 4104 | Unprotect-CmsMessage
```

Tradeoff: your SIEM can't search encrypted text unless it decrypts at ingest. Many SOCs instead enable plaintext logging and restrict access to the log index.

### Sizing

Raise the Operational log size (e.g. 1 GB) and forward events in near real time. Attackers clear logs, so the forwarded copy is your evidence.

---

## 4. Constrained Language Mode (CLM)

- CLM blocks arbitrary .NET types, Add-Type, most COM objects (only Scripting.Dictionary, Scripting.FileSystemObject and VBScript.RegExp are allowed) and direct Win32 API calls, which kills most offensive tooling.
- It is a **security boundary only when enforced by App Control for Business or AppLocker** script rules. Allowed (signed or allowlisted) scripts run in FullLanguage; everything else runs in CLM.
- Setting `$ExecutionContext.SessionState.LanguageMode` or the `__PSLockdownPolicy` environment variable by hand is **not** a control, because it is trivially undone.
- Verify with `$ExecutionContext.SessionState.LanguageMode`. PowerShell 7.4+ shows CLM in the startup banner.
- See `defensive-application-control` for the policy work.

Test admin tooling in audit mode first. Scripts that call `Add-Type` or `[System.Reflection.Assembly]` break under CLM and need code signing.

---

## 5. AMSI & Defender

- AMSI passes de-obfuscated script content (PowerShell, VBScript, JScript, Office VBA, .NET in-memory loads) to the antivirus before it runs.
- Keep Defender, or a third-party AV that registers as an AMSI provider, active. Real-time protection off means AMSI is blind.
- ASR rule **Block execution of potentially obfuscated scripts** — `5beb7efe-fd9a-4556-801d-275e5ffc04cc` (audit first).
- Common bypass patterns to detect: `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer` patching, `System.Management.Automation.AmsiUtils` reflection, and unloading or hijacking `amsi.dll`. AMSI catches many of these strings itself, and the 4104 log records the attempt even when it succeeds.

---

## 6. Execution Policy Is Not Security

`Set-ExecutionPolicy` is a safety feature against accidental script runs. `-ExecutionPolicy Bypass`, piping scripts to `iex`, and `-EncodedCommand` all ignore it. Set `AllSigned` or `RemoteSigned` through GPO for hygiene, but count on CLM + App Control + logging for actual protection.

---

## 7. Just Enough Administration (JEA)

JEA (Windows PowerShell 5.1+) gives helpdesk staff a remoting endpoint that exposes only the cmdlets they need, running as a temporary virtual account or a gMSA. No admin group membership required.

```powershell
# Role: what can be run
New-PSRoleCapabilityFile -Path 'C:\Program Files\WindowsPowerShell\Modules\JEA\RoleCapabilities\Helpdesk.psrc' `
  -VisibleCmdlets 'Get-Service', @{ Name='Restart-Service'; Parameters=@{ Name='Name'; ValidateSet='Spooler','W32Time' } }

# Session: who maps to which role, and the run-as identity
New-PSSessionConfigurationFile -Path .\Helpdesk.pssc -SessionType RestrictedRemoteServer `
  -RunAsVirtualAccount -TranscriptDirectory 'C:\JEA\Transcripts' `
  -RoleDefinitions @{ 'CORP\Helpdesk' = @{ RoleCapabilities = 'Helpdesk' } }

Test-PSSessionConfigurationFile .\Helpdesk.pssc
Register-PSSessionConfiguration -Name Helpdesk -Path .\Helpdesk.pssc -Force

# User side
Enter-PSSession -ComputerName srv01 -ConfigurationName Helpdesk
```

JEA pitfalls (escape routes):
- Never expose `Invoke-Expression`, `Start-Process`, `New-Service`, `Add-Type`, unrestricted `Set-Item`, `Copy-Item` or any cmdlet that accepts a script block or arbitrary path. Each of these is a path back to full admin.
- Constrain parameters with `ValidateSet` / `ValidatePattern`.
- Use `RestrictedRemoteServer`. A virtual account is a local admin on the box, so the role definition *is* the boundary.
- Ship the JEA transcripts and the 4104 logs from the endpoint.

---

## 8. Remoting Hardening

- WinRM over HTTPS (5986), or Kerberos-only over 5985 inside the domain. Never use `AllowUnencrypted` or Basic auth.
- Allow 5985/5986 only from admin jump hosts / PAWs (Windows Firewall remote-address scoping).
- Restrict the default endpoint's SDDL (`Set-PSSessionConfiguration Microsoft.PowerShell -ShowSecurityDescriptorUI`) and remove broad groups.
- Avoid CredSSP. Use JEA, Kerberos constrained delegation, or `-Credential` on the remote side.
- Monitor: `Microsoft-Windows-WinRM/Operational` 91 (session created), 4624 logon type 3 with `wsmprovhost.exe` as the child process.

---

## 9. Detection

**High-signal patterns**
- `-enc` / `-EncodedCommand` / `-e ` with long base64, especially with a parent process of Office, browser, `wmiprvse.exe`, or `mshta.exe`
- Download cradles: `IEX (New-Object Net.WebClient).DownloadString`, `Invoke-WebRequest … | iex`, `Start-BitsTransfer`, `[Net.WebRequest]`
- Reflection/in-memory: `[System.Reflection.Assembly]::Load`, `VirtualAlloc`, `GetDelegateForFunctionPointer`
- AMSI/logging tampering: `amsiInitFailed`, `AmsiScanBuffer`, `EnableScriptBlockLogging` set to 0, `wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`
- Downgrade: event 400 with `EngineVersion=2.0`
- `powershell.exe` loaded in unusual hosts (`System.Management.Automation.dll` loaded by non-PowerShell processes = unmanaged PowerShell / PowerPick)

**Microsoft Defender XDR (KQL)**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{40,}"
   or ProcessCommandLine has_any ("DownloadString","FromBase64String","-version 2","IEX(")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

```kql
// Unmanaged PowerShell: automation DLL loaded outside PowerShell hosts
DeviceImageLoadEvents
| where FileName =~ "System.Management.Automation.dll" or FileName startswith "System.Management.Automation.ni"
| where InitiatingProcessFileName !in~ ("powershell.exe","pwsh.exe","powershell_ise.exe","wsmprovhost.exe")
| summarize count() by InitiatingProcessFileName, DeviceName
```

**Splunk (4104)**
```spl
index=wineventlog (source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" OR source="XmlWinEventLog:PowerShellCore/Operational") EventCode=4104
| search ScriptBlockText IN ("*AmsiUtils*","*amsiInitFailed*","*AmsiScanBuffer*","*VirtualAlloc*","*DownloadString*","*FromBase64String*")
| stats count values(ScriptBlockText) as script by host, UserID
```

**Sigma (AMSI bypass in script block)**
```yaml
title: PowerShell AMSI Bypass Strings in Script Block
status: experimental
logsource: { product: windows, category: ps_script }
detection:
  selection:
    ScriptBlockText|contains: ['AmsiUtils', 'amsiInitFailed', 'AmsiScanBuffer', 'amsiContext']
  condition: selection
level: high
tags: [attack.defense-evasion, attack.t1562.001]
```

To reconstruct large scripts split over multiple 4104 events, group by `ScriptBlockId` and order by `MessageNumber`. See `defensive-script-deobfuscation` for decoding.

---

## 10. Linux & macOS

`pwsh` on Linux and macOS is used for admin automation and sometimes by attackers. Enable logging in `powershell.config.json` (forwarded through syslog / unified logs), monitor `pwsh` process creation with auditd/EDR, and remove it where nothing needs it.

---

## Engagement Cheatsheet

| Need | Do |
|------|----|
| Baseline logging | GPO: SBL + module `*` for 5.1 **and** PowerShell Core; `RegisterManifest.ps1` for pwsh |
| Kill downgrade | Disable the `MicrosoftWindowsPowerShellV2Root` feature; alert on event 400 `EngineVersion=2.0` |
| Stop offensive tooling | App Control/AppLocker script enforcement → CLM |
| Secrets in logs | Protected Event Logging (EKU 1.3.6.1.4.1.311.80.1) or locked-down SIEM index |
| Helpdesk without admin | JEA, `RestrictedRemoteServer`, virtual account, `ValidateSet` parameters |
| Obfuscation | ASR `5beb7efe-fd9a-4556-801d-275e5ffc04cc` + AMSI-capable AV |
| Version hygiene | Upgrade to 7.6 LTS; 7.4/7.5 go end of support 2026-11-10 |
| Investigate | 4104 by `ScriptBlockId`, 400/403 host/version, 4103, transcripts, WinRM 91 |

Related: `defensive-application-control`, `defensive-windows-hardening`, `defensive-windows-event-logs`, `defensive-detect-execution`, `defensive-detect-defense-evasion`, `defensive-script-deobfuscation`, `defensive-hunt-windows`, `defensive-pam`.

## Key References

- about_Logging_Windows — https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows
- about_PowerShell_Config — https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_config
- about_Language_Modes — https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes
- PowerShell support lifecycle — https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
- PowerShell 2.0 removal (KB5065506) — https://support.microsoft.com/help/5065506
- JEA overview — https://learn.microsoft.com/powershell/scripting/security/remoting/jea/overview
- AMSI — https://learn.microsoft.com/windows/win32/amsi/antimalware-scan-interface-portal
- ASR rules reference — https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference
- MITRE ATT&CK T1059.001 PowerShell — https://attack.mitre.org/techniques/T1059/001/
