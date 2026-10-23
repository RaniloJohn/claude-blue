---
name: defensive-detect-execution
description: "Detection pack for MITRE ATT&CK Execution (TA0002): command and scripting interpreters (PowerShell, cmd, VBScript/JScript, Python, Unix shells, AppleScript, JavaScript), WMI (T1047), scheduled task/job execution, system services (T1569), user execution of malicious files/links (T1204), native API, shared modules, container administration commands (T1609), serverless execution, software deployment tools (T1072), and inter-process communication (T1559). Telemetry, Sigma/SPL/KQL/EQL detections, FPs, and pivots. Use when writing or reviewing execution detections."
---

# Detection Pack — Execution (TA0002)

Execution is where most endpoint detections live. Focus on interpreter abuse with suspicious content or lineage, remote execution primitives (WMI, services, deployment tools), and execution from user-writable locations.

## Quick Workflow

1. Telemetry: process creation with command line (Sysmon 1 / 4688 + cmdline GPO / EDR), PowerShell 4104, WMI-Activity, auditd execve
2. Deploy content-based (encoded, download cradles) and lineage-based detections
3. Baseline admin tooling and deployment systems
4. Promote with triage guides

---

## 1. Technique → Signal

| Technique | Signal |
|---|---|
| T1059.001 PowerShell | `-enc`/`-EncodedCommand`, `IEX`, `DownloadString`, `FromBase64String`, `-w hidden`, `-nop`, `-ep bypass`; 4104 content |
| T1059.003 cmd | `cmd /c` chains from Office/web servers; `^`-obfuscation; `for /f` loops |
| T1059.005 VBScript / T1059.007 JavaScript | `wscript`/`cscript` running from Downloads/Temp; `.js`/`.vbs`/`.wsf`/`.hta` |
| T1059.004 Unix shell | `bash -c` with curl/wget pipes; reverse shell patterns |
| T1059.006 Python | `python -c` with socket/subprocess/base64 |
| T1059.002 AppleScript | `osascript -e` with `display dialog` (password phishing) or `do shell script` |
| T1047 WMI | `wmic process call create`, `Invoke-WmiMethod`, `WmiPrvSE.exe` children |
| T1569.002 Service execution | 7045/4697 new service with `cmd /c` / random name; `services.exe` children |
| T1053.005 Scheduled task | `schtasks /create`, 4698; taskeng/`svchost -k netsvcs -p -s Schedule` children |
| T1204.002 Malicious file | Executables launched by `explorer.exe` from Downloads/Temp/archives |
| T1072 Software deployment tools | SCCM/Intune/PDQ/RMM executing unexpected payloads |
| T1609 Container admin command | `kubectl exec`, `docker exec` (K8s audit `pods/exec`) |
| T1559.001 COM | Office spawning via DCOM; `mmc.exe`/`excel.exe` as parents with no UI |

---

## 2. Detections

### Suspicious PowerShell command line

```yaml
title: Suspicious PowerShell Command Line
logsource: { product: windows, category: process_creation }
detection:
  img:
    - Image|endswith: ['\powershell.exe','\pwsh.exe']
    - OriginalFileName: ['PowerShell.EXE','pwsh.dll']
  flags:
    CommandLine|windash|contains:
      - ' -enc'
      - ' -encodedcommand'
      - ' -w hidden'
      - ' -windowstyle hidden'
      - ' -ep bypass'
      - ' -executionpolicy bypass'
  content:
    CommandLine|contains:
      - 'IEX'
      - 'Invoke-Expression'
      - 'DownloadString'
      - 'DownloadFile'
      - 'FromBase64String'
      - 'Net.WebClient'
      - 'Invoke-WebRequest'
      - 'Start-BitsTransfer'
  condition: img and (flags or content)
level: medium
tags: [attack.execution, attack.t1059.001]
```

### PowerShell script block content (4104)

```spl
index=wineventlog source="*PowerShell/Operational" EventCode=4104
| regex ScriptBlockText="(?i)(AmsiUtils|amsiInitFailed|VirtualAlloc|CreateThread|Reflection\.Assembly\]::Load|System\.Net\.Sockets\.TCPClient|-bxor|\[Convert\]::FromBase64String)"
| stats count values(ScriptBlockText) as blocks by host UserID
```

### WMI remote process creation

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","mshta.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Service creation with shell payload (PsExec-like / Impacket)

```spl
index=wineventlog (EventCode=7045 OR EventCode=4697)
| eval path=coalesce(ImagePath, Service_File_Name)
| where match(path, "(?i)(cmd(\.exe)?\s*/c|%COMSPEC%|powershell|\\\\ADMIN\$|\\\\[0-9a-z]{8}\.exe|\\\\Windows\\\\Temp\\\\)")
| table _time host Service_Name path Account_Name
```

### Execution from user-writable paths (first-seen)

```eql
process where event.type == "start" and
  process.executable : ("?:\\Users\\*\\AppData\\*", "?:\\Users\\Public\\*", "?:\\ProgramData\\*", "?:\\Windows\\Temp\\*", "?:\\Users\\*\\Downloads\\*") and
  not process.code_signature.trusted == true
```

Use Elastic **new terms** on `process.hash.sha256` per host for first-seen tuning.

### Linux interpreter abuse

```spl
index=linux sourcetype=linux:audit key=exec
| search proctitle IN ("*curl*|*sh*","*wget*|*sh*","*bash -i*","*/dev/tcp/*","*python*-c*socket*","*base64 -d*|*sh*")
```

### macOS AppleScript password prompt

Unified Log / ESF: `osascript` exec with args containing `display dialog` and `hidden answer` from an unsigned parent → infostealer.

### Kubernetes exec

```bash
jq -c 'select(.objectRef.subresource=="exec" and (.user.username|test("^system:")|not))' audit.log
```

---

## 3. False Positives

| Detection | FP sources | Tune by |
|---|---|---|
| Encoded PowerShell | SCCM, Intune scripts, monitoring agents, some installers | Parent + signer + host group |
| WMI children | Management tools (SCCM, monitoring) | Specific cmdline patterns + service accounts |
| Service creation | Software installs, patching, remote admin tools | Signed binaries in Program Files |
| User-writable exec | Per-user installs (Teams, Zoom, VS Code, Chrome updaters) | Signer allowlist |

---

## 4. Triage Pivots

1. Decode payloads (Base64 → UTF-16LE for `-enc`) — CyberChef
2. Parent chain to initial access vector
3. Network connections from the same PID ±1 min
4. Files written by the process (Sysmon 11) and their later execution
5. Same command line across fleet (prevalence)

---

## Engagement Cheatsheet

```text
cmdline + 4104 + WMI + service + task telemetry → content & lineage rules → user-writable exec first-seen
→ Linux/macOS/K8s exec → FP tuning by signer/parent → triage: decode → parent → network → files → prevalence
```

---

## Key References

- MITRE ATT&CK TA0002; LOLBAS; GTFOBins
- Microsoft PowerShell logging docs
- Related: `defensive-windows-hardening`, `defensive-tool-cyberchef`, `defensive-hunt-windows`, `defensive-linux-telemetry`
