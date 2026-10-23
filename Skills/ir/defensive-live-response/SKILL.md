---
name: defensive-live-response
description: "Live response and remote forensic collection at scale: Velociraptor (VQL hunts, artifacts, offline collectors), EDR live response consoles (Defender, CrowdStrike RTR, SentinelOne), KAPE triage, UAC for Linux/macOS, memory acquisition (WinPmem, DumpIt, avml, LiME), volatile data commands for Windows/Linux, evidence integrity, and safe remote collection without tipping off the adversary. Use when collecting evidence from live systems, running fleet-wide hunts for an IOC, or building an offline collector for an isolated host."
---

# Live Response & Remote Collection

Collect what you need, from where you need it, without destroying it. Fleet-scale questions ("which hosts have this file/service/connection?") are answered with Velociraptor or EDR hunts, not by logging into machines.

## Quick Workflow

1. Define questions → artifacts needed
2. Pick tool: EDR live response (single host), Velociraptor (fleet), offline collector (isolated/no agent)
3. Memory first on key hosts
4. Collect triage artifacts; hash outputs
5. Hunt fleet-wide for confirmed indicators
6. Store in case repository with chain of custody

---

## 1. Velociraptor

| Concept | Meaning |
|---|---|
| Artifact | Packaged VQL (e.g. `Windows.KapeFiles.Targets`, `Windows.System.Pslist`) |
| Collection | Run artifacts on one client |
| Hunt | Run artifacts across many clients |
| Offline collector | Standalone binary that collects and zips results without a server |
| Notebook | Post-process results with VQL |

Useful artifacts:

| Artifact | Purpose |
|---|---|
| `Windows.KapeFiles.Targets` | KAPE-style triage file collection |
| `Windows.Memory.Acquisition` | Memory image |
| `Windows.System.Pslist`, `Windows.Network.Netstat` | Volatile state |
| `Windows.Sysinternals.Autoruns` | Persistence |
| `Windows.EventLogs.EvtxHunter` | Keyword search across EVTX |
| `Windows.Detection.Yara.Process` / `Generic.Detection.Yara.Glob` | YARA on memory / files |
| `Windows.Forensics.Prefetch`, `Windows.Forensics.SRUM`, `Windows.NTFS.MFT` | Execution and file artifacts |
| `Linux.Sys.BashHistory`, `Linux.Collection.UAC` | Linux triage |

VQL example — find a file by hash across fleet:

```sql
SELECT FullPath, Size, Mtime, hash(path=FullPath).SHA256 AS sha256
FROM glob(globs="C:/Users/*/AppData/**/*.exe")
WHERE sha256 = "<sha256>"
```

Security: keep server patched (2026 advisories fixed privilege issues in client monitoring artifacts — upgrade to ≥0.77.2), restrict who can schedule `EXECVE`-capable artifacts, MFA on GUI.

---

## 2. EDR Live Response

| Platform | Capabilities |
|---|---|
| Microsoft Defender for Endpoint | Live response: `processes`, `connections`, `getfile`, `run` (signed scripts), `collect investigation package`, isolate |
| CrowdStrike RTR | `ps`, `netstat`, `get`, `memdump`, `runscript`; admin vs responder roles |
| SentinelOne | Remote shell, fetch files, Deep Visibility queries |

Log every command executed; prefer read-only commands until scope is clear.

---

## 3. Memory Acquisition

| OS | Tool | Command |
|---|---|---|
| Windows | WinPmem | `winpmem_mini_x64.exe C:\case\mem.raw` |
| Windows | DumpIt / Magnet RAM Capture | GUI/CLI |
| Linux | avml | `sudo ./avml /case/mem.lime` |
| Linux | LiME | kernel module per kernel version |
| macOS | Limited (SIP/Apple silicon) — prefer EDR / UAC volatile data |

Write output to external/remote storage, not the suspect disk. Record hash immediately.

---

## 4. Volatile Data — Windows

```powershell
Get-Date -Format o; hostname; whoami /all
Get-Process | Select Id,ProcessName,Path,StartTime | Sort StartTime
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection | Where State -eq Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
Get-DnsClientCache
Get-ScheduledTask | Where State -ne Disabled | Select TaskName,TaskPath,@{n='Action';e={$_.Actions.Execute}}
Get-CimInstance Win32_Service | Select Name,State,StartMode,PathName
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
query user; net session; klist sessions
```

## 5. Volatile Data — Linux

```bash
date -u; hostname; id; uptime
ps auxwwf; ss -tulpanw; lsof -nP -i
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'
cat /proc/<pid>/maps; cat /proc/<pid>/environ | tr '\0' '\n'
last -F; who; w
crontab -l; ls -la /etc/cron.* /var/spool/cron/; systemctl list-timers --all
systemctl list-units --type=service --state=running
lsmod; cat /etc/ld.so.preload 2>/dev/null
```

UAC (Unix-like Artifacts Collector): `./uac -p ir_triage /evidence` — Linux, macOS, BSD, Solaris, AIX.

---

## 6. KAPE (Windows Triage)

```powershell
kape.exe --tsource C: --tdest E:\case\%m\tout --target !SANS_Triage --vss false `
         --mdest E:\case\%m\mout --module !EZParser --zip %m
```

`--vss true` includes Volume Shadow Copies (slower, more history).

---

## 7. Fleet Hunting Pattern

```text
Confirmed IOC/IOA → Velociraptor/EDR hunt (hash, path, service name, scheduled task, registry key, mutex, YARA)
→ results → new affected hosts → collect triage from each → pivot again
```

---

## 8. OPSEC & Integrity

- Assume the adversary watches: avoid naming files/tasks "incident", avoid emailing about the compromise from compromised mailboxes
- Don't run unknown samples on the suspect host; don't install heavy tools if EDR/Velociraptor can collect
- Minimize changes; document every command with UTC time
- Hash outputs; store in write-once case storage

---

## Engagement Cheatsheet

```text
Questions → tool (EDR/Velociraptor/offline) → memory → volatile → triage (KAPE/UAC)
→ hash + custody → fleet hunt on IOCs → iterate
```

---

## Key References

- Velociraptor docs — https://docs.velociraptor.app
- KAPE (Kroll); UAC — https://github.com/tclahr/uac
- avml — https://github.com/microsoft/avml ; WinPmem — https://github.com/Velocidex/WinPmem
- Related: `defensive-incident-response`, `defensive-windows-forensics`, `defensive-memory-forensics`
