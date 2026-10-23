---
name: defensive-quick-checks
description: "Fast compromise-assessment checklists for the first 30 minutes on a suspect Windows, Linux, or macOS host, cloud account, or M365/Entra identity: volatile state, suspicious processes and network connections, persistence locations, recent accounts and logons, security tool status, scheduled tasks/services/cron, recently modified files, and quick cloud/identity checks. Includes copy-paste command sequences and red-flag tables. Use when an analyst needs to quickly decide whether a system is compromised before deeper forensics."
---

# Quick Compromise Checks

Thirty minutes, read-only, evidence-preserving. Goal: decide **compromised / suspicious / clean-so-far** and what to collect next. Run from trusted tools (EDR live response or known-good binaries); record UTC times; save outputs.

## Quick Workflow

1. Record context (host, user, alert, UTC time); start memory capture if compromise likely
2. Processes & network
3. Persistence
4. Accounts & logons
5. Security tooling status
6. Recent file activity
7. Verdict → escalate / collect / close

---

## 1. Windows (PowerShell, admin)

```powershell
$o="C:\IR\$(hostname)_$(Get-Date -Format yyyyMMddTHHmmssZ)"; mkdir $o | Out-Null
# Processes with parents and command lines
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | Export-Csv $o\procs.csv -NoType
# Network
Get-NetTCPConnection | ? State -in 'Established','Listen' | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA 0).Path}} | Export-Csv $o\net.csv -NoType
Get-DnsClientCache | Export-Csv $o\dns.csv -NoType
# Persistence
Get-CimInstance Win32_StartupCommand | Export-Csv $o\startup.csv -NoType
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run*,HKCU:\Software\Microsoft\Windows\CurrentVersion\Run* -EA 0 | Out-File $o\runkeys.txt
Get-ScheduledTask | ? State -ne Disabled | Select TaskPath,TaskName,@{n='Exec';e={($_.Actions|%{$_.Execute+' '+$_.Arguments}) -join ';'}} | Export-Csv $o\tasks.csv -NoType
Get-CimInstance Win32_Service | Select Name,State,StartMode,PathName,StartName | Export-Csv $o\services.csv -NoType
Get-CimInstance -Namespace root\subscription -Class __EventConsumer | Out-File $o\wmi_consumers.txt
# Accounts & logons
Get-LocalUser | Select Name,Enabled,LastLogon,PasswordLastSet | Out-File $o\localusers.txt
Get-LocalGroupMember Administrators | Out-File $o\admins.txt
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4672,4720,4732;StartTime=(Get-Date).AddDays(-3)} -EA 0 | Select TimeCreated,Id,Message | Export-Csv $o\sec_events.csv -NoType
# Security tooling
Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated | Out-File $o\defender.txt
Get-MpPreference | Select ExclusionPath,ExclusionProcess,ExclusionExtension | Out-File $o\exclusions.txt
Get-Service Sysmon*,Sense,WinDefend -EA 0 | Out-File $o\sec_services.txt
# Recent executables in user-writable paths (7 days)
Get-ChildItem C:\Users\*\AppData,C:\ProgramData,C:\Windows\Temp,C:\Users\Public -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.js,*.hta -EA 0 | ? LastWriteTime -gt (Get-Date).AddDays(-7) | Select FullName,Length,LastWriteTime | Export-Csv $o\recent_exec.csv -NoType
```

### Windows Red Flags

| Finding | Why |
|---|---|
| Process from `AppData`, `Temp`, `ProgramData`, `Public` with network connections | Common malware staging |
| `rundll32`/`regsvr32`/`mshta` with network or no DLL argument | LOLBin abuse |
| Service `PathName` with `cmd /c`, `powershell`, random names | PsExec/Impacket/persistence |
| Scheduled task running from user-writable path or encoded PowerShell | Persistence |
| WMI `CommandLineEventConsumer` | Fileless persistence |
| New local admin / unknown user | Backdoor account |
| Defender RTP off, new exclusions, Sysmon stopped | Defense evasion |
| Security log recently cleared (1102) | Anti-forensics |
| RMM tools (AnyDesk, ScreenConnect, Atera) not approved | Remote access persistence |

---

## 2. Linux

```bash
o=/root/ir_$(hostname)_$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $o
ps auxwwf > $o/ps.txt; ss -tulpanw > $o/ss.txt; lsof -nP -i > $o/lsof_net.txt 2>/dev/null
ls -la /proc/*/exe 2>/dev/null | grep -E '\(deleted\)|/tmp/|/dev/shm/' > $o/suspicious_exe.txt
last -F -i > $o/last.txt; lastb -F -i 2>/dev/null | head -200 > $o/lastb.txt
grep -hE "Accepted|Failed|sudo:" /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -500 > $o/auth.txt
awk -F: '$3==0' /etc/passwd > $o/uid0.txt
for u in /root /home/*; do ls -la $u/.ssh 2>/dev/null; cat $u/.ssh/authorized_keys 2>/dev/null; done > $o/ssh_keys.txt
crontab -l > $o/root_cron.txt 2>&1; ls -la /etc/cron* /var/spool/cron/* > $o/cron.txt 2>&1
systemctl list-unit-files --state=enabled > $o/enabled_units.txt; systemctl list-timers --all > $o/timers.txt
cat /etc/ld.so.preload > $o/preload.txt 2>&1; lsmod > $o/lsmod.txt
find / -xdev \( -path /proc -o -path /sys \) -prune -o -type f -newermt "7 days ago" \( -path "/tmp/*" -o -path "/dev/shm/*" -o -path "/var/tmp/*" -o -path "/etc/*" -o -path "/usr/bin/*" \) -print 2>/dev/null > $o/recent_files.txt
(debsums -s 2>/dev/null || rpm -Va 2>/dev/null | grep '^..5') > $o/pkg_integrity.txt
```

### Linux Red Flags

Deleted-but-running binaries; processes from `/tmp`, `/dev/shm`; unknown UID 0 accounts; new `authorized_keys`; cron/systemd entries running `curl|sh`, base64, or from temp dirs; `ld.so.preload` content; unknown kernel modules; modified system binaries; web server user spawning shells; connections to mining pools (3333/4444/5555/14444) or rare IPs.

---

## 3. macOS

```bash
o=~/ir_$(hostname)_$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $o
ps auxww > $o/ps.txt; lsof -nP -i > $o/net.txt
sudo sfltool dumpbtm > $o/btm.txt
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons > $o/launch.txt
profiles list -all > $o/profiles.txt 2>&1
log show --last 24h --predicate 'process == "osascript" OR process == "sudo" OR process == "sshd"' > $o/ul.txt
```

Red flags: unsigned launch items; binaries in `/Users/Shared`, `/tmp`, `~/Library/Application Support/<random>`; unexpected configuration profiles; `osascript` password prompts; `curl` uploads of archives.

---

## 4. Cloud & Identity (fast)

| Platform | Check |
|---|---|
| AWS | CloudTrail last 7 d for principal: new keys/users/roles, policy attachments, `StopLogging`, unusual regions; GuardDuty findings |
| Azure/Entra | Sign-ins from new countries/ASNs; MFA method changes; role assignments; app consents; inbox rules |
| GCP | SA key creation, `SetIamPolicy` adds, `GenerateAccessToken`, sink changes |
| M365 | Inbox rules, forwarding, `MailItemsAccessed` spikes, OAuth grants |

---

## 5. Verdict

| Verdict | Criteria | Next |
|---|---|---|
| Compromised | Any confirmed malicious persistence, tool, C2, or unauthorized access | IR: contain + full collection (`defensive-incident-response`) |
| Suspicious | Anomalies without confirmation | Memory + triage collection; hunt related hosts |
| Clean so far | No red flags in checks | Document scope of checks; monitor |

---

## Engagement Cheatsheet

```text
context + memory (if likely) → procs/net → persistence → accounts/logons → security tooling → recent files
→ red-flag tables → verdict → escalate/collect/monitor
```

---

## Key References

- SANS Intrusion Discovery Cheat Sheets (Windows/Linux)
- Microsoft Defender for Endpoint live response; Velociraptor triage artifacts
- Related: `defensive-live-response`, `defensive-incident-response`, `defensive-alert-triage`
