---
name: defensive-hunt-linux
description: "Threat hunting on Linux servers and cloud workloads: hypotheses and data sources (auditd/Laurel, eBPF/Falco/Tetragon, EDR, osquery, syslog/journald, auth logs, shell history, web logs), hunts for SSH abuse (brute force success, new authorized_keys, agent forwarding), execution from temp directories, curl/wget pipe-to-shell, reverse shells, persistence (cron, systemd, ld.so.preload, PAM, udev), privilege escalation (sudo/SUID/capabilities), cryptomining, webshells, container escapes, and credential access; with SPL, KQL, osquery, and jq examples. Use when proactively hunting across Linux fleets."
---

# Linux Threat Hunting

Linux fleets are often under-monitored. Hunts focus on **how attackers get in (SSH, web apps), what they run (temp-dir binaries, interpreters), and how they stay (cron, systemd, keys, preload)**.

## Quick Workflow

1. Confirm telemetry: process exec with command line (auditd/EDR/eBPF), auth logs, file writes on persistence paths
2. Pick hypothesis (§2); define scope and time window
3. Stack and long-tail across hosts; investigate rare values
4. Validate with host triage (`defensive-linux-malware`)
5. Turn confirmed patterns into detections

---

## 1. Data Sources

| Source | Content |
|---|---|
| auditd (+ Laurel for JSON enrichment) | execve, file watches, syscalls |
| eBPF (Falco, Tetragon, EDR) | Process, network, file events with container context |
| `/var/log/auth.log` / `secure` / journald | SSH logins, sudo |
| osquery | Point-in-time state (processes, ports, keys, cron) |
| Web server logs | Exploitation attempts, webshell access |
| Shell history | Weak signal (attackers clear it); still useful |

---

## 2. Hunts

### SSH success after brute force

```spl
index=linux sourcetype=linux_secure ("Failed password" OR "Accepted password" OR "Accepted publickey")
| rex "(?<action>Failed|Accepted) (password|publickey) for (invalid user )?(?<user>\S+) from (?<src>\S+)"
| stats count(eval(action="Failed")) as fails count(eval(action="Accepted")) as ok values(user) as users by src host
| where fails > 20 AND ok > 0
```

### Execution from temp/hidden paths

```kql
DeviceProcessEvents
| where OSPlatform == "Linux" or DeviceName has "lnx"
| where FolderPath matches regex @"^/(tmp|dev/shm|var/tmp)/" or FolderPath matches regex @"/\.[^/]+/"
| summarize Hosts = dcount(DeviceName), Cmds = make_set(ProcessCommandLine, 10) by FileName, FolderPath
| order by Hosts asc
```

### Download-and-execute

```spl
index=linux (sourcetype=linux:audit OR sourcetype=edr) (proctitle="*curl*" OR proctitle="*wget*") (proctitle="*| sh*" OR proctitle="*| bash*" OR proctitle="*|sh*" OR proctitle="*-O-*|*")
| stats count values(proctitle) by host auid
```

### Reverse shells

Command-line patterns: `bash -i >& /dev/tcp/`, `nc -e`, `ncat --exec`, `python -c 'import socket,subprocess'`, `socat exec:`, `mkfifo /tmp/f`; network: shell processes (`bash`, `sh`) owning outbound TCP connections (Falco `Redirect STDOUT/STDIN to Network Connection in Container`, eBPF).

### Persistence stacking (osquery across fleet)

```sql
SELECT command, path, minute, hour FROM crontab;
SELECT id, path, fragment_path, active_state FROM systemd_units WHERE fragment_path NOT LIKE '/usr/lib/systemd/%' AND fragment_path NOT LIKE '/lib/systemd/%';
SELECT u.username, k.key FROM users u CROSS JOIN authorized_keys k USING (uid);
SELECT * FROM file WHERE path = '/etc/ld.so.preload';
```

Stack results across hosts: entries present on 1–2 hosts are leads.

### Privilege escalation

- `sudo` to shells/interpreters by users who rarely sudo
- New SUID files (`find / -perm -4000 -newermt "7 days ago"`), `setcap` usage
- Processes with euid 0 whose parent isn't sudo/su/systemd/management agent

### Cryptomining

High CPU processes with random names; DNS/connections to pool domains; `xmrig` strings in binaries; competitor-killing scripts (`pkill -f kdevtmpfsi`, etc.); cron entries re-downloading payloads.

### Webshells

Web server user (`www-data`, `nginx`, `apache`) spawning `sh`, `id`, `whoami`, `uname`, `curl`; new `.php`/`.jsp` files in web roots; POST requests to rarely accessed script files in access logs.

### Container escape indicators

`nsenter`, `mount` of host filesystems from containers, writes to `/proc/sys/kernel/core_pattern` or cgroup `release_agent`, privileged pods created by unusual service accounts (`defensive-k8s-security`).

---

## 3. Validation & Output

For each lead: confirm on host, check package ownership (`dpkg -S`/`rpm -qf`), compare hash against package manifest (`debsums`, `rpm -Va`), review creation times and parent processes. Record in Hunt Report template (router); feed detections to `defensive-detection-as-code`.

---

## Engagement Cheatsheet

```text
telemetry check (auditd/eBPF/EDR/auth/osquery) → hypotheses: SSH brute→success, new keys, temp-dir exec, curl|sh, reverse shells,
cron/systemd/preload stacking, sudo/SUID/caps, miners, webshells, container escape → stack rare → validate (dpkg -S, debsums, rpm -Va) → detections
```

---

## Key References

- auditd/Laurel; Falco rules; Cilium Tetragon; osquery schema; MITRE ATT&CK Linux matrix
- Related: `defensive-linux-telemetry`, `defensive-linux-malware`, `defensive-threat-hunting`, `defensive-tool-osquery`, `defensive-detect-persistence`
