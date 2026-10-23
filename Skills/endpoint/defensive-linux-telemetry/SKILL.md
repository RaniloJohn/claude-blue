---
name: defensive-linux-telemetry
description: "Linux security telemetry and detection: auditd rules and syscall auditing (execve, ptrace, module load, identity files), audit log parsing (ausearch, aureport, laurel for JSON), eBPF sensors (Falco, Tetragon TracingPolicy, Tracee, bcc tools), Sysmon for Linux, osquery, journald/rsyslog/auth.log/PAM, detecting reverse shells, privilege escalation, persistence (cron/systemd/ssh keys/ld.so.preload), container and namespace escape, cryptominers, and web shells. Use when instrumenting Linux servers or writing Linux detections."
---

# Linux Telemetry & Detection

Linux has no single built-in event log equivalent to Sysmon. Combine auditd (syscalls, file watches) or eBPF (rich, low overhead) with auth/journald logs, and ship off-box before attackers with root can clean up.

## Quick Workflow

1. Choose sensor: auditd (universal) and/or eBPF (Falco/Tetragon/EDR)
2. Deploy baseline rules; measure volume
3. Forward auth, sudo, sshd, journald, audit to SIEM
4. Write detections for execution, persistence, privesc, escapes, exfil
5. Protect the pipeline (immutable audit rules `-e 2`, remote logging)

---

## 1. auditd Baseline

```bash
# /etc/audit/rules.d/50-blue.rules
-D
-b 8192
-f 1
## Execution
-a always,exit -F arch=b64 -S execve,execveat -k exec
-a always,exit -F arch=b32 -S execve,execveat -k exec
## Identity & auth
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k priv
-w /etc/sudoers.d/ -p wa -k priv
-w /etc/pam.d/ -p wa -k pam
-w /etc/ssh/sshd_config -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_keys
## Persistence
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k preload
-w /etc/profile.d/ -p wa -k profile
## Kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
## Ptrace / injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k ptrace_poketext
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k ptrace_pokedata
## Network sockets by non-root (optional, volume)
# -a always,exit -F arch=b64 -S connect -F euid!=0 -k net_connect
## Make immutable (requires reboot to change)
-e 2
```

```bash
augenrules --load && auditctl -l
ausearch -k exec -i | tail
aureport -x --summary
```

Laurel (`threathunters-io/laurel`) converts audit records to JSON with process enrichment — easier SIEM parsing. Volume: execve auditing on busy build servers can be heavy; exclude known daemons with `-F exe!=` rules placed before the general rule.

---

## 2. eBPF Sensors

| Tool | Strength |
|---|---|
| Falco | Rules language, container/K8s context, large default ruleset |
| Tetragon (Cilium) | TracingPolicy kprobes/tracepoints, in-kernel filtering and enforcement |
| Tracee (Aqua) | Signatures, forensics capture |
| bcc-tools | Ad-hoc: `execsnoop-bpfcc`, `opensnoop-bpfcc`, `tcpconnect-bpfcc`, `bashreadline-bpfcc` |

Tetragon policy (adapt from project examples):

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: watch-shadow-reads
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values: ["/etc/shadow"]
```

Falco rule:

```yaml
- rule: CB Reverse Shell via Redirect
  desc: Shell with stdin/stdout redirected to a network socket
  condition: >
    evt.type in (dup, dup2, dup3) and evt.dir = < and
    proc.name in (shell_binaries) and
    fd.num in (0, 1, 2) and fd.type in (ipv4, ipv6)
  output: "Possible reverse shell (cmd=%proc.cmdline user=%user.name conn=%fd.name container=%container.name)"
  priority: CRITICAL
  tags: [T1059.004]
```

(Falco's default ruleset includes a maintained "Redirect STDOUT/STDIN to Network Connection in Container" rule — prefer upstream rules where available.)

---

## 3. Sysmon for Linux & osquery

```bash
sudo sysmon -accepteula -i config.xml        # eBPF-based; events to syslog
osqueryi "SELECT pid,name,path,cmdline FROM processes WHERE on_disk=0;"
osqueryi "SELECT * FROM listening_ports lp JOIN processes p USING(pid) WHERE lp.address NOT IN ('127.0.0.1','::1');"
osqueryi "SELECT * FROM crontab;"
osqueryi "SELECT * FROM authorized_keys;"
osqueryi "SELECT * FROM suid_bin;"
```

---

## 4. Detections

| Behavior | Signal |
|---|---|
| Reverse shell | `bash -i >& /dev/tcp/`, `nc -e`, `ncat --exec`, `socat exec:`, `python -c 'import socket,subprocess'`, `mkfifo` + `nc` |
| Download & execute | `curl|wget` piped to `sh`/`bash`; exec from `/tmp`, `/dev/shm`, `/var/tmp` |
| Web shell | Parent `nginx`/`apache2`/`httpd`/`php-fpm`/`java` (Tomcat) spawning `sh`, `id`, `whoami`, `uname` |
| Privesc | `sudo` failures then success; SUID binary exec by unusual user; `pkexec`; capability abuse (`setcap`) |
| Persistence | Writes to cron/systemd/`authorized_keys`/`ld.so.preload`/`.bashrc` (auditd keys) |
| Defense evasion | `history -c`, `unset HISTFILE`, `HISTSIZE=0`, log truncation (`> /var/log/auth.log`), `auditctl -D` |
| Kernel module | `insmod`/`modprobe` outside patch windows |
| Container escape | `nsenter -t 1`, mount of host `/`, writes to `/proc/sys/kernel/core_pattern`, cgroup `release_agent`, access to `/var/run/docker.sock` |
| Cryptominer | `xmrig`, stratum protocol (`stratum+tcp`), sustained high CPU, connections to pool ports (3333, 4444, 5555, 14444) |
| Credential access | Reads of `/etc/shadow`, SSH private keys, cloud creds (`~/.aws/credentials`), `/proc/<pid>/mem` |

```spl
index=linux sourcetype=linux:audit key=exec
| eval cmd=coalesce(proctitle, exe)
| search cmd IN ("*/dev/tcp/*","*nc -e*","*ncat*--exec*","*socat*exec*","*mkfifo*") OR exe IN ("/tmp/*","/dev/shm/*","/var/tmp/*")
```

---

## 5. Auth Logs

```bash
grep -E "sshd.*(Accepted|Failed|Invalid user)" /var/log/auth.log
grep -E "sudo:.*COMMAND=" /var/log/auth.log
journalctl _COMM=sshd --since "1 hour ago" -o json | jq -r '.MESSAGE'
```

Forward with rsyslog (TCP+TLS) or an agent; local logs are not trustworthy after root compromise.

---

## Engagement Cheatsheet

```text
auditd baseline (-e 2) or eBPF sensor → forward auth/journald/audit → detections
(reverse shell, /tmp exec, web shell parent, persistence writes, escapes, miners) → tune volume
```

---

## Key References

- Linux Audit documentation; Neo23x0/auditd rules; laurel
- Falco rules — https://github.com/falcosecurity/rules ; Tetragon docs
- osquery schema — https://osquery.io/schema
- Related: `defensive-linux-forensics`, `defensive-linux-hardening`, `defensive-k8s-security`
