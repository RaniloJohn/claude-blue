---
name: defensive-linux-forensics
description: "Linux host forensics and compromise assessment: triage collection with UAC, auth.log/secure and journald analysis, wtmp/btmp/lastlog, shell histories, auditd/ausearch, cron/systemd/rc/profile persistence, SSH authorized_keys, ld.so.preload and PAM backdoors, kernel modules/rootkits, deleted-but-running binaries, /proc analysis, package integrity (debsums, rpm -Va), web shells, container escapes, file timeline with find/stat/debugfs, ext4 crtime, and memory with avml + Volatility 3 linux plugins. Use for investigating compromised Linux servers and cloud instances."
---

# Linux Forensics

Linux leaves fewer default artifacts than Windows, and attackers with root can alter most of them. Collect volatile state first, compare against package-manager ground truth, and lean on logs shipped off-box.

## Quick Workflow

1. Memory (avml) + volatile state
2. UAC triage collection; hash
3. Auth timeline (logins, sudo, SSH keys)
4. Persistence sweep
5. Binary integrity vs package manager
6. File timeline around anchors
7. Web/app logs if internet-facing

---

## 1. Volatile & Triage

```bash
sudo ./avml /mnt/ext/mem.lime
sudo ./uac -p ir_triage /mnt/ext/
date -u; uptime; uname -a; cat /etc/os-release
ps auxwwf; ss -tulpanw; lsof -nP -i
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'           # running deleted binaries
for p in /proc/[0-9]*; do echo "$p $(tr '\0' ' ' < $p/cmdline)"; done 2>/dev/null
cat /proc/<pid>/environ | tr '\0' '\n'
cp /proc/<pid>/exe /mnt/ext/pid_<pid>.bin                    # recover deleted binary
```

---

## 2. Authentication

| Source | Command |
|---|---|
| auth.log / secure | `grep -E "Accepted|Failed|Invalid user|sudo:|su:" /var/log/auth.log*` |
| journald | `journalctl -u ssh -u sshd --since "2026-10-01" -o short-iso` |
| wtmp (logins) | `last -F -i -f /var/log/wtmp` |
| btmp (failures) | `lastb -F -i` |
| lastlog | `lastlog` |
| SSH keys | `~/.ssh/authorized_keys` all users incl. root; `AuthorizedKeysFile` in `sshd_config` |
| sudoers | `/etc/sudoers`, `/etc/sudoers.d/*` (NOPASSWD entries) |
| Accounts | `/etc/passwd` UID 0 duplicates, new shells; `/etc/shadow` changes |

```bash
awk -F: '$3==0{print}' /etc/passwd
grep -h "Accepted" /var/log/auth.log* | awk '{print $9,$11}' | sort | uniq -c | sort -nr
```

---

## 3. Persistence Locations

| Mechanism | Paths |
|---|---|
| cron | `/etc/crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}/`, `/var/spool/cron/crontabs/` |
| systemd | `/etc/systemd/system/`, `/lib/systemd/system/`, `~/.config/systemd/user/`, timers, generators |
| init/rc | `/etc/init.d/`, `/etc/rc.local` |
| Shell rc | `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `~/.bashrc`, `~/.bash_profile`, `~/.zshrc` |
| SSH | `authorized_keys`, `sshd_config` (`AuthorizedKeysCommand`, `PermitRootLogin`) |
| Preload | `/etc/ld.so.preload`, `LD_PRELOAD` in environment files |
| PAM | `/etc/pam.d/*`, rogue `pam_*.so` in `/lib/*/security/` |
| Kernel | `lsmod`, `/etc/modules`, `/etc/modules-load.d/` |
| udev | `/etc/udev/rules.d/` `RUN+=` |
| at | `/var/spool/cron/atjobs` |
| Web | web roots (`/var/www`) — recently modified `.php`, `.jsp`, `.aspx` |
| Containers | Docker `--restart always` containers, malicious images |

```bash
find /etc/systemd /lib/systemd /usr/lib/systemd ~/.config/systemd -name "*.service" -newermt "2026-10-01" 2>/dev/null
systemctl list-unit-files --state=enabled
grep -r "ExecStart" /etc/systemd/system/ | grep -vE "/usr/(s)?bin|/usr/lib"
```

---

## 4. Binary Integrity

```bash
debsums -s 2>/dev/null                 # Debian/Ubuntu: changed package files
rpm -Va | grep -E '^..5'               # RHEL: files with changed MD5
find / -xdev -perm -4000 -type f 2>/dev/null   # SUID inventory vs baseline
find /usr/bin /usr/sbin /bin /sbin -newermt "2026-10-01" -type f
```

Rootkit indicators: hidden processes (`ps` vs `/proc` listing mismatch), `ld.so.preload` entries, unknown kernel modules, tampered `ls`/`ps`/`netstat` (package mismatch). Tools: `chkrootkit`, `rkhunter` (signatures only — inconclusive negative).

---

## 5. File Timeline

```bash
find / -xdev -newermt "2026-10-20" ! -newermt "2026-10-22" -type f 2>/dev/null > recent.txt
stat /path/file                                     # atime/mtime/ctime (+ Birth on ext4/xfs with recent coreutils)
debugfs -R 'stat <inode>' /dev/sdX1                 # ext4 crtime
```

`ctime` cannot be set by `touch` — mtime << ctime suggests timestomping. Use Plaso on disk images for full timelines.

---

## 6. auditd

```bash
ausearch -k exec -i --start 10/20/2026 00:00:00 --end 10/22/2026 23:59:59
ausearch -m USER_LOGIN,USER_AUTH -i
ausearch -x /usr/bin/curl -i
aureport -x --summary ; aureport -au --failed ; aureport -m
```

---

## 7. Web Server Compromise

```bash
grep -E "POST .*\.(php|jsp|aspx)" /var/log/nginx/access.log* | awk '{print $1,$7}' | sort | uniq -c | sort -nr | head
grep -E "(cmd=|exec|system\(|passthru|base64_decode|eval\()" -r /var/www --include=*.php -l
find /var/www -name "*.php" -newermt "2026-10-01"
```

Correlate web request timestamps with process creation by the web server user (auditd `execve` with `uid=www-data`).

---

## 8. Memory (Volatility 3)

```bash
vol -f mem.lime linux.pslist ; vol -f mem.lime linux.pstree
vol -f mem.lime linux.bash                       # recovered bash history
vol -f mem.lime linux.lsof ; vol -f mem.lime linux.sockstat
vol -f mem.lime linux.malfind
vol -f mem.lime linux.check_syscall ; vol -f mem.lime linux.check_modules ; vol -f mem.lime linux.hidden_modules
vol -f mem.lime linux.envars
```

Requires matching symbol tables (ISF) for the kernel — generate with `dwarf2json` from the kernel's debug symbols.

---

## Engagement Cheatsheet

```text
avml + volatile → UAC → auth timeline → persistence sweep → debsums/rpm -Va → file timeline
→ auditd → web logs → memory plugins → IOCs
```

---

## Key References

- UAC — https://github.com/tclahr/uac ; avml — https://github.com/microsoft/avml
- Volatility 3 linux plugins; dwarf2json
- SANS FOR577 Linux Incident Response & Threat Hunting
- Related: `defensive-linux-telemetry`, `defensive-linux-hardening`, `defensive-memory-forensics`
