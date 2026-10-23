---
name: defensive-linux-hardening
description: "Linux server hardening mapped to attacker techniques: CIS Benchmarks and DISA STIGs, OpenSCAP/Lynis auditing, SSH hardening (key-only, no root login, modern ciphers, MFA, certificate auth), sudo policy, PAM and password policy, account hygiene, file permissions and SUID/SGID review, kernel sysctl hardening, mount options (noexec/nosuid/nodev), SELinux/AppArmor enforcing, firewall (nftables, firewalld, ufw), service minimization, automatic security updates, auditd and remote logging, AIDE file integrity, and container host specifics. Use when hardening Linux or remediating findings after a Linux compromise."
---

# Linux Hardening

Reduce what can run, who can log in, and what a compromised process can reach. Then make tampering visible.

## Quick Workflow

1. Baseline scan: Lynis / OpenSCAP (CIS or STIG profile)
2. Minimize packages and services
3. SSH + sudo + PAM hardening
4. Kernel, filesystem, and MAC (SELinux/AppArmor) controls
5. Host firewall default-deny inbound
6. Updates, auditd, remote logging, FIM
7. Re-scan; record exceptions

---

## 1. Assessment

```bash
sudo lynis audit system
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results results.xml --report report.html /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml
```

(Adjust content file and profile ID to your distro/version — list with `oscap info <ds.xml>`.)

---

## 2. SSH

```text
# /etc/ssh/sshd_config.d/10-hardening.conf
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey          # or publickey,keyboard-interactive for MFA via PAM
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowGroups ssh-users
X11Forwarding no
AllowTcpForwarding no                    # unless required (jump hosts)
AllowAgentForwarding no
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
LogLevel VERBOSE                          # logs key fingerprints
```

`sshd -t && systemctl reload ssh`. Prefer SSH certificates (short-lived, CA-signed) or IdP-backed access (e.g., cloud OS Login, Teleport-style bastions) over static `authorized_keys`. Restrict SSH to bastion/VPN source ranges.

---

## 3. Accounts, sudo, PAM

```text
[ ] Only UID 0 = root; no shared accounts; lock unused (usermod -L, nologin shell)
[ ] sudo via groups; no NOPASSWD except narrowly scoped automation; `Defaults use_pty, logfile=/var/log/sudo.log`
[ ] No `sudo ALL` for service accounts; avoid sudo rules allowing shells/editors/interpreters (GTFOBins)
[ ] pam_faillock (lockout), pam_pwquality (if passwords used)
[ ] Remove/restrict `su` (pam_wheel)
[ ] Home dirs 0750; umask 027
```

---

## 4. Filesystem & Permissions

```bash
# Mount options (/etc/fstab): /tmp, /var/tmp, /dev/shm with nodev,nosuid,noexec
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null     # review SUID/SGID vs baseline
find / -xdev -type f -perm -0002 2>/dev/null                            # world-writable files
getcap -r / 2>/dev/null                                                 # file capabilities
chmod 600 /etc/ssh/ssh_host_*_key; chmod 640 /etc/shadow (root:shadow)
```

---

## 5. Kernel (sysctl)

```text
# /etc/sysctl.d/90-hardening.conf
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
kernel.unprivileged_userns_clone = 0   # Debian/Ubuntu-specific; breaks some sandboxes/containers — test
```

Module blacklisting for unused filesystems/protocols (cramfs, udf, dccp, sctp, rds, tipc) via `/etc/modprobe.d/`.

---

## 6. MAC: SELinux / AppArmor

```bash
getenforce; sudo setenforce 1        # RHEL family — set SELINUX=enforcing in /etc/selinux/config
sudo aa-status; sudo aa-enforce /etc/apparmor.d/*   # Ubuntu/Debian
ausearch -m AVC -ts recent           # SELinux denials
```

Never "fix" by disabling — write targeted policy (`audit2allow` review) or adjust booleans.

---

## 7. Network

```bash
# nftables minimal inbound
nft add table inet filter
nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iif lo accept
nft add rule inet filter input ip saddr 10.0.50.0/24 tcp dport 22 accept     # bastion subnet
nft add rule inet filter input tcp dport { 80, 443 } accept
```

Disable unneeded listeners: `ss -tulpn`; `systemctl disable --now <svc>`.

---

## 8. Updates, Logging, Integrity

```text
[ ] unattended-upgrades / dnf-automatic for security updates; livepatch for kernels where available
[ ] auditd rules (see defensive-linux-telemetry) with -e 2
[ ] rsyslog/journald forwarding over TLS to SIEM
[ ] AIDE (aide --init; daily aide --check) or osquery FIM
[ ] Time sync (chrony) — accurate timelines
[ ] Remove compilers/debug tools from production where feasible
```

---

## Engagement Cheatsheet

```text
Lynis/OpenSCAP → minimize → sshd hardening + bastion-only → sudo/PAM → mounts + SUID review
→ sysctl → SELinux/AppArmor enforcing → nftables default drop → updates + auditd + remote logs + AIDE → rescan
```

---

## Key References

- CIS Distribution Independent Linux & distro-specific Benchmarks; DISA STIGs
- OpenSCAP / SCAP Security Guide; Lynis
- Mozilla OpenSSH guidelines; GTFOBins (sudo/SUID abuse reference)
- Related: `defensive-linux-telemetry`, `defensive-linux-forensics`, `defensive-container-hardening`
