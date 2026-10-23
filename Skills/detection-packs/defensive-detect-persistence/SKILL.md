---
name: defensive-detect-persistence
description: "Detection pack for MITRE ATT&CK Persistence (TA0003) across Windows, Linux, macOS, identity, and cloud: Run keys and startup folder, services, scheduled tasks/cron/systemd timers, WMI event subscriptions, COM hijacking, IFEO/SilentProcessExit, accessibility features, LSA/authentication packages, Office add-ins/templates, account creation and manipulation, SSH authorized_keys, LaunchAgents/Daemons, shell profiles, ld.so.preload, PAM modules, kernel modules, web shells, cloud IAM users/keys/roles, OAuth apps, MFA device registration, and server software components. Detections, FPs, and triage. Use when building persistence detections or sweeping for persistence."
---

# Detection Pack — Persistence (TA0003)

Persistence artifacts are durable and enumerable — detect creation in real time, and sweep periodically for anything that slipped by.

## Quick Workflow

1. Real-time: registry/file/task/service/account creation events
2. Periodic: autoruns-style sweeps diffed against baseline
3. Identity/cloud: new credentials, roles, apps, MFA methods
4. Investigate every new persistence on Tier 0 immediately

---

## 1. Windows

| Mechanism | ATT&CK | Telemetry | Signal |
|---|---|---|---|
| Run/RunOnce keys | T1547.001 | Sysmon 13 | Value pointing to user-writable path, script hosts, encoded commands |
| Startup folder | T1547.001 | Sysmon 11 | `.lnk/.vbs/.bat/.exe` in `\Start Menu\Programs\Startup\` |
| Services | T1543.003 | 7045, 4697, Sysmon 13 (`\Services\*\ImagePath`) | Non-Program Files path, `cmd /c`, random names |
| Scheduled tasks | T1053.005 | 4698/4702, TaskScheduler 106/140 | Actions with PowerShell/script hosts, user-writable paths, hidden tasks (SD removed) |
| WMI subscriptions | T1546.003 | Sysmon 19/20/21, WMI-Activity 5861 | `CommandLineEventConsumer`, `ActiveScriptEventConsumer` |
| COM hijack | T1546.015 | Sysmon 12/13 `HKCU\Software\Classes\CLSID\*\InprocServer32` | User-hive CLSID overriding HKLM |
| IFEO / SilentProcessExit | T1546.012 | Sysmon 13 `Image File Execution Options\*\Debugger`, `SilentProcessExit\*\MonitorProcess` | Any new value |
| Accessibility features | T1546.008 | File replace of `sethc.exe`/`utilman.exe`/`osk.exe`; IFEO Debugger on them | Hash mismatch / IFEO |
| Winlogon | T1547.004 | Sysmon 13 `Winlogon\Userinit`, `Shell` | Additional entries |
| LSA packages | T1547.002/.005 | Sysmon 13 `Control\Lsa\Security Packages`, `Authentication Packages`, `Notification Packages` | New DLL names |
| Office add-ins/templates | T1137 | Sysmon 11 `Normal.dotm`, `XLSTART`, `\AddIns\` | New/modified files |
| BITS jobs | T1197 | Bits-Client 3/59, `bitsadmin /SetNotifyCmdLine` | Notify command lines |
| Netsh helper | T1546.007 | Sysmon 13 `HKLM\SOFTWARE\Microsoft\NetSh` | New DLL |
| Local/domain account creation | T1136 | 4720, 4732/4728 | Account created + added to admins |
| Web shell | T1505.003 | Sysmon 11 in web roots; web server child processes | New `.aspx/.php/.jsp` |
| Server components (IIS modules, SQL CLR, Exchange transport agents) | T1505 | IIS config changes, `appcmd` | New modules |

```yaml
title: Registry Persistence Pointing To User-Writable Path
logsource: { product: windows, category: registry_set }
detection:
  keys:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run'
      - '\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\'
      - '\Image File Execution Options\'
      - '\SilentProcessExit\'
  bad:
    Details|contains: ['\AppData\','\Temp\','\Users\Public\','\ProgramData\','powershell','mshta','wscript','cmd /c','rundll32']
  condition: keys and bad
level: high
tags: [attack.persistence, attack.t1547.001, attack.t1546.012]
```

```kql
// WMI permanent subscriptions (Defender)
DeviceEvents
| where ActionType == "WmiBindEventFilterToConsumer"
| project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields
```

Periodic sweep: Sysinternals Autoruns (`autorunsc64.exe -accepteula -a * -c -h -s -m > autoruns.csv`) or Velociraptor `Windows.Sysinternals.Autoruns`, diffed against golden image.

---

## 2. Linux

| Mechanism | Telemetry |
|---|---|
| cron (`/etc/cron*`, `/var/spool/cron`) | auditd `-k cron` writes |
| systemd units/timers (system + user) | auditd `-k systemd`; new `.service`/`.timer` |
| SSH `authorized_keys` | auditd `-k ssh_keys`; FIM |
| Shell rc/profile | FIM on `/etc/profile.d`, `~/.bashrc` |
| `/etc/ld.so.preload` | auditd `-k preload` — any write is critical |
| PAM modules | FIM `/etc/pam.d`, `/lib*/security/*.so` |
| Kernel modules | `init_module`/`finit_module` syscalls |
| udev rules `RUN+=` | FIM `/etc/udev/rules.d` |
| New users/UID 0 | `useradd`, `/etc/passwd` writes |

```spl
index=linux sourcetype=linux:audit key IN (cron, systemd, ssh_keys, preload, pam, modules)
| stats count values(exe) values(name) by host key auid
```

## 3. macOS

LaunchAgents/LaunchDaemons (`btm_launch_item_add` ESF event, BTM database), login items, configuration profiles (`profile_add`), cron, zsh rc files, authorization plugins. Alert on unsigned/ad-hoc signed program paths in new launch items.

---

## 4. Identity & Cloud

| Platform | Persistence signal |
|---|---|
| AD | New accounts, `msDS-KeyCredentialLink` writes (shadow creds), SID History, AdminSDHolder ACL edits, new GPO scheduled tasks, Golden ticket (krbtgt not rotated), DSRM logon enable (`DsrmAdminLogonBehavior`) |
| Entra ID | New MFA methods, app registrations with credentials, OAuth consent grants, federation domain changes, new Global Admin, CA policy exclusions |
| AWS | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, role trust changes to external accounts, Lambda/EventBridge backdoors, new IdP providers |
| GCP | SA keys, IAM bindings for external principals, startup-script metadata |
| Azure | Role assignments, automation runbooks, VM extensions, managed identity assignments |
| M365 | Inbox rules, forwarding, mailbox delegation, transport rules |

---

## 5. False Positives

Software installs/updates (services, Run keys, tasks), MDM-pushed profiles, configuration management (Ansible/Puppet writing cron/systemd), legitimate OAuth apps. Tune by signer, deployment tool parent, change window, and known automation accounts.

---

## 6. Triage

1. What does it execute? Hash, signature, location, network behavior
2. Who created it (account, process, remote source)?
3. When — correlate with initial access/lateral movement timeline
4. Same artifact elsewhere (fleet hunt)
5. Remove only after scoping all persistence (coordinated eradication)

---

## Engagement Cheatsheet

```text
real-time (Sysmon 11/12/13/19-21, 4698, 7045, auditd keys, ESF BTM) + periodic autoruns diff
+ identity/cloud credential/role/app watches → triage what/who/when/where → coordinated removal
```

---

## Key References

- MITRE ATT&CK TA0003; Sysinternals Autoruns; Velociraptor artifacts
- Related: `defensive-hunt-windows`, `defensive-linux-forensics`, `defensive-macos-forensics`, `defensive-ad-detection`
