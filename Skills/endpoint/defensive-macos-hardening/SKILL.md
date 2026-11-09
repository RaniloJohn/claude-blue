---
name: defensive-macos-hardening
description: "macOS fleet hardening and detection: current release tracking (Golden Gate 27, Tahoe 26, Sequoia 15), declarative software update enforcement (legacy MDM update management removed in 27), mSCP baselines (CIS, NIST 800-53/171, DISA STIG) via mscp.py, SIP, FileVault escrow and bootstrap token, Gatekeeper/notarization and quarantine, XProtect, Lockdown Mode, application firewall, PPPC/TCC profiles (tccutil list, Accessibility key deprecation), Background Task Management, standard-user admin elevation, Platform SSO, Santa allowlisting, Endpoint Security/eslogger and unified log telemetry, and infostealer detection (AMOS, MacSync, Odyssey; ClickFix Terminal and applescript:// lures, osascript password phishing, hdiutil, LaunchAgent persistence). Use when hardening Macs, building MDM baselines, or detecting macOS threats."
---

# macOS Hardening

Mac fleets usually fall to infostealers, not exploits. A user is talked into pasting a command or opening a fake app, types their password into an `osascript` dialog, and loses their browser sessions, Keychain and wallets. Defense means patch fast via DDM, enforce a baseline with MDM, keep users standard, and alert on the stealer kill chain.

## Quick Workflow

1. Inventory OS versions; enforce updates with **declarative** software update (deadline + restart countdown)
2. Generate a baseline with **mSCP** (CIS L1 to start, NIST/STIG if mandated) → MDM profiles + compliance script
3. Verify the platform controls: SIP, FileVault (escrowed), Gatekeeper, XProtect, firewall, bootstrap token
4. Remove local admin; use time-boxed elevation
5. Control execution: Gatekeeper with no user override, plus Santa (or the macOS 27 managed app rules)
6. Deploy PPPC/TCC profiles sparingly; audit grants with `tccutil list` (27+)
7. Stream Endpoint Security telemetry (EDR or eslogger) and unified logs to the SIEM
8. Deploy infostealer detections: osascript prompts, curl→shell, quarantine stripping, BTM tampering, LaunchAgents

---

## 1. Release & Patch Tracking

| Line | Current (as of 2026-10-26) | Notes |
|------|-----------------------|-------|
| macOS Golden Gate 27 | 27.2 | Current major release (27.0 shipped 2026-09-14) |
| macOS Tahoe 26 | 26.7.2 | Security updates only |
| macOS Sequoia 15 | 15.8.2 | Security updates only |
| Sonoma 14 and older | — | Treat as end of life when Apple stops listing releases for them |

Apple fixes the full set of CVEs only in the current major release. N-1 and N-2 get only some fixes, so plan for N, with N-1 as an exception track. Check https://support.apple.com/100100 for the current list.

**Software update management changed:**
- **26.0:** MDM update commands, the `com.apple.SoftwareUpdate` payload and the update restrictions are deprecated.
- **26.1:** At the DDM enforcement deadline, the "Not Now" option is removed.
- **27.0:** Legacy update management **no longer works**: commands, queries, deferral restrictions and Background Security Improvements controls. Use only the declarative software update configuration (target version + deadline). Older MDM workflows silently stop enforcing.

```bash
softwareupdate --list
sw_vers
system_profiler SPInstallHistoryDataType | grep -A4 -E "XProtect|Background Security"
```

---

## 2. Baselines — macOS Security Compliance Project (mSCP)

NIST's `usnistgov/macos_security` generates configuration profiles, **DDM assets**, documentation and a compliance script (to check and fix settings profiles can't enforce) for: CIS Benchmark L1/L2, CIS Controls v8, NIST SP 800-53, 800-171 r2/r3 (CMMC), CNSSI 1253, DISA STIG, HICP, NLMAPGOV. `main` targets macOS 27. Use the per-OS branches for older releases.

```bash
git clone https://github.com/usnistgov/macos_security && cd macos_security
python3 -m venv .venv && source .venv/bin/activate      # Python >= 3.12.1
python3 -m pip install --upgrade -r requirements.txt
./mscp.py guidance        # first run sets up the Ruby components; see ./mscp.py --help for baseline/profile options
```

Older branches use `scripts/generate_baseline.py -k cis_lvl1` and `scripts/generate_guidance.py -p -s build/baselines/cis_lvl1.yaml` (`-p` = profiles, `-s` = compliance script). Tailor the baseline (ODVs, exemptions) before you generate it. Deploy profiles in rings, and run the compliance script through MDM/EDR for drift reporting.

---

## 3. Platform Controls (Verify Everywhere)

| Control | Check | Target |
|---------|-------|--------|
| System Integrity Protection | `csrutil status` | enabled (only changeable from Recovery) |
| Signed System Volume | `csrutil authenticated-root status` | enabled |
| FileVault | `fdesetup status`; `fdesetup haspersonalrecoverykey` | On; personal recovery key escrowed to MDM |
| Bootstrap token | `profiles status -type bootstraptoken` | escrowed (needed for updates, kext/SSO on Apple silicon) |
| Secure Token | `sysadminctl -secureTokenStatus <user>` | expected users only |
| Gatekeeper | `spctl --status` | assessments enabled |
| Firewall | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getstealthmode` | on, stealth on |
| Remote Login / Screen Sharing | `systemsetup -getremotelogin` | off unless managed |
| Lockdown Mode | MDM status item (27+) | on for high-risk users (execs, journalists) |
| Auto-login, guest | `defaults read /Library/Preferences/com.apple.loginwindow` | disabled (or Authenticated Guest via PSSO) |

**FileVault notes:**
- 26.0: an escrow configuration rotates an existing recovery key before escrowing it, provided a bootstrap token exists.
- 26.0: FileVault can be unlocked over SSH after a restart when Remote Login is on. Keep Remote Login off unless you need it.
- 27.0: Platform SSO and OpenID authentication work at FileVault unlock.

---

## 4. Gatekeeper, Quarantine & XProtect

- Downloads get the `com.apple.quarantine` xattr, so Gatekeeper checks signing and notarization on first launch.
- Since **Sequoia 15**, the Control-click → Open override is gone. Users must go to System Settings → Privacy & Security → "Open Anyway". Remove even that with the MDM `com.apple.systempolicy.control` payload (`EnableAssessment=true`, `AllowIdentifiedDevelopers=true`). Don't let users disable Gatekeeper.
- Attackers get around this by **stripping quarantine** (`xattr -d com.apple.quarantine`, `xattr -c`), by `curl` downloads (curl doesn't set quarantine), or by having the user paste commands. Detect all three (§8).
- XProtect (signature detection) and XProtect Remediator (periodic scanning) update on their own schedule, separate from OS updates. Alert on fleet machines whose XProtect version lags (`system_profiler SPInstallHistoryDataType`, or the `xprotect version` CLI on 15+).
- **26.4+:** Terminal scans and warns on pasted commands, and Script Editor warns before running downloaded scripts. This adds friction against ClickFix, but `applescript://` one-click lures and fake "Terminal-free" flows still get through.

---

## 5. Admin Rights & Identity

- Make users **standard**. Infostealers need the password, not admin rights, but admin access turns a stealer into full persistence (LaunchDaemons, profiles, disabling security tools).
- Elevate with time-boxed tools (e.g. SAP Privileges, MDM/EDR just-in-time admin) and log every elevation.
- **Platform SSO** (13+): sync the local account with the IdP; use Secure Enclave keys or smart cards.
  - 26: enforce PSSO during Automated Device Enrollment.
  - 27: OpenID/MFA/QR at the login window and FileVault unlock; require Touch ID or Apple Watch.
  - A domain supports only one SSO extension. With Kerberos SSO, set `syncLocalPassword` to false.
- Rotate local admin (LAPS-style) through MDM; disable root (`dsenableroot -d`).

---

## 6. Execution Control & Privacy (TCC)

- **Santa** (now maintained by North Pole Security at `northpolesec/santa`; `google/santa` is archived): binary/team-ID/signing-ID/CDHash allowlisting in monitor → lockdown modes, plus file access authorization. 2026.8 fixed a race where the policy was checked against different content than what ran. Keep it current. See `defensive-application-control`.
- **macOS 27:** device management can control which apps and binaries may run, and App Attest can verify Mac app authenticity. Check that your MDM supports the new declarations before you depend on them.
- **PPPC / TCC** (`com.apple.TCC.configuration-profile-policy`):
  - Grant Full Disk Access only to your EDR/backup agents, pinned by code requirement.
  - Never pre-approve Screen Recording or Accessibility for broad app sets.
  - 27.0 deprecates the Accessibility key. Users are notified and can revoke managed grants.
  - 27.0: apps can no longer read the TCC database directly. Audit with `tccutil list` (27+), or with your MDM/EDR inventory on older systems.
- **Background Task Management (13+):**
  - `sfltool dumpbtm` lists login items, LaunchAgents and LaunchDaemons.
  - Use the MDM `com.apple.servicemanagement` payload to pin managed items so users can't disable them.
  - Malware kills `BTMNotificationAgent` / `BackgroundTaskManagementAgent` to hide its "new login item" alert. Treat that as high signal.

---

## 7. Telemetry

| Source | What you get | How |
|--------|--------------|-----|
| Endpoint Security framework | exec, fork, file create/rename, mount, BTM add, XProtect, authentication, TCC (newer releases) | EDR (Defender, CrowdStrike, SentinelOne, Jamf Protect), or `eslogger` for testing |
| Unified log | Gatekeeper/XProtect/TCC/sudo/SSH decisions | `log stream`/`log show` predicates; forward via EDR or MDM log collection |
| osquery | launchd, sip_config, disk_encryption, gatekeeper, alf, quarantine | scheduled queries (`defensive-tool-osquery`) |
| MDM | compliance, profiles, DDM status (enrollment type, Lockdown Mode) | API → SIEM |

```bash
sudo eslogger exec create btm_launch_item_add > /tmp/es.json      # ES events as JSON (13+)
log show --last 1h --predicate 'subsystem == "com.apple.syspolicy" OR process == "XProtect"'
log stream --predicate 'process == "sudo" OR eventMessage CONTAINS "authentication"'
sfltool dumpbtm | grep -E "Path|Developer|Disposition"
```

```sql
-- osquery: user LaunchAgents not from Apple/known vendors
SELECT path, program, program_arguments, run_at_load FROM launchd
WHERE (path LIKE '/Users/%/Library/LaunchAgents/%' OR path LIKE '/Library/LaunchDaemons/%')
  AND path NOT LIKE '%com.microsoft.%' AND path NOT LIKE '%com.jamf.%';
```

---

## 8. Infostealer Detection (AMOS, MacSync, Odyssey & co.)

**Kill chain seen in 2026:**
1. **Lure:** fake CAPTCHA "verify you are human" (ClickFix), copy a command, paste it into Terminal. Variants use an `applescript://` link that opens Script Editor with the script pre-filled, or a fake app in a DMG ("Toria" wallet, cracked software, fake meeting tools).
2. **Staging:** `curl -fsSL … | zsh`, or `curl -o /tmp/x.dmg` → `hdiutil attach -nobrowse` → `open` the first `.app`/`.pkg` found. Quarantine is stripped by the app itself.
3. **Credential phishing:** `osascript -e 'display dialog … with hidden answer'` styled as System Settings or the impersonated app. The password is validated with `dscl . -authonly` or, newer (MacSync, Pam Stealer), through the PAM API.
4. **Collection:** Chromium/Firefox profiles, Safari cookies, `login.keychain-db`, Apple Notes, Telegram, Discord, wallets (Exodus, Electrum, Ledger Live/Trezor Suite get trojanized), plus developer secrets (`~/.ssh`, `~/.aws`, `~/.kube`, `.gitconfig`, shell history). Staged in `/tmp`, zipped, then exfiltrated over HTTP POST.
5. **Persistence (newer variants):** LaunchAgents/Daemons named like Apple items (`com.apple.finder.agent`, `com.finder.helper.plist`, `~/.helper`), lines added to `.zshrc`, global Git hooks, a watchdog that restores deleted files, killing BTM notification agents. MacSync even pulled commands from a public iCloud calendar.

**Defender for Endpoint (macOS) KQL**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "osascript"
| where ProcessCommandLine has "display dialog" and ProcessCommandLine has_any ("hidden answer","password")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName == "xattr" and ProcessCommandLine has_any ("-d com.apple.quarantine","-c","-cr"))
     or (FileName == "hdiutil" and ProcessCommandLine has "attach" and ProcessCommandLine has "-nobrowse")
     or (FileName == "dscl" and ProcessCommandLine has "-authonly")
     or (FileName in ("killall","pkill") and ProcessCommandLine has_any ("BTMNotificationAgent","BackgroundTaskManagementAgent"))
     or (FileName == "curl" and InitiatingProcessFileName in ("zsh","bash","sh") and InitiatingProcessParentFileName in ("Terminal","iTerm2","Script Editor"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

```kql
// Sensitive stores read by non-browser processes
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/Library/Keychains/login.keychain-db","/Google/Chrome/Default/Login Data","/Firefox/Profiles/","/Exodus/","/Electrum/wallets")
| where InitiatingProcessFileName !in~ ("Google Chrome","firefox","Safari","securityd","Exodus","Electrum","mds_stores","backupd")
| summarize files=dcount(FolderPath) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| where files > 3
```

**Sigma** — SigmaHQ already ships `file_event_macos_malware_amos_persistence` (curl writing `/Users/*/.helper`, `/Library/LaunchDaemons/com.finder.helper.plist`). Pair it with a generic rule:
```yaml
title: macOS Osascript Password Prompt
status: experimental
logsource: { product: macos, category: process_creation }
detection:
  selection:
    Image|endswith: '/osascript'
    CommandLine|contains|all: ['display dialog', 'hidden answer']
  condition: selection
level: high
tags: [attack.credential-access, attack.t1056.002]
```

**Response:** isolate the host, then revoke all sessions for the user's browser-saved accounts (SaaS tokens, not just passwords), rotate the Keychain, SSH, cloud and Git credentials, move wallet funds from a clean device, remove persistence (LaunchAgents, `.zshrc`, Git hooks, watchdog), and re-image if a LaunchDaemon or profile was installed. See `defensive-incident-response` / `defensive-macos-forensics`.

---

## 9. Network & Data

- Turn on the application firewall plus stealth mode. On 26+, use the Network Extension URL filtering API / content filters for web control.
- 26.0 IKEv2 removes DES/3DES/SHA1-96/SHA1-160 and DH groups below 14. Update legacy VPN gateways.
- Disable AirDrop for "Everyone", or restrict it by profile. Control USB/accessories (accessory security now also applies in Recovery). See `defensive-usb-device-control`.
- iCloud Drive and Keychain sync on managed devices: decide by policy and enforce through restrictions or Managed Apple Accounts.

---

## Engagement Cheatsheet

| Need | Do |
|------|----|
| Patch enforcement | DDM software update with deadline; legacy MDM update commands stop working in 27 |
| Baseline | mSCP `./mscp.py` → profiles + DDM + compliance script; start CIS L1 |
| Quick posture check | `csrutil status`, `fdesetup status`, `spctl --status`, `profiles status -type bootstraptoken`, firewall state |
| Stop user overrides | `com.apple.systempolicy.control`; standard users; Santa lockdown |
| TCC audit | `tccutil list` (27+); minimal PPPC; no blanket Accessibility |
| Persistence hunt | `sfltool dumpbtm`, osquery `launchd`, `.zshrc`, global Git hooks |
| Stealer alerting | osascript hidden-answer dialogs, `xattr -d com.apple.quarantine`, `hdiutil -nobrowse`, `dscl -authonly`, BTM agent kills, curl→shell from Terminal |
| After a stealer hit | Revoke sessions/tokens first, then rotate credentials, clean persistence, rebuild if admin was used |

Related: `defensive-application-control`, `defensive-hunt-macos`, `defensive-macos-forensics`, `defensive-tool-osquery`, `defensive-browser-security`, `defensive-usb-device-control`, `defensive-edr-tuning`, `defensive-detect-credential-access`, `defensive-phishing-resistant-mfa`.

## Key References

- Apple security releases — https://support.apple.com/100100
- What's new for enterprise in macOS Golden Gate 27 — https://support.apple.com/148830
- What's new for enterprise in macOS Tahoe 26 — https://support.apple.com/124963
- Apple Platform Security: Gatekeeper and runtime protection — https://support.apple.com/guide/security/sec5599b66df/web
- Platform SSO for macOS — https://support.apple.com/guide/deployment/dep7bbb05313/web
- mSCP — https://github.com/usnistgov/macos_security
- Santa (North Pole Security) — https://github.com/northpolesec/santa
- MacSync analysis (Help Net Security, Sep 2026) — https://www.helpnetsecurity.com/2026/09/25/macsync-info-stealing-malware-for-macos/
- ClickFix applescript:// variant (CSO Online, Apr 2026) — https://www.csoonline.com/article/4156500/new-clickfix-variant-bypasses-apple-safeguards-with-one-click-script-execution.html
- SigmaHQ AMOS persistence rule — https://github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats/2025/Malware/Atomic-MacOS-Stealer
- MITRE ATT&CK macOS matrix — https://attack.mitre.org/matrices/enterprise/macos/
