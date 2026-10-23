---
name: defensive-macos-forensics
description: "macOS forensics and endpoint telemetry: Unified Logging System (log show/collect predicates, .logarchive), Endpoint Security Framework events via eslogger, Background Task Management (sfltool dumpbtm), LaunchAgents/LaunchDaemons and login items, TCC.db privacy grants, quarantine events and Gatekeeper/XProtect, KnowledgeC/Biome, FSEvents, Spotlight, shell histories, configuration profiles, authorization plugins, APFS snapshots, and triage with Aftermath or UAC. Use for investigating compromised Macs, infostealer infections, and macOS detection engineering."
---

# macOS Forensics

macOS hides much behind SIP, TCC, and sealed system volumes, so collection needs Full Disk Access and often root. The richest live sources are the Unified Log and Endpoint Security events; persistence centers on launchd and BTM.

## Quick Workflow

1. Grant collector Full Disk Access; collect with Aftermath or UAC
2. Export Unified Logs (`log collect`)
3. Review persistence (BTM, LaunchAgents/Daemons, profiles)
4. Review TCC grants and quarantine history
5. Timeline (FSEvents, Unified Log, KnowledgeC/Biome)
6. Map to infostealer / backdoor patterns

---

## 1. Collection

```bash
sudo log collect --last 3d --output /Volumes/EXT/case.logarchive
sudo /usr/local/bin/aftermath --output /Volumes/EXT/aftermath     # Jamf Aftermath
sudo ./uac -p ir_triage /Volumes/EXT/                             # UAC
sudo sfltool dumpbtm > /Volumes/EXT/btm.txt
```

Memory acquisition on Apple silicon is restricted; rely on EDR and live data.

---

## 2. Unified Logging

```bash
log show case.logarchive --start "2026-10-20 00:00:00" --end "2026-10-21 00:00:00" --predicate 'process == "sshd"'
log show --last 1d --predicate 'process == "sudo"' --style syslog
log show --last 1d --predicate 'subsystem == "com.apple.xprotect"'
log show --last 1d --predicate 'process == "syspolicyd"'                     # Gatekeeper decisions
log show --last 1d --predicate 'subsystem == "com.apple.TCC"'                 # privacy prompts/grants
log show --last 1d --predicate 'eventMessage CONTAINS[c] "authentication"'
log show --last 1d --predicate 'process == "screensharingd" OR process == "ARDAgent"'
```

---

## 3. Endpoint Security (ESF)

`eslogger` (macOS 13+) streams ESF events as JSON — same source EDRs use:

```bash
sudo eslogger exec fork create rename mmap btm_launch_item_add > es.json
jq -c 'select(.event.exec != null) | {t:.time, parent:.process.executable.path, exec:.event.exec.target.executable.path, args:.event.exec.args}' es.json
```

Key events: `exec`, `fork`, `create`, `rename`, `unlink`, `mmap`, `open`, `btm_launch_item_add`, `authentication`, `xp_malware_detected`, `login_login`, `screensharing_attach`, `profile_add`, `tcc_modify` (newer macOS).

---

## 4. Persistence

| Mechanism | Location |
|---|---|
| LaunchAgents (user) | `~/Library/LaunchAgents/`, `/Library/LaunchAgents/` |
| LaunchDaemons (root) | `/Library/LaunchDaemons/` |
| Login items / BTM | `sfltool dumpbtm`; BTM DB in `/private/var/db/com.apple.backgroundtaskmanagement/` |
| Configuration profiles | `profiles list -all`; `/Library/Managed Preferences/` |
| Cron / periodic | `crontab -l`, `/etc/periodic/` |
| Shell rc | `~/.zshrc`, `~/.zprofile`, `/etc/zshrc` |
| Authorization plugins | `/Library/Security/SecurityAgentPlugins/` |
| Login/logout hooks (legacy) | `com.apple.loginwindow` plist |
| Browser extensions | Chrome/Safari extension dirs |

```bash
for f in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
  echo "== $f"; plutil -p "$f" | grep -E 'ProgramArguments|Program"|RunAtLoad|KeepAlive' -A3
done
codesign -dvvv /path/to/binary 2>&1 | grep -E 'Authority|TeamIdentifier|Signature'
spctl --assess --verbose /path/to/app
```

Unsigned or ad-hoc signed binaries in launch items, binaries in `/Users/Shared`, `/tmp`, `~/Library/Application Support/<random>` are high signal.

---

## 5. TCC & Quarantine

```bash
sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" 'select service,client,auth_value,last_modified from access'
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db 'select service,client,auth_value,last_modified from access'
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  'select datetime(LSQuarantineTimeStamp+978307200,"unixepoch"),LSQuarantineAgentName,LSQuarantineDataURLString,LSQuarantineOriginURLString from LSQuarantineEvent order by 1 desc limit 50'
xattr -l /path/to/file          # com.apple.quarantine
```

TCC `auth_value` 2 = allowed. Watch `kTCCServiceSystemPolicyAllFiles` (Full Disk Access), `kTCCServiceAccessibility`, `kTCCServiceScreenCapture`, `kTCCServiceAppleEvents` for unexpected clients.

---

## 6. Infostealer Pattern (AMOS/Atomic, Poseidon, Banshee-style)

| Step | Artifact |
|---|---|
| Fake app/DMG or cracked software | Quarantine events, Gatekeeper override (`syspolicyd`), DMG in Downloads |
| `osascript` password prompt | Unified Log `osascript`; ESF exec of `osascript -e 'display dialog ... hidden answer'` |
| Keychain / browser data access | `security` CLI exec, reads of `login.keychain-db`, Chrome `Login Data`, wallet extensions |
| Archive + exfil | `ditto -c -k`/`zip` in `/tmp`, `curl -F` POST to raw IP |

Hunt: `osascript` spawned by unsigned binary; `curl` uploading archives; `security dump-keychain` or `find-generic-password`.

---

## 7. Timeline Sources

| Source | Content |
|---|---|
| FSEvents (`/.fseventsd`) | File system changes (parse with `FSEventsParser`) |
| KnowledgeC / Biome | App usage, device state (version-dependent; Biome on newer macOS) |
| Unified Log | Process, auth, network extension events |
| Spotlight store | File metadata incl. `kMDItemWhereFroms` |
| `install.log` | Package installs |
| Shell history | `~/.zsh_history` |

---

## Engagement Cheatsheet

```text
FDA collector → log collect → sfltool dumpbtm → launch plists + codesign → TCC + quarantine
→ FSEvents/Unified Log timeline → infostealer checks (osascript, keychain, curl exfil) → IOCs
```

---

## Key References

- Apple: Unified Logging; Endpoint Security framework; `eslogger(1)`
- Jamf Aftermath — https://github.com/jamf/aftermath
- Objective-See tools (KnockKnock, BlockBlock, LuLu)
- Related: `defensive-malware-triage`, `defensive-timeline-analysis`
