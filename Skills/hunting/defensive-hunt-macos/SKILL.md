---
name: defensive-hunt-macos
description: "Threat hunting on macOS fleets: data sources (Endpoint Security Framework via EDR, eslogger, Unified Logs, osquery, MDM inventory, TCC.db, BTM/launch items, quarantine events), hunts for infostealers (AppleScript password prompts, keychain and browser data access, curl uploads), unsigned or ad-hoc signed binaries and Gatekeeper bypass, persistence (LaunchAgents/Daemons, login items, configuration profiles, cron, shell rc files), TCC permission abuse, suspicious osascript/curl/base64 chains, Python/shell droppers, malicious DMG/PKG installs, and remote access tools; with osquery, log predicates, and EDR-style queries. Use when proactively hunting on Macs."
---

# macOS Threat Hunting

macOS threats are dominated by **infostealers** delivered through fake apps/cracked software/malvertising and **social-engineered permission grants**, plus persistence via launch items. Hunts focus on execution provenance, password prompts, and data access.

## Quick Workflow

1. Confirm telemetry: ESF-based EDR (process exec with code-signing info, file, TCC events), MDM inventory, osquery
2. Hunt (§2); stack rare signers, team IDs, launch items
3. Validate on host (`defensive-macos-forensics`)
4. Convert to detections; push MDM controls

---

## 1. Data Sources

| Source | Use |
|---|---|
| EDR (ESF events: exec, open, create, `btm_launch_item_add`, `tcc_modify`, `xp_malware_detected`) | Primary telemetry |
| `eslogger` (built-in ESF CLI, root, Full Disk Access) | Ad hoc capture: `sudo eslogger exec create btm_launch_item_add > es.json` |
| Unified Logs | `log show --predicate ... --last 24h` |
| osquery | Launchd, signatures, apps, extensions, quarantine events |
| TCC.db (user + system) | Permission grants (needs FDA) |
| Quarantine DB | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` — download origins |
| MDM | Installed profiles, apps, compliance |

---

## 2. Hunts

### Infostealer password phishing (AppleScript)

```bash
log show --last 7d --predicate 'process == "osascript"' --style compact | grep -i "display dialog\|hidden answer"
```

EDR: `osascript` with arguments containing `display dialog` + `hidden answer` / `with hidden answer`, parent an unsigned or ad-hoc-signed binary from `/tmp`, `/Volumes/`, or `~/Downloads`.

### Data collection & exfil chain

`security find-generic-password`/`dump-keychain`; reads of `~/Library/Keychains/`, browser `Login Data`/`Cookies`, crypto wallet extension folders, Telegram/Notes data by non-native processes; staging zip in `/tmp` then `curl -F`/`-X POST` upload.

### Unsigned / ad-hoc signed execution

```sql
SELECT p.pid, p.name, p.path, s.signed, s.identifier, s.team_identifier, s.authority
FROM processes p JOIN signature s ON p.path = s.path
WHERE s.signed = 0 OR s.team_identifier = '' ;
```

Stack `team_identifier` and signing authorities fleet-wide; rare team IDs are leads.

### Gatekeeper bypass / quarantine removal

`xattr -d com.apple.quarantine` or `xattr -c` by scripts; apps launched from mounted DMGs with "right-click open" social engineering; quarantine events showing downloads from file-sharing/cracked-software sites.

```sql
SELECT * FROM quarantine_items;   -- (osquery table availability varies; otherwise query QuarantineEventsV2 SQLite)
```

### Persistence

```sql
SELECT label, path, program, program_arguments, run_at_load, keep_alive FROM launchd
WHERE path NOT LIKE '/System/%' AND path NOT LIKE '/Library/Apple/%';
SELECT * FROM startup_items;
```

Plus: BTM records (`sfltool dumpbtm`), login items, configuration profiles (`profiles list -all`), cron, `~/.zshrc`/`~/.zprofile` modifications, `/Library/Security/SecurityAgentPlugins/` (authorization plugins).

### TCC abuse

New grants for `kTCCServiceScreenCapture`, `kTCCServiceAccessibility`, `kTCCServiceSystemPolicyAllFiles` (Full Disk Access), `kTCCServiceAppleEvents` to unknown apps — EDR `tcc_modify` events or TCC.db diffs.

### Suspicious command chains

`curl ... | bash`, `base64 -d | sh`, `osascript -e` with `do shell script`, `python3 -c` with `urllib`/`exec`, `launchctl load`/`bootstrap` from scripts, `chmod +x` in `/tmp` followed by execution.

### Remote access tools

Unapproved AnyDesk/TeamViewer/ScreenConnect installs, `screensharing` enabled via `kickstart`, new SSH (Remote Login) enablement.

---

## 3. Validation

Check code signature and notarization (`codesign -dv --verbose=4`, `spctl -a -vv`), quarantine attributes (`xattr -l`), XProtect/XProtect Remediator logs, and file provenance. Remove via MDM-driven remediation; rotate credentials and session cookies if an infostealer ran (all browser sessions are compromised).

---

## Engagement Cheatsheet

```text
ESF/EDR + eslogger + unified log + osquery + TCC/quarantine/MDM → osascript password prompts → keychain/browser/wallet access + curl upload
→ unsigned/ad-hoc/rare team IDs → quarantine removal → launchd/BTM/profiles/rc persistence → TCC grants → curl|bash chains → RATs
→ validate (codesign/spctl/xattr) → MDM remediation + credential & session rotation
```

---

## Key References

- Apple Endpoint Security docs; `eslogger(1)`; Apple Platform Security Guide; Objective-See tools (KnockKnock, BlockBlock, LuLu)
- Related: `defensive-macos-forensics`, `defensive-threat-hunting`, `defensive-tool-osquery`, `defensive-detect-credential-access`
