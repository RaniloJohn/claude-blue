---
name: defensive-browser-security
description: "Enterprise browser security for Chrome, Edge, and Firefox: managed policies, extension governance after the Manifest V2 end (Chrome 139 removed the MV2 enterprise override; MV2 extensions removed from the Web Store Aug 31, 2026), extension allowlisting and blocklisting, Safe Browsing/SmartScreen and Enhanced Security Mode, session cookie theft defenses (Chrome App-Bound Encryption, Device Bound Session Credentials GA for Google accounts on Windows Chrome in 2026, Entra token protection), ClickFix and fake-CAPTCHA paste-and-run attacks with Microsoft-recommended mitigations and RunMRU hunting, macOS ClickFix variants, download and isolation controls, browser telemetry, and incident response for infostealer cookie theft. Use when hardening or monitoring enterprise browsers."
---

# Browser Security

The browser is where users meet the internet and where session tokens live. 2024–2026 attacks centered on **malicious extensions**, **infostealers stealing cookies to bypass MFA**, and **ClickFix** lures that trick users into running commands themselves.

## Quick Workflow

1. Manage browsers centrally (GPO/Intune/Chrome Enterprise Core/Jamf); block unmanaged browsers where feasible
2. Extensions: default-deny with allowlist; review permissions
3. Enable protections: Safe Browsing/SmartScreen, Enhanced Security Mode, download restrictions
4. Defend sessions: App-Bound Encryption on, short sessions, token binding where available, EDR for infostealers
5. Counter ClickFix: Run dialog/paste controls, script logging, ASR, awareness
6. Collect browser telemetry; prepare cookie-theft response

---

## 1. Extension Governance

| Fact | Detail |
|---|---|
| Manifest V2 end | Chrome disabled MV2 by default Mar 31, 2025; fully disabled in Chrome 138 (Jul 24, 2025); `ExtensionManifestV2Availability` policy removed in **Chrome 139**; remaining MV2 extensions removed from the Chrome Web Store **Aug 31, 2026** |
| Edge | Still documents `ExtensionManifestV2Availability`; verify current Edge MV2 status before relying on it |

Policy pattern (Edge example from Microsoft docs; Chrome uses equivalent `ExtensionInstallBlocklist` / `ExtensionInstallAllowlist` / `ExtensionSettings`):

```text
HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist   "1" = "*"
HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist   "1" = "<approved-extension-id>"
HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist   "1" = "<id>;<update-url>"
```

Use `ExtensionSettings` to block by permission (e.g., `<all_urls>`, `cookies`, `debugger`) and to restrict install sources; `BlockExternalExtensions` to stop sideloaded extensions. Review allowlisted extensions on each update — ownership transfers and malicious updates are common.

---

## 2. Protection Features

| Feature | Setting |
|---|---|
| Chrome Safe Browsing | Enhanced protection for high-risk users; at least standard, user can't disable |
| Edge SmartScreen + Enhanced Security Mode | `EnhanceSecurityMode` strict for untrusted sites; enforce/bypass lists for internal apps |
| Downloads | Block dangerous file types; restrict downloads for uncategorized sites via SWG (`defensive-proxy-tls-inspection`) |
| Password manager | Disable built-in password saving if an enterprise manager is standard; otherwise require OS-level protection |
| Sync and profiles | Restrict sign-in to corporate accounts (`RestrictSigninToPattern`, Edge `RestrictSigninToPattern`); block personal profiles on managed devices (Okta's 2023 breach began with a credential synced to a personal Google profile) |
| Remote browser isolation | For risky/uncategorized browsing (SSE vendors) |

---

## 3. Session Cookie Theft

| Defense | Detail |
|---|---|
| App-Bound Encryption (Chrome 127+, Windows) | Binds cookie keys to Chrome's identity on top of DPAPI; raises cost for user-level infostealers but bypassable with SYSTEM or code injection; policy `ApplicationBoundEncryptionEnabled`; Chrome logs Application event **ID 257** (source "Chrome") on verification failure — useful detection |
| Device Bound Session Credentials (DBSC) | **GA for Google Workspace and personal Google accounts in Chrome on Windows** (rollout from May 2026); on by default, no admin toggle; protects **Google** sessions only |
| Non-Google sessions | Entra token protection / Continuous Access Evaluation, short session lifetimes, compliant-device requirements, IdP session revocation on infostealer detection |
| EDR | Detect non-browser processes reading `Cookies`, `Login Data`, `Local State` (`defensive-detect-credential-access`) |

Infostealer response: isolate host → reimage → **revoke all sessions** (IdP, SaaS, Google, GitHub, cloud consoles) → rotate passwords and saved credentials → check for attacker MFA enrollment and OAuth grants.

---

## 4. ClickFix / Fake CAPTCHA

Seen since 2024 (first Storm-1607 delivering DarkGate); delivers Lumma, XWorm, AsyncRAT, NetSupport, Latrodectus, rootkits and, on macOS, Atomic Stealer (AMOS).

Microsoft-recommended mitigations (Aug 2025):
- Remove the Run dialog via Group Policy where users don't need it
- App Control policies blocking native binaries launched via Run
- Windows Terminal multi-line paste warning
- PowerShell script block logging; AllSigned/RemoteSigned execution policy (not a boundary, adds friction)
- ASR rules (obfuscated scripts, scripts launching downloaded executables, executables not meeting prevalence/age criteria), Network Protection, SmartScreen

Hunting — RunMRU (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`) entries invoking script hosts:

```kql
DeviceRegistryEvents
| where RegistryKey has @"\Explorer\RunMRU"
| where RegistryValueData has_any ("powershell","pwsh","mshta","curl","wscript","cscript","rundll32","msiexec","certutil","bitsadmin")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryValueName, RegistryValueData
```

Process lineage: `explorer.exe` → `powershell.exe`/`mshta.exe` with download cradles shortly after a browser visit (`defensive-detect-initial-access`).

macOS variants: macOS 26.4 added scanning of commands pasted into Terminal, but 2026 variants used `applescript://` links to open Script Editor with prefilled scripts and silent DMG mounts (`hdiutil attach -nobrowse`) to deliver AMOS — hunt for Script Editor/Terminal → `curl` → `zsh`/`hdiutil` chains and osascript password prompts (`defensive-hunt-macos`).

---

## 5. Telemetry

Chrome Enterprise reporting connector / Chrome Enterprise Premium events (malware transfer, password reuse, extension installs), Edge management service reports, EDR browser child processes and network events, proxy/DNS logs, Windows event ID 257 (ABE failures).

---

## Engagement Cheatsheet

```text
central management + corporate-only sign-in → extensions default-deny + allowlist (MV2 gone from Chrome 139/Web Store Aug 2026) → Safe Browsing/SmartScreen/ESM + download controls
→ ABE on (watch event 257), DBSC for Google, token protection + short sessions for others, EDR cookie-read detection → ClickFix: Run dialog removal, App Control, script logging, ASR, RunMRU hunt
→ macOS Script Editor/DMG variants → infostealer IR: reimage + revoke all sessions + rotate
```

---

## Key References

- Chrome MV2 deprecation timeline (developer.chrome.com); Microsoft Edge policy reference; Google Security Blog on App-Bound Encryption (Jul 2024); Google Workspace Updates: DBSC GA (May 2026)
- Microsoft Threat Intelligence: "Think before you ClickFix" (Aug 21, 2025)
- Related: `defensive-browser-forensics`, `defensive-detect-initial-access`, `defensive-hunt-macos`, `defensive-phishing-resistant-mfa`, `defensive-security-awareness`
