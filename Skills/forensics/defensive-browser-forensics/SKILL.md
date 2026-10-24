---
name: defensive-browser-forensics
description: "Web browser forensics for Chromium-based browsers (Chrome, Edge, Brave), Firefox, and Safari: profile locations on Windows, macOS, and Linux, SQLite databases (History, Downloads, Cookies, Login Data, Web Data, Top Sites, Favicons, places.sqlite, formhistory, cookies.sqlite), cache and session files, extensions and their permissions, timestamp formats (WebKit/Chrome microseconds since 1601, PRTime, Mac absolute time), download provenance and Mark-of-the-Web, cookie theft and session hijacking evidence, infostealer artifacts, tools (Hindsight, DB Browser for SQLite, KAPE targets, Velociraptor artifacts, BrowsingHistoryView), and building browser timelines for phishing and initial-access investigations. Use when analyzing browser activity in an investigation."
---

# Browser Forensics

Most initial access touches a browser: phishing clicks, malicious downloads, OAuth consent, session-cookie theft. Browser artifacts answer **what was visited, downloaded, entered, and installed — and when**.

## Quick Workflow

1. Collect profiles for all users (copy while browser closed, or collect locked files via raw copy/VSS)
2. Parse History/Downloads/Cookies/extensions with Hindsight or SQL
3. Convert timestamps to UTC
4. Correlate downloads with Mark-of-the-Web, process execution, and proxy/DNS logs
5. Report the click → download → execution chain

---

## 1. Profile Locations

| Browser | Windows | macOS | Linux |
|---|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\` | `~/Library/Application Support/Google/Chrome/<Profile>/` | `~/.config/google-chrome/<Profile>/` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\` | `~/Library/Application Support/Microsoft Edge/` | `~/.config/microsoft-edge/` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\` | `~/Library/Application Support/BraveSoftware/Brave-Browser/` | `~/.config/BraveSoftware/Brave-Browser/` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\<x>.default-release\` | `~/Library/Application Support/Firefox/Profiles/` | `~/.mozilla/firefox/` |
| Safari | — | `~/Library/Safari/` (History.db; needs Full Disk Access) | — |

`<Profile>` = `Default`, `Profile 1`, … — check all.

---

## 2. Key Databases

| Browser | File | Content |
|---|---|---|
| Chromium | `History` | `urls`, `visits` (transition types), `downloads`, `downloads_url_chains`, `keyword_search_terms` |
| Chromium | `Cookies` (`Network\Cookies` in newer versions) | Session cookies (values encrypted) |
| Chromium | `Login Data` | Saved credentials (encrypted) — infostealer target |
| Chromium | `Web Data` | Autofill, addresses, cards (encrypted) |
| Chromium | `Preferences`, `Secure Preferences`, `Extensions\` | Extensions, permissions, settings |
| Chromium | `Sessions\`, `Current Session` | Open tabs |
| Firefox | `places.sqlite` | `moz_places`, `moz_historyvisits`, bookmarks; downloads in `moz_annos` |
| Firefox | `cookies.sqlite`, `formhistory.sqlite`, `logins.json` + `key4.db`, `extensions.json` | Cookies, forms, logins, add-ons |
| Safari | `History.db`, `Downloads.plist`, `LastSession.plist` | History, downloads, tabs |

```sql
-- Chromium: visits with UTC time (WebKit microseconds since 1601-01-01)
SELECT datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS visit_utc, u.url, u.title, v.transition & 0xFF AS transition
FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time;
-- Chromium downloads
SELECT datetime(start_time/1000000 - 11644473600,'unixepoch') AS start_utc, target_path, tab_url, referrer, total_bytes, danger_type, mime_type
FROM downloads ORDER BY start_time;
-- Firefox visits (PRTime microseconds since 1970)
SELECT datetime(h.visit_date/1000000,'unixepoch') AS visit_utc, p.url, p.title FROM moz_historyvisits h JOIN moz_places p ON p.id = h.place_id ORDER BY h.visit_date;
```

Safari timestamps: Mac absolute time (seconds since 2001-01-01) → add 978307200.

---

## 3. Investigation Patterns

| Question | Evidence |
|---|---|
| Phishing click | History visit with `transition` link/typed from webmail referrer; proxy log; email click logs (`UrlClickEvents`) |
| Malicious download | `downloads` row (tab_url, referrer, target_path) + Zone.Identifier ADS (`HostUrl`, `ReferrerUrl`) + execution artifacts |
| Credential entry on phish | Visit to lookalike domain + `Login Data`/form history entries (if saved) + IdP sign-in from attacker IP shortly after |
| OAuth consent phishing | Visit to `login.microsoftonline.com/.../oauth2/...consent` + Entra audit "Consent to application" |
| Malicious extension | New extension ID in `Extensions\` + broad permissions (`<all_urls>`, `cookies`, `webRequest`) + install time |
| Session cookie theft | Infostealer execution on host (reads of `Cookies`/`Login Data`/`Local State` by non-browser process) + session reuse from new IP in IdP logs |
| Fake CAPTCHA / ClickFix | Visit to lure site, then `explorer.exe`→`powershell`/`mshta` and RunMRU registry entry with pasted command |

---

## 4. Tools

| Tool | Use |
|---|---|
| Hindsight | Chromium timeline (History, cookies, extensions, preferences) → XLSX/SQLite |
| DB Browser for SQLite / sqlite3 | Manual queries (work on copies; include `-wal` files) |
| KAPE targets (`WebBrowsers`) / Velociraptor (`Windows.Applications.Chrome.History` etc.) | Collection at scale |
| Plaso parsers | Super timeline inclusion |
| BrowsingHistoryView (NirSoft) | Quick multi-browser view |

Copy SQLite files **with** their `-wal`/`-journal` companions — recent activity may only be in the WAL.

---

## Engagement Cheatsheet

```text
collect all profiles (+WAL) → History/visits/downloads, places.sqlite, Safari History.db → UTC conversion (1601 µs / PRTime / 2001 s)
→ downloads ↔ Zone.Identifier ↔ execution → extensions & permissions → credential/cookie theft indicators ↔ IdP logs → click→download→execute narrative
```

---

## Key References

- Hindsight (obsidianforensics); SANS browser forensics posters; Mozilla/Chromium source docs for schema
- Related: `defensive-windows-forensics`, `defensive-macos-forensics`, `defensive-phishing-triage`, `defensive-detect-initial-access`, `defensive-timeline-analysis`
