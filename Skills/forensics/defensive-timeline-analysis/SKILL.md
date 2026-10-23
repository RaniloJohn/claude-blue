---
name: defensive-timeline-analysis
description: "Forensic timeline construction and analysis: super-timelines with Plaso (log2timeline, psort, pinfo), Timesketch collaborative analysis, EZ Tools + Timeline Explorer CSV timelines, Hayabusa/Chainsaw EVTX timelines, merging host, network, identity, and cloud logs, UTC normalization and clock skew, anchor-and-pivot methodology, MACB semantics, filtering noise, pivot points, and producing a defensible incident narrative with root cause and dwell time. Use when reconstructing what happened across one or many systems."
---

# Timeline Analysis

A timeline turns artifacts into a story with causality. Build from anchors outward; never try to read a million-row super-timeline top to bottom.

## Quick Workflow

1. Collect sources; normalize all times to UTC; record skew
2. Identify anchors (high-confidence malicious events)
3. Generate targeted timelines (window around anchors), then super-timeline if needed
4. Filter noise (known-good paths, update activity)
5. Walk backward to initial access; forward to objectives
6. Tag events with ATT&CK and confidence
7. Write the narrative

---

## 1. Sources by Layer

| Layer | Sources |
|---|---|
| Host file system | $MFT, $J, $LogFile, Prefetch, LNK, ShellBags, Amcache |
| Host logs | EVTX, Sysmon, PowerShell, syslog/journald, auditd, Unified Log |
| Memory | Process create times, socket times |
| Identity | DC Security logs, Entra sign-ins, Okta System Log |
| Network | Zeek, Suricata, firewall, proxy, DNS, VPN |
| Cloud | CloudTrail, Azure Activity, GCP Audit |
| Email | Message trace, UAL |
| EDR | Process/network/file telemetry |

---

## 2. Plaso

```bash
log2timeline.py --storage-file case.plaso /evidence/disk.E01
log2timeline.py --parsers "win7,!filestat" --storage-file case.plaso /evidence/disk.E01   # parser presets
pinfo.py case.plaso
psort.py -o l2tcsv -w case.csv case.plaso "date > '2026-10-20 00:00:00' AND date < '2026-10-22 00:00:00'"
psort.py -o dynamic -w case.csv case.plaso
```

Import `.plaso` into **Timesketch** for multi-analyst tagging, starring, saved views, and analyzers (e.g., browser search, account finder, Sigma).

---

## 3. Targeted Timelines (faster)

```text
KAPE/EZ Tools CSVs (MFT, USN, Prefetch, Amcache, EVTX, LNK) → Timeline Explorer
Hayabusa csv-timeline for EVTX with Sigma tagging:
  hayabusa csv-timeline -d ./evtx -o hayabusa.csv -p super-verbose
Chainsaw for hunt-focused EVTX:
  chainsaw hunt ./evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml --csv -o out/
```

Merge network/cloud logs as CSV with columns: `time_utc, source, host, user, event, details, ref`.

---

## 4. MACB Semantics (NTFS)

| Letter | $STANDARD_INFORMATION | Meaning |
|---|---|---|
| M | Modified | Content changed |
| A | Accessed | Last access (often disabled/lazy) |
| C | MFT entry changed | Metadata changed |
| B | Born | Created |

`$FILE_NAME` times update on create/rename/move — harder to forge. Copy within volume vs move behave differently; know your OS version's rules before concluding.

---

## 5. Anchor-and-Pivot Method

1. Anchor: e.g., EDR alert on `C:\ProgramData\x.exe` at 2026-10-21T02:14:07Z
2. Look −10 min / +10 min across all sources on that host
3. Identify parent action (download? service? remote logon?)
4. Pivot to that new anchor (e.g., 4624 type 3 from 10.1.2.3 at 02:13:51Z)
5. Jump to source host 10.1.2.3, repeat
6. Stop when reaching initial access (phish, exploit, valid creds) or log horizon

---

## 6. Noise Reduction

- Exclude Windows Update, AV definition updates, software deployment folders (`ccmcache`) unless relevant
- Filter `$MFT` to user-writable paths for initial pass: `Users\`, `ProgramData\`, `Windows\Temp\`, `PerfLogs\`, web roots
- Collapse repetitive events (same event within seconds)
- Tag known-good before hunting unknowns

---

## 7. Time Pitfalls

| Pitfall | Mitigation |
|---|---|
| Mixed time zones | Normalize to UTC at ingest; keep original field |
| Clock skew between hosts | Compare known cross-host events (Kerberos, SMB) |
| Log ingestion time vs event time | Use event time fields (`TimeCreated`, `eventTime`) |
| FAT/exFAT local time, 2 s resolution | Note precision |
| Daylight saving transitions | UTC normalization |

---

## 8. Narrative Output

```markdown
| Time (UTC) | Host | Source | Event | ATT&CK | Confidence |
|---|---|---|---|---|---|
| 2026-10-20T13:02:11Z | WS-114 | Email trace | Phishing email delivered to j.doe | T1566.001 | High |
| 2026-10-20T13:05:40Z | WS-114 | Sysmon 1 | WINWORD.EXE → powershell.exe -enc ... | T1204.002, T1059.001 | High |
...
Root cause: <vector + failed control>
Dwell time: <first malicious → eradication>
Gaps: <log rollover, missing sources>
```

---

## Engagement Cheatsheet

```text
UTC normalize → anchors → targeted CSV timelines → pivot backward/forward
→ super-timeline only if needed → tag ATT&CK + confidence → narrative + gaps
```

---

## Key References

- Plaso — https://plaso.readthedocs.io ; Timesketch — https://timesketch.org
- Hayabusa, Chainsaw; Eric Zimmerman Timeline Explorer
- Related: `defensive-windows-forensics`, `defensive-linux-forensics`, `defensive-ir-reporting`
