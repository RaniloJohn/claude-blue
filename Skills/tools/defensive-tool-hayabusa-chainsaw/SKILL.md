---
name: defensive-tool-hayabusa-chainsaw
description: "Fast Windows event log triage with Hayabusa (Yamato Security) and Chainsaw (WithSecure): Hayabusa 4.x dfir-timeline command replacing csv-timeline/json-timeline, output profiles and min-level filtering, update-rules, logon-summary with RDP and GeoIP, search, eid-metrics, computer-metrics, pivot-keywords-list, live analysis and AV false positives on Sigma YAML (live-response packages with encoded rules), Chainsaw hunt with Sigma mappings, search, SRUM and Shimcache analysis, Takajo for Hayabusa result analysis, offline evidence handling, and tuning noisy rules. Use when triaging EVTX files quickly with Sigma-based tools."
---

# Hayabusa & Chainsaw

Both apply Sigma (and built-in) rules to EVTX files at high speed, producing a prioritized timeline before a full SIEM ingest is possible. Hayabusa 4.2.0 and Chainsaw 2.17.1 observed 2026-10-23.

## Quick Workflow

1. Collect EVTX (KAPE/Velociraptor) — analyze offline copies when possible
2. Update rules on the analysis machine
3. Run a timeline at `--min-level medium` (then low) and logon summary
4. Pivot on high/critical hits; search keywords; build a narrative
5. Import CSV/JSONL into Timeline Explorer, Elastic, or Timesketch

---

## 1. Hayabusa 4.x

Breaking change: v4.0.0 replaced `csv-timeline` and `json-timeline` with **`dfir-timeline`** (`-t csv|json|jsonl`; old `json-timeline -L` → `-t jsonl`).

```powershell
hayabusa.exe update-rules
hayabusa.exe dfir-timeline -d E:\Case42\evtx -t csv -o timeline.csv -p verbose --min-level medium
hayabusa.exe dfir-timeline -d E:\Case42\evtx -t jsonl -o timeline.jsonl
hayabusa.exe logon-summary -d E:\Case42\evtx -G <geoip-db-dir> -o logons     # includes RDP sessions; ASN/country/city with -G
hayabusa.exe search -d E:\Case42\evtx -k "mimikatz" -k "sekurlsa"            # -b disables field abbreviations
hayabusa.exe eid-metrics -d E:\Case42\evtx
hayabusa.exe computer-metrics -d E:\Case42\evtx
hayabusa.exe pivot-keywords-list -d E:\Case42\evtx -o pivots
hayabusa.exe level-tuning -f tuning.txt                                       # adjust rule levels for your environment
```

(Flags evolve — run `hayabusa.exe help <command>` for your version.)

Live analysis: running on a live host triggers AV on Sigma `.yml` files (false positives). The project ships **live-response packages** (e.g., `hayabusa-4.x-win-x64-live-response.zip`) with encoded rules for this purpose. Prefer offline copies; if live, run from external media and record the action.

Takajo (Yamato Security) post-processes Hayabusa JSONL (process trees, stacking, VirusTotal lookups — mind data sharing).

---

## 2. Chainsaw

```bash
chainsaw hunt E:/Case42/evtx -s sigma/rules --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output out/
chainsaw hunt E:/Case42/evtx -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --level high --json > hits.json
chainsaw search mimikatz -i E:/Case42/evtx
chainsaw search -t 'Event.System.EventID: =4624' E:/Case42/evtx
chainsaw analyse srum --software SOFTWARE SRUDB.dat -o srum.json
chainsaw analyse shimcache SYSTEM --amcache Amcache.hve --tspair
```

Keep the Sigma repo pinned to a known commit for reproducibility; record commit hash in reports.

---

## 3. Triage Strategy

| Pass | Goal |
|---|---|
| Critical/high | Immediate leads (credential dumping, log clearing, known tools) |
| Medium | Suspicious behavior needing context |
| Logon summary | Account/source anomalies, RDP sources, failed logon patterns |
| EID metrics | Missing logs (audit gaps, cleared logs) |
| Keyword search | IOCs from intel/other hosts |
| Low/informational | Timeline filler around key times |

---

## 4. Tuning & Pitfalls

- Expect noise from admin tools and installers — use level tuning/exclusions, never delete rules from the evidence run record
- Missing channels (Sysmon/PowerShell not enabled) → rules silently produce nothing; check `eid-metrics`
- Timestamps in UTC by default — keep UTC; note host timezone separately
- Rules detect patterns, not verdicts — confirm with raw events
- Large datasets: scope by date range/computer to speed up

---

## Engagement Cheatsheet

```text
collect EVTX → update-rules (analysis box) → hayabusa dfir-timeline -t csv/jsonl --min-level medium → logon-summary (-G) → eid-metrics (gaps)
→ search IOCs → chainsaw hunt with Sigma mappings / analyse srum,shimcache → pin rule commit → confirm in raw events → timeline tool
```

---

## Key References

- github.com/Yamato-Security/hayabusa (v4 changelog, live-response packages); Takajo
- github.com/WithSecureLabs/chainsaw
- Related: `defensive-windows-event-logs`, `defensive-sigma`, `defensive-timeline-analysis`, `defensive-tool-kape-eztools`
