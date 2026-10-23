---
name: defensive-tool-plaso
description: "Plaso (log2timeline) super-timeline generation and analysis from official documentation: date-based releases, Docker usage, log2timeline extraction from images (E01, raw, VMDK, VSS) and triage folders, parser presets and filter files to limit scope, storage files, pinfo for provenance, psort output modules (dynamic, l2tcsv, json_line, OpenSearch) and filtering, psteal one-shot, time zone handling, performance tuning (workers, process memory limits), Timesketch import, and evidence/workflow safety. Use when building or analyzing a super timeline with Plaso."
---

# Plaso (log2timeline)

Plaso extracts timestamps from hundreds of artifact types into one timeline. It's thorough and slow — scope it with parsers and filter files, then analyze in Timesketch or Timeline Explorer. Versions are date-based (latest observed 20260928).

## Quick Workflow

1. Run in Docker or a dedicated venv on the analysis host
2. Point at a read-only image/mount or triage collection
3. Use a parser preset and filter file to limit scope
4. Inspect with `pinfo.py`; export with `psort.py` filtered by date
5. Load into Timesketch for collaborative analysis

---

## 1. Running

```bash
docker pull log2timeline/plaso
docker run --rm -v /cases/42:/data log2timeline/plaso log2timeline.py --storage-file /data/host.plaso /data/host.E01
docker run --rm -v /cases/42:/data log2timeline/plaso psort.py -o dynamic -w /data/host.csv /data/host.plaso
```

Pin the image by digest for reproducibility; record the Plaso version (`log2timeline.py --version`).

---

## 2. Scoping Extraction

```bash
log2timeline.py --parsers 'win7,!filestat' --storage-file host.plaso /mnt/evidence        # preset minus noisy filestat
log2timeline.py -f filter_windows.yaml --storage-file host.plaso host.E01                  # only paths in filter file
log2timeline.py --vss-stores all --storage-file host.plaso host.E01                        # include shadow copies
log2timeline.py --partitions all --storage-file host.plaso disk.raw
log2timeline.py --info                                                                       # list parsers/presets
```

Filter file example (YAML artifact-style paths): EVTX, registry hives, prefetch, Amcache, `$MFT`, browser histories, LNK, jump lists, scheduled tasks.

Performance: `--workers N`, `--worker-memory-limit`, place storage on fast disk; `filestat` on full images is the biggest volume driver.

---

## 3. Inspect & Export

```bash
pinfo.py host.plaso                                    # parsers used, counts, warnings, source info
psort.py -o dynamic -w timeline.csv host.plaso "date > '2026-10-15 00:00:00' AND date < '2026-10-22 00:00:00'"
psort.py -o json_line -w timeline.jsonl host.plaso
psort.py --output-time-zone UTC -o l2tcsv -w l2t.csv host.plaso
psort.py -o opensearch --server es.lab --port 9200 --index_name case42 host.plaso
psteal.py --source host.E01 -o dynamic -w quick.csv     # extract + export in one step
```

Use `--analysis` plugins sparingly (tagging, browser search, hash lookups — online lookups leak hashes to third parties).

---

## 4. Timesketch

Import `.plaso` or JSONL/CSV into Timesketch; use saved searches, tags, stories, and analyzers (e.g., Sigma, domain, browser timeframe). Restrict Timesketch access (SSO), as timelines contain user activity and PII.

---

## 5. Safety & Pitfalls

| Issue | Practice |
|---|---|
| Evidence integrity | Mount images read-only; work on copies; hash `.plaso` outputs too |
| Time zones | Plaso stores UTC; some artifacts store local time — check parser notes and host TZ (registry `TimeZoneInformation`) |
| Volume | Full-disk super timelines reach tens of millions of rows — filter by time window and source types |
| Timestamps semantics | Distinguish creation/modification/access/entry-modified (MACB) — access times may be disabled or updated by triage tools |
| Parser warnings | Review `pinfo.py` warnings — corrupt artifacts may be silently skipped |
| Privacy | Timelines expose browsing/user activity — restrict access, retention |

---

## Engagement Cheatsheet

```text
Docker (pinned digest) → log2timeline --parsers preset,!filestat -f filter.yaml (--vss-stores all) → pinfo (warnings, counts)
→ psort -o dynamic|json_line date window --output-time-zone UTC → Timesketch (SSO) → MACB semantics + TZ checks → hash outputs
```

---

## Key References

- plaso.readthedocs.io (log2timeline, psort, filter files, parsers); Timesketch docs
- Related: `defensive-timeline-analysis`, `defensive-tool-kape-eztools`, `defensive-windows-forensics`
