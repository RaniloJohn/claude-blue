---
name: defensive-tool-kape-eztools
description: "KAPE (Kroll Artifact Parser and Extractor) and Eric Zimmerman's tools for Windows triage: licensing terms check, safe collection from external media, targets (KapeTriage, !SANS_Triage, RegistryHives, EventLogs, $MFT, $J), modules (!EZParser), VSS processing, VHDX/ZIP containers with transfer, sync/update of targets and modules, Get-ZimmermanTools with .NET runtime selection and date-based versions, key EZ tools (MFTECmd, EvtxECmd with maps, PECmd, AmcacheParser, AppCompatCacheParser, RECmd batch files, LECmd, JLECmd, SBECmd, SrumECmd, RBCmd, WxTCmd, Timeline Explorer, Registry Explorer), chain of custody, and pitfalls. Use when collecting or parsing Windows forensic artifacts with KAPE/EZ Tools."
---

# KAPE & Eric Zimmerman's Tools

KAPE collects (targets) and processes (modules) Windows artifacts fast; EZ Tools parse them into CSV for Timeline Explorer or SIEM. Together they are the standard Windows triage kit.

## Quick Workflow

1. Confirm license terms (KAPE: check Kroll's current terms — commercial/third-party use has historically required a paid license)
2. Update targets/modules (`--sync`) and EZ Tools on the **analysis** workstation, not the victim
3. Collect from external/network media with admin rights; write output off the evidence volume
4. Process with `!EZParser` (or run EZ Tools manually) on the analysis machine
5. Hash outputs; record tool versions and command lines in the case notes

---

## 1. KAPE Collection

```powershell
# Triage to VHDX container, with VSS, flush destination
.\kape.exe --tsource C: --tdest E:\Case42\%m\T --tflush --target KapeTriage --vss --vhdx %m --zv false
# Collect + process in one pass
.\kape.exe --tsource C: --tdest E:\Case42\%m\T --target KapeTriage --mdest E:\Case42\%m\M --module !EZParser --mef csv
# Process an existing collection (analysis workstation)
.\kape.exe --msource E:\Case42\HOST\T --mdest E:\Case42\HOST\M --module !EZParser
# Update targets/modules
.\kape.exe --sync
```

| Option | Purpose |
|---|---|
| `--target KapeTriage` / `!SANS_Triage` / `RegistryHives` / `EventLogs` / `FileSystem` | Compound target sets |
| `--vss` | Include Volume Shadow Copies |
| `--vhdx`/`--vhd`/`--zip` | Containerize output |
| `%m`, `%d` | Machine name / timestamp variables |
| `--tflush`/`--mflush` | Delete destination before writing — use carefully |
| `--scs/--scp/--scu/--scpw` | SFTP transfer of container; `--s3*` for S3 |
| `gkape.exe` | GUI that builds the command line |

Safety:
- Run from removable/network media; never install on the evidence host
- Destination must not be the source volume (avoid overwriting unallocated space)
- Transfer credentials embedded in command lines are visible in process telemetry — use short-lived, write-only credentials
- KAPE uses raw access for locked files; still a live system change (processes, prefetch, logs) — document it
- AV/EDR may flag KAPE or its modules — coordinate exclusions for the IR window only

---

## 2. Installing EZ Tools

```powershell
.\Get-ZimmermanTools.ps1 -Dest C:\Tools\EZ -NetVersion 9
```

EZ Tools ship .NET builds (use the current runtime option offered by the script; older .NET 4/6 builds are legacy) and now use date-based versions (e.g., MFTECmd 2026.10.x). Keep maps (EvtxECmd) and batch files (RECmd) updated: `EvtxECmd.exe --sync`, `RECmd` batch files in `BatchExamples`.

---

## 3. Key Tools

| Tool | Artifact | Example |
|---|---|---|
| MFTECmd | `$MFT`, `$J` (USN), `$LogFile`, `$Boot`, `$SDS` | `MFTECmd.exe -f "E:\C\$MFT" --csv out --csvf mft.csv` ; `-f "$J" --csv out` |
| EvtxECmd | EVTX with maps | `EvtxECmd.exe -d E:\C\Windows\System32\winevt\Logs --csv out --csvf evtx.csv` |
| PECmd | Prefetch | `PECmd.exe -d E:\C\Windows\Prefetch --csv out` |
| AmcacheParser | Amcache.hve | `AmcacheParser.exe -f Amcache.hve -i --csv out` |
| AppCompatCacheParser | Shimcache (SYSTEM hive) | `AppCompatCacheParser.exe -f SYSTEM --csv out` |
| RECmd | Registry with batch files | `RECmd.exe -d E:\C --bn BatchExamples\Kroll_Batch.reb --csv out` |
| LECmd / JLECmd | LNK / Jump Lists | `LECmd.exe -d E:\C\Users --csv out` |
| SBECmd | ShellBags | `SBECmd.exe -d E:\C\Users --csv out` |
| SrumECmd | SRUM (network/app usage) | `SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv out` |
| RBCmd | Recycle Bin `$I` files | `RBCmd.exe -d "E:\C\$Recycle.Bin" --csv out` |
| WxTCmd | Windows Timeline (ActivitiesCache.db) | `WxTCmd.exe -f ActivitiesCache.db --csv out` |
| Timeline Explorer | View/filter CSVs | GUI |
| Registry Explorer | Interactive hive analysis (handles dirty hives with transaction logs) | GUI |

Dirty hives: replay transaction logs (`.LOG1/.LOG2`) — Registry Explorer/RECmd prompt for this; keep originals untouched.

---

## 4. Evidence Handling

```powershell
Get-FileHash -Algorithm SHA256 E:\Case42\HOST\T\*.vhdx | Export-Csv E:\Case42\HOST\hashes.csv -NoTypeInformation
```

Record: collector name, time (UTC), host, KAPE version, target/module list, command line, hashes, chain-of-custody handoffs.

---

## 5. Pitfalls

- Timezones: EZ Tools output UTC — keep the timeline in UTC
- `$J` may be large and partly overwritten; collect early
- Prefetch disabled on some servers (SSD/server defaults) — absence isn't evidence of absence
- Shimcache entries ≠ proof of execution on modern Windows; Amcache presence + other artifacts needed
- Running modules on the victim host alters it and wastes time — process elsewhere

---

## Engagement Cheatsheet

```text
license check → update on analysis box (--sync, Get-ZimmermanTools) → kape --target KapeTriage --vss --vhdx from external media (dest ≠ source)
→ hash container → process !EZParser offline → MFTECmd/EvtxECmd/PECmd/Amcache/AppCompat/RECmd/LECmd/SBECmd/SrumECmd → Timeline Explorer (UTC) → document versions & commands
```

---

## Key References

- Kroll KAPE documentation & KapeFiles repository; ericzimmerman.github.io (EZ Tools, Get-ZimmermanTools)
- SANS Windows Forensic Analysis poster
- Related: `defensive-windows-forensics`, `defensive-timeline-analysis`, `defensive-tool-velociraptor`, `defensive-live-response`
