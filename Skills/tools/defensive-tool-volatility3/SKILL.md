---
name: defensive-tool-volatility3
description: "Volatility 3 memory forensics framework operation and safety from official documentation: installation (pip/venv), version (2.x series; Volatility 2 deprecated after May 2025 parity release), symbol tables (Windows PDB auto-download vs offline symbol packs, Linux/macOS ISF generation with dwarf2json), plugin reference for Windows (info, pslist, pstree, psscan, cmdline, netscan, malfind, dlllist, handles, svcscan, filescan, dumpfiles, registry, hashdump caveat), Linux and macOS plugins, renderers (JSON/CSV) and output directories, analysis workflow, handling dumped malicious files, protecting sensitive memory images, and common errors. Use when analyzing memory images with Volatility 3."
---

# Volatility 3

Volatility 3 is the maintained memory analysis framework (2.x series; 2.28.x observed 2026-10-23). Volatility 2 is deprecated since the May 2025 parity release — migrate any old profiles/workflows.

## Quick Workflow

1. Install in an isolated analysis VM (venv); prepare symbols (online or offline packs)
2. Hash the image; work on a copy
3. `windows.info` (or `banners.Banners` for Linux) to confirm OS/symbols
4. Process → network → injection → persistence → files/registry
5. Export JSON/CSV; dump suspicious objects into a quarantined directory
6. Correlate with disk/log timelines

---

## 1. Install

```bash
python3 -m venv ~/vol3 && . ~/vol3/bin/activate
pip install volatility3          # or: git clone https://github.com/volatilityfoundation/volatility3 && pip install -e ".[full]"
vol -h
```

---

## 2. Symbols

| OS | Behavior |
|---|---|
| Windows | Downloads PDB symbols from Microsoft's symbol server on demand → needs internet. Offline: place Windows symbol pack (`windows.zip`) in `volatility3/symbols/` or pass `-s <dir>`; use `--offline` (2.x) to stop remote fetches in air-gapped labs |
| Linux | Requires ISF (JSON) for the **exact** kernel: build with `dwarf2json linux --elf vmlinux-with-debug --system-map System.map > kernel.json` and place in `symbols/linux/` |
| macOS | ISF from kernel debug kit via `dwarf2json mac` |

Identify the kernel: `vol -f mem.lime banners.Banners`.

---

## 3. Windows Plugins

```bash
vol -f mem.raw windows.info
vol -f mem.raw windows.pslist ; vol -f mem.raw windows.pstree ; vol -f mem.raw windows.psscan   # psscan finds unlinked/terminated
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.netscan                 # connections + owning PID
vol -f mem.raw windows.malfind --pid 4321      # RWX/private executable regions (injection)
vol -f mem.raw windows.dlllist --pid 4321 ; vol -f mem.raw windows.ldrmodules --pid 4321
vol -f mem.raw windows.handles --pid 4321
vol -f mem.raw windows.svcscan
vol -f mem.raw windows.filescan | grep -i '\.ps1\|\\temp\\'
vol -f mem.raw -o ./dump windows.dumpfiles --virtaddr 0xfa8001234560
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.vadyarascan --yara-file rules.yar     # YARA over process memory (plugin name varies by version: yarascan/vadyarascan)
vol -f mem.raw windows.ssdt ; vol -f mem.raw windows.callbacks ; vol -f mem.raw windows.driverscan   # rootkit checks
```

Credential plugins (`windows.hashdump`, `windows.lsadump`, `windows.cachedump`) extract secrets — run only when the investigation requires it, protect output as credentials, and note that results are sensitive evidence.

---

## 4. Linux & macOS

```bash
vol -f mem.lime linux.pslist ; vol -f mem.lime linux.pstree ; vol -f mem.lime linux.psaux
vol -f mem.lime linux.bash                     # bash history from memory
vol -f mem.lime linux.sockstat                 # sockets (plugin availability varies)
vol -f mem.lime linux.malfind ; vol -f mem.lime linux.check_modules ; vol -f mem.lime linux.check_syscall
vol -f mem.raw mac.pslist ; vol -f mem.raw mac.bash ; vol -f mem.raw mac.netstat
```

---

## 5. Output

```bash
vol -r json -f mem.raw windows.pslist > pslist.json
vol -r csv  -f mem.raw windows.netscan > netscan.csv
vol -q -f mem.raw -o ./artifacts windows.malfind --dump    # dumped regions to ./artifacts
```

Use `-q` to suppress progress output in scripts; `-vvv` to debug symbol issues.

---

## 6. Workflow

| Step | Look for |
|---|---|
| Processes | Wrong parent (e.g., `svchost.exe` not under `services.exe`), wrong path, misspellings, psscan-only processes |
| Command lines | Encoded PowerShell, LOLBins, tools |
| Network | Connections from unexpected processes; listening backdoors |
| Injection | `malfind` hits with MZ headers or shellcode in non-image memory; unlinked DLLs (`ldrmodules` False/False/False) |
| Persistence | Services, Run keys in hives, scheduled tasks in memory artifacts |
| Kernel | Unknown drivers, SSDT/callback hooks |
| Files | Scripts, droppers via `filescan` + `dumpfiles` |

---

## 7. Safety

- Memory images contain passwords, tokens, keys, PII → encrypt at rest, restrict access, retention per policy
- Dumped files/regions may be live malware → output inside the analysis VM; AV may quarantine them (exclude only the quarantined case folder in the lab)
- Don't upload dumps to public sandboxes without approval
- Record Volatility version and symbol source in the report for reproducibility

---

## 8. Common Errors

| Error | Fix |
|---|---|
| "Unsatisfied requirement … symbol_table_name" | Missing/incorrect symbols — check network/offline pack; for Linux build exact ISF |
| Empty results | Wrong OS plugin family; corrupted/partial image; smeared acquisition (re-acquire) |
| Slow scans | Use `--pid` filters; scan plugins are expensive |

---

## Engagement Cheatsheet

```text
isolated venv → symbols (online / offline pack / dwarf2json ISF) → hash image → windows.info|banners → pslist/pstree/psscan → cmdline → netscan
→ malfind/ldrmodules → svcscan/registry → filescan/dumpfiles → kernel checks → -r json/csv → protect image & dumps → note versions
```

---

## Key References

- volatility3.readthedocs.io; Volatility Foundation release announcements (parity release May 16, 2025); dwarf2json
- Related: `defensive-memory-forensics`, `defensive-dynamic-analysis`, `defensive-timeline-analysis`
