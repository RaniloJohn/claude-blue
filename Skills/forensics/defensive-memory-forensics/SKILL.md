---
name: defensive-memory-forensics
description: "Memory forensics with Volatility 3 (parity release May 2025; Volatility 2 deprecated): acquisition, symbol tables, Windows plugins (info, pslist, psscan, pstree, cmdline, dlllist, ldrmodules, malfind, vadinfo, handles, netscan, svcscan, filescan, dumpfiles, registry.hivelist/printkey, getsids, privileges, vadyarascan), Linux plugins, detecting process hollowing, injection, unlinked DLLs, unbacked executable memory, hidden processes, credential artifacts, and memory-resident malware; plus MemProcFS. Use when analyzing RAM images or EDR memory dumps."
---

# Memory Forensics

Memory shows what was actually running: injected code, decrypted payloads, network sockets, and command lines that never touched disk. Volatility 3 is the standard; Volatility 2 is deprecated and archived since the 2025 parity release.

## Quick Workflow

1. Acquire and hash; note OS build
2. `windows.info` — confirm profile/symbols resolve
3. Process inventory: `pslist` vs `psscan` vs `pstree`
4. Command lines and parent anomalies
5. Network: `netscan`
6. Injection: `malfind`, `ldrmodules`, `vadinfo`
7. Dump suspects; YARA + static triage
8. Correlate with disk/EDR timeline

---

## 1. Setup

```bash
pip install volatility3          # provides `vol`
vol -f mem.raw windows.info      # downloads Windows PDB symbols automatically if online
```

Offline: pre-populate `volatility3/symbols/` with Windows symbol packs. Linux/macOS need ISF from kernel debug info (`dwarf2json`).

---

## 2. Process Analysis

```bash
vol -f mem.raw windows.pslist
vol -f mem.raw windows.psscan            # finds unlinked/terminated EPROCESS
vol -f mem.raw windows.pstree
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.getsids --pid <pid>
vol -f mem.raw windows.privileges --pid <pid>
vol -f mem.raw windows.envars --pid <pid>
```

| Check | Suspicious |
|---|---|
| In `psscan` not `pslist` | Hidden (DKOM) or exited |
| Wrong parent | `lsass.exe` not child of `wininit.exe`; `svchost.exe` not child of `services.exe` |
| Wrong path | System binary outside `System32` |
| Name typosquat | `lsasss.exe`, `svch0st.exe`, `scvhost.exe` |
| Multiple instances | >1 `lsass.exe`, >1 `wininit.exe` |
| `svchost.exe` without `-k` | Masquerade |
| Odd start time | System process starting long after boot |
| SID mismatch | System process running as user SID |

---

## 3. Injection & Hollowing

```bash
vol -f mem.raw windows.malfind                      # RWX private VADs with code / MZ
vol -f mem.raw windows.malfind --pid <pid> --dump
vol -f mem.raw windows.ldrmodules --pid <pid>       # InLoad/InInit/InMem False = unlinked DLL
vol -f mem.raw windows.vadinfo --pid <pid>
vol -f mem.raw windows.dlllist --pid <pid>
vol -f mem.raw windows.hollowprocesses              # hollowing indicators (recent vol3 releases)
```

| Pattern | Indicator |
|---|---|
| Classic injection | `PAGE_EXECUTE_READWRITE` private memory with MZ or shellcode prologue |
| Reflective DLL | MZ in private memory, not in loader lists |
| Hollowing | Image VAD path ≠ PEB image path; mapped image section replaced |
| Module stomping | Legit DLL mapped, but in-memory bytes differ from on-disk |
| Unbacked threads | Thread start address not within any loaded module |

False positives in `malfind`: JIT engines (.NET, browsers, Java), some AV/EDR. Validate by disassembly and dumped content.

---

## 4. Network & Handles

```bash
vol -f mem.raw windows.netscan          # TCP/UDP endpoints with owning PID
vol -f mem.raw windows.netstat          # walks live structures (newer builds)
vol -f mem.raw windows.handles --pid <pid>    # files, keys, mutants (mutex IOCs), events
vol -f mem.raw windows.mutantscan
```

---

## 5. Persistence & Services

```bash
vol -f mem.raw windows.svcscan
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.scheduled_tasks        # where supported
vol -f mem.raw windows.driverscan ; vol -f mem.raw windows.modules ; vol -f mem.raw windows.ssdt
```

---

## 6. Files & Extraction

```bash
vol -f mem.raw windows.filescan | grep -i "\\Users\\.*\\AppData"
vol -f mem.raw windows.dumpfiles --virtaddr <addr>
vol -f mem.raw windows.pslist --pid <pid> --dump      # dump process image
vol -f mem.raw windows.memmap --pid <pid> --dump      # full process memory
vol -f mem.raw windows.vadyarascan --yara-file rules.yar
```

Hash and YARA-scan dumps; submit hashes (not internal files) to reputation services per policy.

---

## 7. Credential Artifacts

- `windows.hashdump`, `windows.lsadump`, `windows.cachedump` — show what an attacker could extract; treat output as sensitive (rotate affected creds)
- Detect *attacker* credential access via LSASS handles from non-system processes (`windows.handles` on suspect PIDs with `lsass.exe` process handles)

---

## 8. MemProcFS

Mounts memory as a filesystem (`M:\`) with processes, handles, findevil, timeline CSVs:

```bash
MemProcFS.exe -device mem.raw -forensic 1
# M:\forensic\csv\  → timeline_*.csv, findevil.csv
```

`findevil` flags injection, PE anomalies, and suspicious threads — fast first pass.

---

## Engagement Cheatsheet

```text
info → pslist/psscan/pstree → cmdline → netscan → malfind/ldrmodules/hollowprocesses
→ handles/mutants → svcscan/registry → dump + YARA → correlate with disk timeline
```

---

## Key References

- Volatility 3 — https://github.com/volatilityfoundation/volatility3 ; parity release announcement (May 2025)
- The Art of Memory Forensics (Ligh, Case, Levy, Walters)
- MemProcFS — https://github.com/ufrisk/MemProcFS
- SANS FOR508 / FOR526 memory forensics posters
- Related: `defensive-live-response`, `defensive-malware-triage`, `defensive-yara`
