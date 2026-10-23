---
name: defensive-yara
description: "YARA and YARA-X rule writing for malware detection, threat hunting, and file/memory scanning. Use when writing or reviewing YARA rules, choosing strings (text, hex, regex, wide, nocase, xor, base64), building conditions with magic bytes, filesize, and modules (pe, elf, macho, dotnet, math, hash, lnk, dex), avoiding slow atoms, testing against goodware, migrating to YARA-X (yr check, yr fmt, stricter parsing), scanning memory dumps or Velociraptor/THOR/Loki/EDR integrations, and writing YARA-L 2.0 for Google SecOps."
---

# YARA / YARA-X

YARA matches files and memory; it is not a behavioral detector. Good rules anchor on file structure plus multiple independent, hard-to-change artifacts.

**Status (2026):** YARA-X (Rust rewrite, VirusTotal) reached 1.0 in June 2025 and is the actively developed engine; classic YARA is maintenance-only. CLI binary: `yr`.

## Quick Workflow

1. Collect ≥3 samples of the family; diff for stable artifacts
2. Pick anchors: magic bytes, structure, unique strings, code bytes
3. Write strings; avoid short/common atoms
4. Condition: structure AND N of strings, bounded by filesize
5. Test: samples (TP) + goodware corpus (FP) + performance
6. Version, tag, document

---

## 1. Rule Anatomy

```yara
import "pe"

rule CB_Loader_Example_2026
{
    meta:
        author      = "claude-blue"
        description = "Loader family X — config decryption stub and mutex"
        date        = "2026-10-23"
        reference   = "internal case 2026-114"
        mitre       = "T1027, T1055"
        hash1       = "<sha256 of reference sample>"
        tlp         = "TLP:AMBER"
    strings:
        $mutex   = "Global\\cb_x_7f3a" ascii wide
        $cfg     = { 8B 45 ?? 33 C9 8A 14 08 80 F2 5A 88 14 08 41 3B CE 7C F3 }   // xor 0x5A loop
        $pdb     = /\\Release\\[a-z]{4,12}\.pdb/ nocase
        $ua      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) cbx" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        pe.number_of_sections < 8 and
        2 of ($mutex, $cfg, $pdb, $ua)
}
```

---

## 2. String Types & Modifiers

| Form | Use |
|---|---|
| `"text"` | ASCII literal |
| `ascii wide` | Match both ASCII and UTF-16LE |
| `nocase` | Case-insensitive (slower) |
| `fullword` | Delimited by non-alphanumerics |
| `xor` / `xor(0x01-0xff)` | Single-byte XOR variants |
| `base64` / `base64wide` | Base64-encoded forms (min length 3 in YARA-X) |
| `{ 4D 5A ?? ?? [2-4] 50 45 }` | Hex with wildcards and jumps |
| `/regex/` | Regex — keep anchored by a literal ≥4 bytes |
| `private` | String used in condition but not reported |

---

## 3. Conditions

| Construct | Example |
|---|---|
| Magic bytes | `uint16(0) == 0x5A4D` (MZ), `uint32(0) == 0x464C457F` (ELF), `uint32(0) == 0xFEEDFACF` (Mach-O 64), `uint32(0) == 0x04034B50` (ZIP/OOXML), `uint32(0) == 0xE011CFD0` (OLE) |
| Size | `filesize < 5MB` |
| Counts | `#s1 > 3` |
| Offsets | `$s1 at 0`, `$s1 in (0..1024)` |
| Sets | `2 of ($a*)`, `any of them`, `all of ($cfg*)` |
| Loops | `for any i in (0..pe.number_of_sections-1): (pe.sections[i].name == ".x0r")` |
| Entropy | `math.entropy(0, filesize) > 7.2` (import "math") |
| Imphash | `pe.imphash() == "..."` |
| Rich header | `pe.rich_signature.clear_data` hashing |
| Signature | `pe.number_of_signatures == 0` |

---

## 4. Performance

- Every string should contain an atom ≥4 bytes that is rare in normal files
- Avoid leading wildcards and `.*` regex; avoid `nocase` on hex-like strings
- Put cheap checks first in conditions (`uint16(0)`, `filesize`) — YARA-X evaluates efficiently but scanning cost is driven by atoms
- YARA-X: `yr check rules/` warns about slow patterns; `yr fmt` normalizes style

---

## 5. YARA → YARA-X Migration Notes

- Stricter parser: invalid escape sequences error (use `\\` for literal backslash), duplicate modifiers error, negative array indexes error
- `base64` strings need ≥3 chars
- `magic` and `cuckoo` modules not carried forward; new `lnk`, `dex`; rewritten `pe`, `elf`, `macho`
- Run `yr check` over the whole ruleset before switching scanners

```bash
yr check rules/
yr scan rules/ /samples -r
yr scan -s rules/my.yar suspicious.bin      # print matching strings
yara -r -s rules/my.yar /samples              # classic YARA
```

---

## 6. Testing

```bash
# TP
yr scan rules/new.yar samples/family_x/ -r | wc -l
# FP — Windows system binaries + your software repo
yr scan rules/new.yar C:/Windows/System32 -r
yr scan rules/new.yar /mnt/goodware -r
```

Zero hits on goodware, ≥90% on family samples, scan time acceptable on 10k files.

---

## 7. Memory & Live Scanning

| Tool | Use |
|---|---|
| Volatility 3 `windows.vadyarascan --yara-file r.yar` | Scan process memory in dumps |
| Velociraptor `Windows.Detection.Yara.Process` / `Generic.Detection.Yara.Glob` | Fleet-wide scanning |
| THOR / Loki | Compromise assessment scanners |
| EDR custom IOC (where supported) | Live process scanning |

---

## 8. YARA-L 2.0 (Google SecOps) — Different Language

YARA-L matches UDM events, not bytes:

```text
rule cb_office_spawns_shell {
  meta:
    author = "claude-blue"
    mitre = "T1204.002"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.file.full_path = /\\(winword|excel|powerpnt)\.exe$/ nocase
    $e.target.process.file.full_path = /\\(powershell|cmd|mshta|wscript)\.exe$/ nocase
  condition:
    $e
}
```

---

## Engagement Cheatsheet

```text
samples ≥3 → diff → anchors (magic + structure + 2-4 unique strings)
→ condition with filesize → yr check → TP scan → goodware scan → perf → ship
```

---

## Key References

- YARA-X docs — https://virustotal.github.io/yara-x/
- YARA docs — https://yara.readthedocs.io
- Florian Roth, "How to Write Simple but Sound YARA Rules"
- Neo23x0/signature-base (rule corpus)
- Related: `defensive-malware-triage`, `defensive-memory-forensics`
