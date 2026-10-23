---
name: defensive-tool-cyberchef
description: "CyberChef (GCHQ) for decoding and analysis: client-side processing model, using the downloadable offline build for sensitive data, URL-embedded input risk when sharing recipe links, recipes for PowerShell -EncodedCommand (Base64 + UTF-16LE), gzip/deflate payloads, XOR brute force, hex/charcode/URL decoding, defanging and extracting IOCs (URLs, IPs, domains, emails), JWT and X.509 parsing, timestamp conversion, regex extraction, entropy and file-type detection, Magic operation, subsections/registers/jumps for multi-stage scripts, Node API for automation, and safe handling of decoded malicious content. Use when decoding obfuscated payloads, extracting indicators, or building reusable decoding recipes."
---

# CyberChef

CyberChef runs operations entirely in the browser (JavaScript) — no server-side processing. That makes it safe for most analysis, but **where you load it from and how you share links** still matter. Version observed: 11.5.0.

## Quick Workflow

1. Use a local/offline copy (download build ZIP or self-host) for sensitive or incident data
2. Paste input; drag operations; check output at each step
3. Save recipes (JSON) in your team repo for reuse
4. Extract and defang IOCs before pasting into tickets/chat
5. Never execute decoded output; treat it as hostile text

---

## 1. Safety

| Risk | Practice |
|---|---|
| Hosted instance availability/integrity | Self-host or offline build; verify release checksum from the official GitHub release |
| Sharing links | CyberChef URLs can embed **input and recipe** (`#recipe=...&input=...` Base64) — strip input before sharing; never paste incident URLs into public channels |
| Rendering operations | Avoid "Render HTML"/"Render Image"/"Render Markdown" on hostile content in an analyst browser; use an isolated VM |
| Clipboard | Decoded payloads may contain malicious commands — don't paste into terminals |
| Large files | Browser memory limits — use Node API or Python for very large inputs |

---

## 2. Core Recipes

| Task | Recipe |
|---|---|
| PowerShell `-enc` | `From Base64` → `Decode text (UTF-16LE (1200))` |
| Compressed + Base64 (`IO.Compression.GzipStream`/`DeflateStream`) | `From Base64` → `Gunzip` (or `Raw Inflate`) → `Decode text` if UTF-16 |
| Char code arrays (`[char]72,101,...`) | `Regular expression` (extract numbers) → `From Charcode (Comma, base 10)` |
| Hex blobs | `From Hex` (Auto delimiter) |
| URL encoding | `URL Decode` |
| XOR single-byte | `XOR Brute Force` (key length 1, look for "MZ", "http", "This program") → `XOR` with key |
| Reverse strings | `Reverse` |
| ROT/Caesar | `ROT13` / `ROT47` brute |
| IOC extraction | `Extract URLs` / `Extract IP addresses` / `Extract domains` / `Extract email addresses` → `Defang URL` / `Defang IP Addresses` |
| JWT | `JWT Decode` (no signature verification without key — `JWT Verify` with secret/public key) |
| Certificates | `Parse X.509 certificate` (PEM/DER) |
| Timestamps | `From UNIX Timestamp`, `Windows Filetime to UNIX Timestamp`, `Translate DateTime Format` |
| File type | `Detect File Type`, `Entropy`, `Strings`, `Extract Files` |
| Unknown encoding | `Magic` (depth 3, intensive mode) — then rebuild a deterministic recipe |
| Multi-stage | `Subsection` (apply ops to regex matches), `Register` (capture keys), `Fork`/`Merge`, `Jump`/`Label` for loops |

Example saved recipe (PowerShell gzip stager):

```json
[
  { "op": "Regular expression", "args": ["User defined", "[A-Za-z0-9+/=]{100,}", true, true, false, false, false, false, "List matches"] },
  { "op": "From Base64", "args": ["A-Za-z0-9+/=", true, false] },
  { "op": "Gunzip", "args": [] },
  { "op": "Decode text", "args": ["UTF-8 (65001)"] }
]
```

---

## 3. Automation (Node API)

```bash
npm install cyberchef
```

```javascript
const chef = require("cyberchef");
const out = chef.bake("SQBFAFgA...", [chef.fromBase64, { op: chef.decodeText, args: ["UTF-16LE (1200)"] }]);
console.log(out.toString());
```

Use in SOAR/enrichment pipelines to decode command lines automatically (`defensive-soar-automation`).

---

## 4. Analysis Tips

- Work iteratively: decode one layer, inspect, then add the next
- Keep the original input; note each layer in the case (layer 1: Base64, layer 2: gzip, …)
- After decoding, look for: URLs/IPs (C2), file paths, AMSI/ETW bypass strings, reflective loading (`[Reflection.Assembly]::Load`), additional encoded blobs
- Hash any extracted binary (`SHA2`) and check reputation by **hash** rather than uploading

---

## Engagement Cheatsheet

```text
offline/self-hosted build → paste input → layer-by-layer (Base64 → Gunzip/Inflate → UTF-16LE) → Magic for unknowns then deterministic recipe
→ extract + defang IOCs → hash extracted files → save recipe JSON → strip input from shared links → Node API in SOAR
```

---

## Key References

- github.com/gchq/CyberChef (releases, wiki); CyberChef Node API docs
- Related: `defensive-malware-triage`, `defensive-phishing-triage`, `defensive-tool-safety`
