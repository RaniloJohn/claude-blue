---
name: defensive-tool-sysinternals
description: "Microsoft Sysinternals Suite for defenders: safe acquisition and signature verification, EULA acceptance flags, Autoruns/autorunsc persistence sweeps with signature and VirusTotal checks, Process Explorer and its VirusTotal integration privacy settings, Process Monitor filters and boot logging, Sigcheck for unsigned/untrusted binaries, TCPView, AccessChk for permission audits, Handle, ListDLLs, Strings, PsExec/ProcDump abuse awareness and restrictions, Sysmon pointer, and using Sysinternals during live response without contaminating evidence. Use when triaging Windows hosts or auditing configuration with Sysinternals tools."
---

# Sysinternals Suite

Sysinternals tools are Microsoft-signed, free, and invaluable for live triage — and equally popular with attackers (PsExec, ProcDump). Use them deliberately, document their use, and restrict the dual-use ones.

## Quick Workflow

1. Acquire from Microsoft (download.sysinternals.com, live.sysinternals.com, winget/Microsoft Store); verify Microsoft signature
2. Run from external/IR media with `-accepteula` (avoids prompts; note it writes an EULA registry value)
3. Capture outputs to files with timestamps; hash them
4. Prefer collection tools (Autoruns, Sigcheck, Handle) over interactive changes during IR
5. Restrict PsExec/ProcDump by app control on non-admin hosts; alert on their use

---

## 1. Verify

```powershell
Get-AuthenticodeSignature .\autorunsc64.exe | Select Status, @{n='Signer';e={$_.SignerCertificate.Subject}}
.\sigcheck64.exe -accepteula -i .\autorunsc64.exe
```

`-accepteula` sets `HKCU\Software\Sysinternals\<Tool>\EulaAccepted` — an artifact defenders and attackers both leave; useful in investigations (attacker tool use evidence).

---

## 2. Key Tools

| Tool | Defensive use | Command |
|---|---|---|
| Autoruns / autorunsc | Persistence sweep (all ASEPs), hashes, signatures | `autorunsc64 -accepteula -a * -c -h -s -m -nobanner > autoruns.csv` (`-m` hides Microsoft entries, `-s` verifies signatures, `-h` hashes) |
| Sigcheck | Unsigned/untrusted executables, file versions | `sigcheck64 -accepteula -u -e -s -c C:\Users > unsigned.csv` |
| Process Explorer | Interactive process tree, signatures, image paths, DLLs, handles | GUI; Options → Verify Image Signatures |
| Process Monitor | File/registry/process/network activity tracing | Filters first (Process Name, Path); boot logging for early persistence; save PML |
| TCPView / tcpvcon | Connections with owning process | `tcpvcon64 -accepteula -a -c > conns.csv` |
| Handle | Open handles (which process locks a file) | `handle64 -accepteula -a -p <pid>` |
| ListDLLs | Loaded DLLs, unsigned modules | `listdlls64 -accepteula -u` |
| AccessChk | Permission audits (writable services, dirs, registry) | `accesschk64 -accepteula -uwcqv "Authenticated Users" *` (writable services); `accesschk64 -uwdqs Users C:\Program Files` |
| Strings | Extract strings from binaries/dumps | `strings64 -accepteula -n 8 sample.bin` |
| LogonSessions | Active logon sessions | `logonsessions64 -accepteula -p` |
| Sysmon | Telemetry (`defensive-sysmon`; native Sysmon in Windows 11/Server 2025 — can't coexist with standalone) | — |

---

## 3. VirusTotal Integration Privacy

Autoruns `-v`/`-vt`, Sigcheck `-v`/`-vt`, and Process Explorer "Check VirusTotal" send **file hashes**; some options can **submit unknown files** (`-vr`/`-vs` style submission options, Process Explorer "Submit Unknown Executables"). Submitting confidential binaries shares them with VirusTotal subscribers — use hash-only lookups unless policy allows submission. Accepting VT terms (`-vt`) is required for automated checks.

---

## 4. Dual-Use Tools

| Tool | Abuse | Control |
|---|---|---|
| PsExec | Lateral movement (service `PSEXESVC`, ADMIN$) | App control allow only on admin hosts; alert on `PSEXESVC` service creation and `-accepteula` registry artifact on unexpected hosts |
| ProcDump | LSASS dumping (`procdump -ma lsass.exe`) | ASR "Block credential stealing from LSASS", LSA PPL/Credential Guard, alert on ProcDump targeting lsass |
| PsLoggedOn / PsInfo | Discovery | Alert from non-admin hosts |
| SDelete | Anti-forensics | Alert on execution |

---

## 5. Live Response Etiquette

- Run from read-only/external media; write outputs to external media or network share
- Don't kill/modify processes before capturing memory and state (`defensive-live-response`)
- Procmon captures are large — filter narrowly, capture briefly
- Record every tool, version, command, time (UTC) in the case log

---

## Engagement Cheatsheet

```text
download from Microsoft + verify signature → run from IR media with -accepteula (artifact noted) → autorunsc -a * -c -h -s -m
→ sigcheck -u -e -s → tcpvcon/handle/listdlls → accesschk permission audits → hash-only VT lookups (no submissions unless approved)
→ restrict + alert PsExec/ProcDump/SDelete → document every command
```

---

## Key References

- learn.microsoft.com/sysinternals (tool pages, EULA); Microsoft native Sysmon documentation
- Related: `defensive-live-response`, `defensive-detect-persistence`, `defensive-hunt-windows`, `defensive-tool-safety`
