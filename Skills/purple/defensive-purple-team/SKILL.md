---
name: defensive-purple-team
description: "Purple teaming and detection validation: planning exercises around ATT&CK techniques, running safe emulations with Atomic Red Team (Invoke-AtomicRedTeam), MITRE Caldera, and vendor BAS tools, measuring prevention/detection/alert/response outcomes per test, telemetry gap analysis, iterating detections live with red and blue together, scoring coverage, lab design for safe testing, and reporting improvements. Use when validating whether detections fire, running purple team sessions, or pairing claude-red techniques with claude-blue detections."
---

# Purple Team & Detection Validation

Untested detections are assumptions. Purple teaming runs a technique, checks every layer (telemetry → detection → alert → response), fixes gaps on the spot, and re-tests.

## Quick Workflow

1. Select techniques (threat-informed, coverage gaps)
2. Prepare: lab or approved production scope, rollback, comms
3. Execute one procedure at a time; record exact time
4. Observe: telemetry? detection? alert? response?
5. Fix gaps (logging, rule, tuning) and re-run
6. Score and report

---

## 1. Outcome Scale per Test

| Outcome | Meaning |
|---|---|
| Blocked | Prevented by control |
| Alerted | Detection fired and reached the SOC queue |
| Logged | Telemetry exists, no detection |
| None | No telemetry |

Track for each: time to alert, analyst triage correctness, response action.

---

## 2. Atomic Red Team

```powershell
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1003.001 -ShowDetailsBrief            # list tests
Invoke-AtomicTest T1003.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1               # execute
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

Linux/macOS via PowerShell Core or bash execution of atomics. Run from a test account on test hosts; some atomics are destructive or noisy — read each YAML first.

---

## 3. Caldera

- Adversary profiles (chains of abilities) mapped to ATT&CK
- Agents (Sandcat) on test hosts; operations with planners
- Use for multi-step emulation (discovery → credential access → lateral)
- Restrict Caldera server access; it is a C2

---

## 4. Session Template

```markdown
## Purple Session — <date> — Scope: <hosts/OUs> — Approved by: <name>
| # | ATT&CK | Procedure | Exec time (UTC) | Telemetry | Detection | Alert | Response | Gap | Fix | Retest |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | T1003.001 | comsvcs MiniDump of LSASS | 02:14:07Z | Sysmon 10, 1 | ✓ rule CB-LSASS | ✓ 40 s | Isolated | — | — | — |
| 2 | T1558.003 | Rubeus kerberoast (RC4) | 02:22:30Z | 4769 | ✗ | ✗ | — | No rule | Added Sigma | ✓ |
```

---

## 5. Common Gap Categories

| Gap | Fix |
|---|---|
| Telemetry missing (audit policy, Sysmon event not configured) | Collection change |
| Telemetry collected but not parsed/normalized | Parser/field mapping |
| Detection logic too narrow (tool name, exact cmdline) | Behavioral rewrite |
| Detection fired, alert suppressed/threshold | Tuning |
| Alert fired, analyst misjudged | Triage guide/training |
| Response slow/blocked | Playbook/authority update |

---

## 6. Safety

```text
[ ] Written approval and scope; change ticket
[ ] Prefer lab replicas; production only for benign/low-impact procedures
[ ] Notify SOC lead (unless testing detection blind, with management approval)
[ ] Cleanup steps executed and verified
[ ] No real credentials or data exfiltrated; test data only
[ ] Stop conditions defined (service impact, unexpected behavior)
```

---

## 7. Pairing with claude-red

Load an offensive skill for procedure detail and its defensive counterpart for detection:

| Red | Blue |
|---|---|
| `offensive-active-directory` | `defensive-ad-detection`, `defensive-ad-hardening` |
| `offensive-lateral-movement` | `defensive-hunt-windows`, `defensive-windows-event-logs` |
| `offensive-edr-evasion` | `defensive-edr-tuning`, `defensive-sysmon` |
| `offensive-cloud` | `defensive-aws-security`, `defensive-cloud-ir` |
| `offensive-phishing` | `defensive-phishing-triage`, `defensive-email-auth` |

Run red procedures only in authorized environments.

---

## Engagement Cheatsheet

```text
pick techniques → approvals + lab → execute one procedure (log time) → telemetry/detect/alert/respond
→ fix gap → retest → outcome table → coverage layer update → report
```

---

## Key References

- Atomic Red Team & Invoke-AtomicRedTeam (Red Canary); MITRE Caldera
- SCYTHE / CTID purple team exercise frameworks; CTID Adversary Emulation Library
- Related: `defensive-adversary-emulation`, `defensive-attack-mapping`, `defensive-detection-as-code`
