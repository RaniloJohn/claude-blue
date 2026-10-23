---
name: defensive-tool-emulation
description: "Safe adversary emulation tooling for detection validation: Atomic Red Team with Invoke-AtomicRedTeam 2.x (official safety warnings, ShowDetails, CheckPrereqs/GetPrereqs, test numbers, cleanup, execution logging with Attire, remote execution), MITRE Caldera 5.x (replace well-known default credentials by creating local.yml instead of running --insecure, API keys, encryption key, internal-only binding, plugins and Sandcat agents, operations with fact sources), test environment design, rules of engagement, mapping results to detections, cleanup verification, and preventing emulation tools from becoming real attacker footholds. Use when planning or running purple team emulation."
---

# Emulation Tools (Atomic Red Team, Caldera)

Emulation proves detections work — but these are real attack techniques. The official Invoke-AtomicRedTeam guidance is blunt: tests may leave systems in an **undesirable state**; understand every test before running it; confirm **permission**; use a test machine resembling production with EDR checking in. Versions observed 2026-10-23: Invoke-AtomicRedTeam 2.3.0, Caldera 5.3.0.

## Quick Workflow

1. Rules of engagement: scope, hosts, techniques, window, approvals, abort criteria (`defensive-purple-team`)
2. Lab/test hosts mirroring production builds, EDR + logging active
3. Read test details; check prerequisites; run; record timestamp
4. Check detections/telemetry; record result (detected/alerted/blocked/missed)
5. Run cleanup; verify cleanup; reimage if unsure
6. Turn misses into detection work items

---

## 1. Invoke-AtomicRedTeam

```powershell
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1059.001 -ShowDetailsBrief                     # list tests
Invoke-AtomicTest T1059.001 -TestNumbers 1 -ShowDetails             # read commands BEFORE running
Invoke-AtomicTest T1059.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs              # may download tools — review sources
Invoke-AtomicTest T1059.001 -TestNumbers 1 -LoggingModule "Attire-ExecutionLogger" -ExecutionLogPath C:\AR\T1059.001.json
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Session $s              # remote via PSSession (authorized hosts only)
```

Safety specifics:
- `-GetPrereqs` downloads third-party binaries (sometimes real offensive tools) — host internal copies, verify hashes, keep off production
- Credential-dumping tests produce real credential material — use dedicated test accounts
- Some tests disable defenses (Defender, firewall) — re-enable and verify after
- Use `-TimeoutSeconds` to bound execution; avoid tests with destructive impact (T1485, T1490, T1486) outside disposable VMs
- Attire logs give exact execution times for detection correlation

---

## 2. Caldera 5.x

| Practice | Detail |
|---|---|
| Configuration | Starting with `--insecure` uses `conf/default.yml`, which contains **well-known default credentials and keys** — lab only. For any shared deployment create `conf/local.yml` with unique user passwords, `api_key_red`/`api_key_blue`, `crypt_salt`, `encryption_key` |
| Exposure | Bind to internal interface; firewall to purple-team hosts; TLS via reverse proxy or SSL plugin; never internet-exposed |
| Auth | LDAP/SSO plugins where available; separate red/blue accounts |
| UI | v5 Vue UI (`--build` on first run/after updates) |
| Agents | Sandcat/Manx agents beacon to the server — deploy only on test hosts, kill and remove after operations; agent binaries are flagged by EDR (that's expected) |
| Plugins | Enable only needed plugins; review community plugins/abilities |
| Operations | Adversary profiles + fact sources; planners (atomic, batch, buckets); use "manual" approval mode for sensitive abilities |

```bash
python3 server.py --build              # with conf/local.yml present (no --insecure)
```

---

## 3. Test Environment

| Element | Requirement |
|---|---|
| Hosts | Same OS build, GPOs, EDR policy as production (or production pilot hosts with approval) |
| Isolation | Separate VLAN; egress restricted except to EDR/SIEM and approved test infrastructure |
| Snapshots | Revert after destructive tests |
| Telemetry | Sysmon/EDR/SIEM forwarding confirmed before tests |
| Accounts | Test users/admins only |

---

## 4. Results Matrix

| Technique | Test | Telemetry? | Alert? | Blocked? | Time to alert | Action |
|---|---|---|---|---|---|---|
| T1059.001 | #1 | Yes | Yes (medium) | No | 2 min | Raise severity |
| T1003.001 | #1 | Yes | No | No | — | New rule DE-142 |

Feed into ATT&CK coverage scoring (`defensive-threat-informed-defense`).

---

## 5. Preventing Abuse

- Inventory every Caldera server and agent; alert on Sandcat/Atomic artifacts outside approved windows/hosts
- Remove test tools and prereq downloads after exercises (`C:\AtomicRedTeam\ExternalPayloads`)
- Attackers use the same public tests — detections built from them are valuable, but vary procedures (Summiting the Pyramid)

---

## Engagement Cheatsheet

```text
RoE + approvals → prod-like isolated test hosts with EDR → ShowDetails → CheckPrereqs (internal prereq mirror) → run with Attire logging
→ record detect/alert/block/time → Cleanup + verify (or revert snapshot) → Caldera: local.yml (no --insecure defaults), internal binding, remove agents
→ misses → detection backlog → retest
```

---

## Key References

- github.com/redcanaryco/atomic-red-team and invoke-atomicredteam wiki (safety warnings, prereqs, cleanup, execution logging)
- caldera.readthedocs.io (server configuration, plugins); MITRE CTID Adversary Emulation Library
- Related: `defensive-purple-team`, `defensive-adversary-emulation`, `defensive-threat-informed-defense`, `defensive-tool-safety`
