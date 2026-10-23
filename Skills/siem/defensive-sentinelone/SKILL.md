---
name: defensive-sentinelone
description: "SentinelOne Singularity operations for defenders: agent deployment and health, policy modes (detect vs protect), engines (static AI, behavioral AI, exploit, lateral movement, documents/scripts), anti-tamper, Singularity Data Lake hunting with S1QL and PowerQuery, Storyline (TrueContext) investigation, STAR custom detection rules, threat mitigation actions (kill, quarantine, remediate, rollback via VSS), network quarantine, RemoteOps scripts, Deep Visibility legacy, Ranger network discovery, exclusions governance, Identity (ITDR), and API automation. Use when hunting, triaging, or responding with SentinelOne."
---

# SentinelOne Singularity

SentinelOne groups related activity into **Storylines**, giving each process tree a shared ID. Defender workflow: **triage threats with Storyline**, **hunt in the Data Lake**, **mitigate (kill/quarantine/remediate/rollback)**, and **codify detections as STAR rules**.

## Quick Workflow

1. Confirm agent coverage, version, and policy mode (Protect for production after tuning)
2. Triage a threat: Storyline, indicators, MITRE mapping, file reputation
3. Hunt related activity across fleet (PowerQuery/S1QL)
4. Mitigate: network quarantine → kill/quarantine → remediate → rollback if encryption
5. Create STAR rules from hunts; review exclusions

---

## 1. Policy

| Setting | Recommendation |
|---|---|
| Threats / suspicious mode | Protect / Protect (after pilot in Detect) |
| Engines | Static AI, behavioral AI, documents & scripts, lateral movement, exploits, potentially unwanted apps — all on |
| Anti-tamper | On; passphrase per site/group stored in vault |
| Agent upgrades | Ringed (pilot → GA) |
| Snapshots (VSS) | Enabled for rollback (Windows) |
| Deep visibility / data collection | Full process, file, network, registry, scheduled tasks, cross-process |
| Device control / firewall control | Enable where licensed |

---

## 2. Hunting — PowerQuery / S1QL

```text
event.type = 'Process Creation' and src.process.name in ('winword.exe','excel.exe','outlook.exe')
  and tgt.process.name in ('powershell.exe','cmd.exe','wscript.exe','mshta.exe','rundll32.exe')
| columns endpoint.name, src.process.user, src.process.name, tgt.process.cmdline
```

```text
tgt.process.name = 'powershell.exe' and tgt.process.cmdline contains:anycase ('-enc', 'frombase64string', 'downloadstring')
| group count = count() by endpoint.name, tgt.process.cmdline
| sort -count
```

```text
event.type = 'DNS Resolved' and event.dns.request contains:anycase ('ngrok', 'trycloudflare')
| group count() by endpoint.name, event.dns.request
```

```text
event.type = 'IP Connect' and dst.port.number in (445, 3389, 5985) and src.process.name != 'svchost.exe'
| group targets = estimate_distinct(dst.ip.address) by endpoint.name, src.process.name
| filter targets > 20
```

Common fields: `endpoint.name`, `event.type`, `src.process.*` (actor), `tgt.process.*` / `tgt.file.*` (target), `src.process.storyline.id`, `dst.ip.address`, `event.dns.request`, `registry.keyPath`, `indicator.name`. (Legacy Deep Visibility S1QL v1 syntax differs — e.g., `TgtProcName`, `SrcProcCmdLine`; translate when migrating saved queries.)

Pivot: filter `src.process.storyline.id = '<id>'` to see everything in a Storyline.

---

## 3. STAR Custom Rules

Convert a hunt query to a STAR (Storyline Active Response) rule: severity, MITRE mapping, response (alert only / mitigate: kill, quarantine, network quarantine), cool-off period, scope (account/site/group). Pilot in alert-only mode, review hits for a week, then enable automated mitigation for high-confidence rules.

---

## 4. Mitigation Actions

| Action | Effect |
|---|---|
| Kill | Terminate Storyline processes |
| Quarantine | Encrypt and move malicious files |
| Remediate | Reverse changes (files, registry, scheduled tasks) made by the Storyline |
| Rollback | Restore files from VSS snapshots (ransomware) — Windows |
| Network quarantine | Disconnect from network except management console |
| Mark as threat / blocklist hash | Fleet-wide prevention |

RemoteOps / Remote Script Orchestration: run collection or remediation scripts at scale (e.g., deploy KAPE/Velociraptor collector, collect logs). Remote Shell for interactive response — restrict to IR roles, MFA, audited.

---

## 5. Ranger & Identity

- **Ranger**: agent-based network discovery of unmanaged devices (find hosts without EDR)
- **Singularity Identity**: AD/Entra attack detection (Kerberoasting, DCSync, credential misuse) and deception (decoy credentials/shares)

---

## 6. Exclusions Governance

Path, hash, certificate, browser, and interoperability exclusions — narrowest scope, ticket, owner, expiry; never exclude user-writable directories broadly; prefer "suppress alerts" (still visible) over "interoperability" exclusions that drop telemetry.

---

## 7. API

```bash
curl -s -H "Authorization: ApiToken $S1_TOKEN" "https://$S1_HOST/web/api/v2.1/agents?computerName__contains=ws-042" | jq '.data[] | {id, computerName, isActive, networkStatus}'
curl -s -X POST -H "Authorization: ApiToken $S1_TOKEN" -H "Content-Type: application/json" \
  "https://$S1_HOST/web/api/v2.1/agents/actions/disconnect" -d '{"filter":{"ids":["<agentId>"]}}'
```

---

## Engagement Cheatsheet

```text
coverage + Protect mode + anti-tamper + VSS → threat triage via Storyline → PowerQuery hunts (event.type, src/tgt.process, storyline.id)
→ STAR rules alert-only → automated mitigation → network quarantine → kill/quarantine/remediate/rollback → Ranger for unmanaged → exclusion hygiene → API automation
```

---

## Key References

- SentinelOne Singularity docs (PowerQuery reference, STAR rules, API v2.1)
- Related: `defensive-edr-tuning`, `defensive-ransomware-response`, `defensive-threat-hunting`, `defensive-live-response`
