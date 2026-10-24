---
name: defensive-bcp-dr
description: "Business continuity and disaster recovery planning with a cyber focus: business impact analysis (BIA), maximum tolerable downtime, RTO and RPO per service, dependency mapping, DR strategies (backup-restore, pilot light, warm standby, multi-site active-active, cold/warm/hot sites), cloud DR patterns, ransomware-ready recovery (clean rooms, immutable backups, identity-first recovery order), crisis management and communications, manual workarounds, ISO 22301 and NIST SP 800-34 alignment, testing types (walkthrough, tabletop, simulation, parallel, full interruption), and plan maintenance. Use when building or reviewing BCP/DR plans or recovery strategies."
---

# Business Continuity & Disaster Recovery

BCP keeps the business operating; DR restores technology. For cyber scenarios, assume **attackers may have destroyed or poisoned backups and identity** — plan recovery accordingly.

## Quick Workflow

1. BIA: critical processes, impact over time, MTD, RTO, RPO
2. Map dependencies (apps, data, identity, network, vendors, people)
3. Select recovery strategies per tier; budget
4. Write plans: crisis management, BCP per department, IT DR runbooks
5. Test, measure actual RTO/RPO, fix gaps, maintain

---

## 1. Business Impact Analysis

| Field | Example |
|---|---|
| Process | Customer payments |
| Owner | Head of Finance Ops |
| Impact over time | 4 h: revenue loss; 24 h: regulatory breach; 72 h: severe reputational |
| MTD | 24 h |
| RTO | 8 h |
| RPO | 15 min |
| Dependencies | Payment app, PostgreSQL, Entra ID, DNS, payment gateway API, 3 trained staff |
| Manual workaround | Batch processing via bank portal for 48 h |

RTO ≤ MTD; RPO drives backup/replication frequency.

---

## 2. Recovery Tiers & Strategies

| Tier | RTO/RPO | Strategy |
|---|---|---|
| 0 (identity, DNS, network core) | Hours / minutes | Redundant across sites/regions; documented forest recovery (`defensive-ad-forest-recovery`) |
| 1 (crown-jewel apps) | ≤ 4–8 h / ≤ 15 min | Warm standby or active-active; replication + immutable backups |
| 2 (important) | ≤ 24–72 h / ≤ 24 h | Pilot light / backup-restore to cloud |
| 3 (other) | Days–weeks / 24 h+ | Backup-restore |

Cloud patterns: backup & restore → pilot light → warm standby → multi-site active/active (increasing cost, decreasing RTO).

---

## 3. Cyber-Specific Recovery

- Replication copies corruption/encryption too — keep **immutable, point-in-time** backups (`defensive-bcp-dr`)
- Recovery order: isolated clean environment → identity → network services → security tooling (EDR/SIEM) → crown jewels → rest
- Scan restored systems; patch the entry vector before reconnecting
- Have clean build media, offline credentials, and out-of-band comms
- Decide in advance who can authorize restoring vs rebuilding

---

## 4. Plans

| Plan | Content |
|---|---|
| Crisis management | Activation criteria, crisis team, decision rights, stakeholder comms |
| BCP (per business unit) | Workarounds, minimum staffing, alternate locations, vendor contacts |
| IT DR runbooks | Step-by-step restore per system with owners, credentials location, validation |
| Communications | Templates for staff, customers, regulators, media |
| Vendor continuity | Critical suppliers' BCP evidence, alternates |

---

## 5. Testing

| Type | Description | Frequency |
|---|---|---|
| Walkthrough | Read plan with owners | Semi-annual |
| Tabletop | Scenario discussion (`defensive-ir-readiness`) | Annual+ |
| Simulation | Simulated events, partial technical | Annual |
| Parallel | Recover systems at DR site without stopping production | Annual for Tier 1 |
| Full interruption | Fail over production | Only with high maturity and approval |

Record actual recovery times vs RTO; open action items with owners.

---

## Engagement Cheatsheet

```text
BIA (MTD/RTO/RPO, owners, impact curve) → dependency map (incl. identity, DNS, vendors, people) → tiered strategies (active/warm/pilot light/backup)
→ cyber recovery (immutable PIT backups, clean room, identity-first order) → crisis/BCP/DR/comms plans → test (walkthrough → parallel) → measure + maintain
```

---

## Key References

- ISO 22301:2019; NIST SP 800-34 Rev 1 (Contingency Planning); AWS/Azure/GCP DR whitepapers
- Related: `defensive-cyber-resilience`, `defensive-ad-forest-recovery`, `defensive-ir-readiness`, `defensive-ransomware-response`
