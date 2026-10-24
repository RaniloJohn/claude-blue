---
name: defensive-ir-readiness
description: "Incident response readiness and preparation: IR plan and policy aligned to NIST SP 800-61 Rev 3 and CSF 2.0, roles and on-call, decision authority and pre-approved containment actions, contact trees (legal, PR, insurers, regulators, law enforcement, CERTs), IR retainers and cyber insurance requirements, out-of-band communications, jump bags and forensic tooling, log retention and telemetry readiness checks, playbooks per scenario, evidence handling procedures, asset and identity inventories, backups and restore testing, exercises and readiness metrics, and a readiness assessment checklist. Use when preparing an organization to respond to incidents or assessing IR maturity."
---

# Incident Response Readiness

Most incident response failures happen before the incident: no logs, no authority, no contacts, no backups, no practice. Readiness turns a crisis into a procedure.

## Quick Workflow

1. Plan: IR policy + plan with roles, severity model, authority, communications
2. Equip: telemetry, retention, tooling, access (break-glass), jump bag
3. Contract: IR retainer, insurance, legal counsel, forensic partners
4. Practice: tabletops and technical drills (`defensive-ir-readiness`)
5. Measure readiness; fix gaps; repeat yearly

---

## 1. Plan Contents (NIST SP 800-61r3 / CSF 2.0 aligned)

| Section | Content |
|---|---|
| Scope & definitions | Event vs incident, severity levels (see router W5) |
| Roles | Incident commander, technical lead, scribe, comms lead, legal, executive sponsor, HR, IT ops liaisons |
| Authority | Pre-approved actions (isolate endpoint, disable account, block IOC, take system offline up to defined criticality) and escalation for others |
| Communications | Internal channels, out-of-band (assume email/Teams compromised), status cadence, external comms approval |
| Legal & regulatory | Privilege (engage counsel early), notification obligations and timelines (`defensive-incident-response`, regional laws), evidence retention |
| Third parties | MSSP/MDR, IR retainer firm, insurer (notification clauses, approved vendors), cloud providers, law enforcement, national CERT |
| Playbooks | Ransomware, BEC, cloud account compromise, insider, DDoS, web compromise, data breach, edge-device exploit |
| Evidence handling | Collection order, tools, chain of custody, storage |
| Recovery & lessons learned | Recovery criteria, post-incident review within 2 weeks |

---

## 2. Technical Readiness Checklist

| Area | Ready when |
|---|---|
| Logging | Critical sources centralized; retention ≥ 90 days hot, ≥ 1 year searchable (adjust to regulation); time synchronized |
| EDR | ≥ 98% coverage; isolation tested; live response access for IR team |
| Identity | Ability to revoke sessions/tokens tenant-wide; break-glass accounts tested; MFA reset procedure secure |
| Network | Ability to block egress quickly; NetFlow/DNS logs retained |
| Forensics | Velociraptor/KAPE ready; memory acquisition tooling; storage for evidence; cloud forensic account |
| Backups | Immutable/offline; restore of crown jewels tested in last 12 months |
| Asset & identity inventory | Up to date, with owners and criticality |
| Cloud | Audit logs enabled in all accounts/subscriptions/projects; incident response roles pre-created |
| Comms | Out-of-band channel (Signal/Wire/separate tenant), printed contact list |

---

## 3. Jump Bag (physical + digital)

Write blockers, encrypted external drives, USB with trusted tools (KAPE, Velociraptor offline collector, Sysinternals, AVML, WinPmem), network tap/switch with SPAN, labels and evidence bags, chain-of-custody forms, laptops with forensic tools, printed runbooks and contact lists, spare credentials in sealed envelopes per policy.

---

## 4. Contracts & Contacts

| Party | Pre-arrange |
|---|---|
| IR retainer | Hours, response SLA, scope (forensics, negotiation support, recovery) |
| Cyber insurance | Notification window, panel vendors, coverage of ransom/extortion considerations |
| Legal counsel | Breach coach; privilege protocols |
| Regulators | Contact methods and forms (e.g., data protection authority; sector regulators) |
| Law enforcement / CERT | National CERT and cybercrime units (e.g., CERT-PH, PNP-ACG, NBI-CCD in the Philippines; CISA/FBI in the US) |
| Key vendors | Identity provider, cloud, EDR, MSP support escalation paths |

---

## 5. Readiness Metrics

Time to assemble IR team (exercise), % playbooks exercised in last 12 months, log source coverage and retention compliance, backup restore success, mean time to isolate in drills, open lessons-learned actions.

---

## Engagement Cheatsheet

```text
plan (roles, severity, authority, comms, legal, third parties, playbooks, evidence, recovery) → technical readiness (logs, EDR, identity revoke, egress block, forensics, backups, inventory, cloud audit, OOB comms)
→ jump bag → retainer/insurance/counsel/regulators/CERT contacts → exercises → metrics → annual refresh
```

---

## Key References

- NIST SP 800-61 Rev 3 (2025) aligned to CSF 2.0; CISA Incident Response Playbooks; SANS Incident Handler's Handbook
- Related: `defensive-incident-response`, `defensive-soc-playbooks`, `defensive-cyber-resilience`
