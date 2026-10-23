---
name: defensive-soc-building
description: "Building or maturing a Security Operations Center: mission and service catalog, scope and authority, phased build (foundation, monitoring, response, proactive), log source onboarding priority, use case development lifecycle (MaGMa framework), tooling stack (SIEM, EDR, SOAR, TIP, case management, NDR), tiering and shift models, runbooks and playbooks, SLAs by severity, shift handover, knowledge base, onboarding and training paths, SOC-CMM assessment, MSSP/MDR integration, and a 90-day/12-month build plan. Use when standing up a SOC, restructuring one, or writing a SOC charter or roadmap."
---

# Building a SOC

A SOC is a **service** with a defined customer, scope, authority, and service levels — not a room full of screens. Build it in phases, onboarding the log sources and use cases that matter most first.

## Quick Workflow

1. Charter: mission, scope, services, authority, stakeholders
2. Foundation: tooling, log sources, asset/identity context
3. Monitoring: prioritized use cases, triage runbooks, case management
4. Response: playbooks, containment authority, IR integration
5. Proactive: hunting, detection engineering, CTI, purple teaming
6. Measure and mature (SOC-CMM, metrics)

---

## 1. Charter Essentials

| Element | Content |
|---|---|
| Mission | "Detect and respond to threats to <org>'s systems and data 24×7" |
| Scope | Business units, environments (on-prem, cloud, OT), what's excluded |
| Services | Monitoring, triage, IR, hunting, detection engineering, vuln intel, forensics, awareness support |
| Authority | Pre-approved actions (isolate endpoint, disable account, block IOC) and escalation for critical systems |
| Stakeholders | CISO, IT ops, cloud, legal, HR, comms, business owners |
| Hours | 24×7, 8×5 + on-call, follow-the-sun |
| Interfaces | IT service desk, NOC, MSSP/MDR, CERT, law enforcement |

---

## 2. Log Source Onboarding Priority

| Priority | Sources |
|---|---|
| P1 | EDR, identity provider (Entra/Okta), AD domain controllers, email security, firewall/VPN/edge, cloud control plane (CloudTrail/Activity/Audit) |
| P2 | DNS, proxy/SWG, M365/Workspace audit, critical servers (Sysmon/auditd), PAM, MDM |
| P3 | NDR/Zeek, WAF, databases, SaaS apps, DHCP, vuln scanner results |
| P4 | Application logs, OT, physical access |

For each source: owner, parser, expected EPS, retention, health monitoring (silence alerts). See `defensive-log-sources`, `defensive-log-parsing`.

---

## 3. Use Case Lifecycle (MaGMa-style)

```text
Business driver / threat → use case (objective) → data requirements → detection logic → triage runbook → response playbook
→ testing (emulation) → production → metrics (TP/FP, volume) → review/retire
```

Use case record: ID, name, ATT&CK techniques, data sources, rule IDs, severity, runbook link, owner, last tested, FP rate.

Start with ~25–50 high-value use cases (identity compromise, ransomware precursors, EDR high alerts, phishing, privileged changes, cloud control-plane abuse) rather than enabling hundreds of vendor rules.

---

## 4. Tooling Stack

| Function | Options |
|---|---|
| SIEM / data lake | Sentinel, Splunk, Elastic, Google SecOps, QRadar, Wazuh, Graylog |
| EDR/XDR | Defender, CrowdStrike, SentinelOne, Elastic Defend |
| SOAR | Sentinel Logic Apps/playbooks, Splunk SOAR, Tines, Torq, Shuffle, XSOAR |
| Case management | SOAR built-in, TheHive, ServiceNow SecOps, Jira |
| TIP | MISP, OpenCTI, commercial |
| NDR | Zeek/Corelight, Security Onion, commercial |
| Forensics | Velociraptor, KAPE, EZ Tools, Volatility |
| Knowledge base | Wiki with runbooks, asset context, contacts |

---

## 5. Tiers & Shifts

| Role | Responsibilities |
|---|---|
| L1 analyst | Triage queue, enrich, close FPs, escalate, initial containment per runbook |
| L2 analyst / incident handler | Deep investigation, scoping, containment, coordination |
| L3 / detection engineer / hunter | Detection content, hunting, tooling, malware analysis |
| SOC lead / manager | Quality, metrics, staffing, stakeholder management |

Shift handover template: open SEV1/SEV2 cases + status, pending actions/owners, notable alerts/trends, tool/log health issues, changes deployed, threat intel updates.

---

## 6. SLAs (example)

| Severity | Triage start | Escalation | Containment target |
|---|---|---|---|
| SEV1 (active compromise, critical asset) | 15 min | Immediate page | 1 h |
| SEV2 (confirmed malicious, contained scope) | 30 min | 1 h | 4 h |
| SEV3 (suspicious, needs investigation) | 4 h | Next business day | 24–72 h |
| SEV4 (informational) | 24 h | — | — |

---

## 7. Training Path

Weeks 1–2: environment, tools, runbooks, shadowing. Weeks 3–6: supervised triage, case write-ups reviewed. Ongoing: monthly labs (`defensive-soc-building`, `defensive-soc-building`), certifications (Security+, CySA+, BTL1, GCIH, GCIA), rotation into DE/IR/CTI.

---

## 8. Build Plan

| Horizon | Deliverables |
|---|---|
| 0–90 days | Charter signed; SIEM + EDR deployed; P1 sources onboarded; 25 use cases with runbooks; case management; on-call; IR retainer |
| 3–6 months | P2 sources; SOAR enrichment + phishing automation; metrics dashboard; tabletop |
| 6–12 months | P3 sources; detection-as-code pipeline; hunting program; purple team cycle; SOC-CMM baseline + targets |
| 12+ months | Threat-informed coverage targets, UEBA/RBA, continuous validation, advanced DFIR |

---

## Engagement Cheatsheet

```text
charter (mission, scope, services, authority) → P1 log sources + health → 25–50 prioritized use cases w/ runbooks
→ tiers/shifts/handover → SLAs → SOAR + case mgmt → training path → 90d/6m/12m plan → SOC-CMM + metrics
```

---

## Key References

- MITRE "11 Strategies of a World-Class Cybersecurity Operations Center" (2022); SOC-CMM; MaGMa Use Case Framework (FI-ISAC NL)
- Related: `defensive-security-operating-model`, `defensive-security-metrics`, `defensive-soc-playbooks`, `defensive-log-sources`, `defensive-detection-as-code`
