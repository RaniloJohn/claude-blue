---
name: defensive-frameworks
description: "Security framework mapping and control alignment for security teams: NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover), CIS Critical Security Controls v8.1 and Implementation Groups, ISO/IEC 27001:2022 and 27002 Annex A (93 controls, 4 themes), NIST SP 800-53 Rev. 5, PCI DSS v4.0.1, SOC 2, NIS2, DORA, EU Cyber Resilience Act, Philippine Data Privacy Act/NPC, and mapping SOC capabilities (logging, detection, IR, vulnerability management) to framework requirements and evidence. Use when aligning security operations to frameworks, preparing audit evidence, or prioritizing controls."
---

# Security Frameworks & Control Mapping

Frameworks describe *what* good looks like; operations prove it with evidence. Map once (control → capability → evidence) and reuse across audits.

## Quick Workflow

1. Identify mandatory frameworks (regulation, contracts) vs voluntary (best practice)
2. Pick a primary control catalog (CIS v8.1 or NIST CSF 2.0) and map others to it
3. Map each control to an owner, capability, and evidence source
4. Gap assessment → prioritized roadmap
5. Continuous evidence collection (automate from SIEM/CSPM/ticketing)

---

## 1. NIST CSF 2.0 (Feb 2024)

| Function | Categories (examples) | SOC relevance |
|---|---|---|
| Govern (GV) — new | Org context, risk strategy, roles, policy, oversight, supply chain risk (GV.SC) | IR policy, authority, metrics reporting |
| Identify (ID) | Asset management, risk assessment, improvement | Asset inventory, vuln mgmt |
| Protect (PR) | Identity/access (PR.AA), awareness, data security, platform security, infrastructure resilience | Hardening, MFA, logging generation (PR.PS) |
| Detect (DE) | Continuous monitoring (DE.CM), adverse event analysis (DE.AE) | SIEM, detection engineering, triage |
| Respond (RS) | Incident management, analysis, reporting/communication, mitigation | IR process |
| Recover (RC) | Recovery plan execution, communication | Restore, lessons learned |

Tiers (Partial → Adaptive) and Profiles (current vs target) structure maturity. NIST SP 800-61r3 maps IR onto CSF 2.0.

---

## 2. CIS Controls v8.1 (June 2024)

| # | Control | IG1 essentials |
|---|---|---|
| 1 | Inventory and Control of Enterprise Assets | Asset inventory |
| 2 | Inventory and Control of Software Assets | Software inventory |
| 3 | Data Protection | Data inventory, encryption |
| 4 | Secure Configuration | Baselines, firewalls, lockouts |
| 5 | Account Management | Inventory, unique passwords, disable dormant |
| 6 | Access Control Management | MFA for external apps/remote/admin |
| 7 | Continuous Vulnerability Management | Process, patching |
| 8 | Audit Log Management | Collect, store, time sync |
| 9 | Email and Web Browser Protections | Supported browsers/clients, DNS filtering |
| 10 | Malware Defenses | AV/EDR, autorun off |
| 11 | Data Recovery | Backups, isolated copy |
| 12 | Network Infrastructure Management | Up-to-date infrastructure |
| 13 | Network Monitoring and Defense | (IG2+) IDS, log alerting |
| 14 | Security Awareness and Skills Training | Training program |
| 15 | Service Provider Management | Inventory of providers |
| 16 | Application Software Security | (IG2+) secure SDLC |
| 17 | Incident Response Management | Designated personnel, reporting process |
| 18 | Penetration Testing | (IG2+) |

IG1 = essential cyber hygiene (56 safeguards); IG2/IG3 add depth. v8.1 added the Govern function alignment and asset-type refinements.

---

## 3. ISO/IEC 27001:2022

- ISMS clauses 4–10 (context, leadership, planning, support, operation, performance evaluation, improvement)
- Annex A: 93 controls in 4 themes — Organizational (37), People (8), Physical (14), Technological (34)
- New in 2022 (examples): A.5.7 Threat intelligence, A.5.23 Cloud services security, A.5.30 ICT readiness for business continuity, A.8.9 Configuration management, A.8.10 Information deletion, A.8.11 Data masking, A.8.12 Data leakage prevention, A.8.16 Monitoring activities, A.8.23 Web filtering, A.8.28 Secure coding
- Transition from 27001:2013 certificates ended 31 Oct 2025

---

## 4. Other Regimes

| Regime | Key operational requirements |
|---|---|
| PCI DSS v4.0.1 | Req. 10 logging (audit logs reviewed; automated mechanisms), 11 testing (vuln scans, pentests, IDS/change detection), 12.10 IR; future-dated requirements effective 31 Mar 2025 (e.g., automated log review, targeted risk analyses, phishing protections, MFA for all CDE access) |
| SOC 2 (AICPA TSC) | Security (CC series): monitoring (CC7), incident response (CC7.3–7.5), change mgmt (CC8) |
| NIS2 (EU) | Risk management measures; incident reporting 24 h early warning / 72 h notification / 1-month final; management accountability |
| DORA (EU financial, applies since 17 Jan 2025) | ICT risk management, major ICT incident reporting, resilience testing (TLPT), third-party risk |
| EU CRA | Manufacturer vuln/incident reporting since 11 Sep 2026; full obligations Dec 2027 |
| PH Data Privacy Act (RA 10173) + NPC circulars | Security measures, breach notification to NPC and data subjects within 72 h of knowledge |
| HIPAA Security Rule (US) | Audit controls, integrity, transmission security, contingency planning |
| NIST SP 800-53 Rev. 5 | Comprehensive control catalog (AU, IR, SI, CA, RA families for SOC) |

---

## 5. SOC Capability → Control Map (excerpt)

| Capability | CSF 2.0 | CIS v8.1 | ISO 27001:2022 | PCI DSS 4.0.1 | Evidence |
|---|---|---|---|---|---|
| Centralized logging & retention | PR.PS-04, DE.CM | 8 | A.8.15, A.8.17 | 10.2–10.7 | Log source inventory, retention config, health dashboards |
| Detection & alerting | DE.CM, DE.AE | 13 | A.8.16 | 10.4.1.1, 11.5 | Rule repo, alert metrics |
| Incident response | RS.*, RC.* | 17 | A.5.24–A.5.28 | 12.10 | Playbooks, incident records, exercise reports |
| Vulnerability management | ID.RA | 7 | A.8.8 | 6.3, 11.3 | Scan reports, SLA metrics |
| Threat intelligence | ID.RA-02/03 | — | A.5.7 | — | Intel products, feed inventory |
| Asset inventory | ID.AM | 1, 2 | A.5.9 | 12.5.1 | CMDB exports |
| MFA / access control | PR.AA | 5, 6 | A.5.15–A.5.18, A.8.5 | 7, 8 | IdP config, CA policies |

(Verify specific subcategory/requirement numbers against the official documents when producing audit artifacts.)

---

## 6. Evidence Automation

- Export SIEM coverage and health dashboards monthly
- CSPM compliance reports (Prowler/Security Hub/Defender) per framework
- Ticketing: incidents, change records, vuln SLA reports
- Store evidence with date, owner, control ID in a GRC tool or structured repo

---

## Engagement Cheatsheet

```text
mandatory vs voluntary → primary catalog (CIS v8.1 / CSF 2.0) → crosswalk others → control→owner→capability→evidence
→ gap roadmap → automated evidence → periodic review
```

---

## Key References

- NIST CSF 2.0; NIST SP 800-53r5; NIST SP 800-61r3
- CIS Controls v8.1 (and CIS mappings to CSF 2.0, ISO, PCI)
- ISO/IEC 27001:2022 & 27002:2022
- PCI DSS v4.0.1; NIS2 Directive; DORA; EU CRA; Philippine RA 10173
- Related: `defensive-risk-threat-modeling`, `defensive-soc-playbooks`, `defensive-log-sources`
