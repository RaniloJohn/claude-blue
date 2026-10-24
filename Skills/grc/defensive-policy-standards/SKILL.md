---
name: defensive-policy-standards
description: "Writing and governing information security policies, standards, procedures, guidelines, and baselines: document hierarchy, core policy set (information security, acceptable use, access control, password/authentication, data classification and handling, encryption, logging and monitoring, incident response, vulnerability and patch management, change management, backup, remote work, third-party, secure development, AI usage), writing style (shall/should, measurable requirements), mapping to ISO 27001:2022 Annex A, NIST CSF 2.0, CIS Controls v8.1, exception and risk acceptance process, review cycles, attestation, and enforcement through technical controls. Use when drafting, reviewing, or rationalizing security policies and standards."
---

# Security Policies & Standards

Policies state **intent and accountability**; standards make it **measurable**; procedures make it **repeatable**; technical controls make it **real**. A policy nobody can verify is decoration.

## Quick Workflow

1. Inventory existing documents; map to a framework
2. Define hierarchy and owners
3. Draft concise policies + specific standards
4. Approve (executive/board), publish, train, attest
5. Enforce via technical controls; measure compliance; manage exceptions; review annually

---

## 1. Hierarchy

| Level | Purpose | Example |
|---|---|---|
| Policy | High-level mandate, approved by leadership | "All access to company systems shall be authenticated with MFA." |
| Standard | Specific, mandatory, measurable | "Privileged accounts use phishing-resistant MFA (FIDO2/CBA); sessions ≤ 12 h." |
| Baseline | Configuration minimums | CIS Level 1 for Windows 11 with listed deviations |
| Procedure | Step-by-step | "How to onboard a new admin with PIM" |
| Guideline | Recommended, not mandatory | "Prefer passkeys for personal accounts" |

---

## 2. Core Document Set

| Document | Key requirements |
|---|---|
| Information Security Policy | Scope, roles (CISO, owners), risk approach, compliance, review |
| Acceptable Use | Permitted use, monitoring notice, personal devices, prohibited activities, AI tools |
| Access Control & Identity | Least privilege, joiner-mover-leaver, access reviews, MFA, privileged access |
| Authentication / Password | Length over complexity, no forced periodic rotation without cause (NIST SP 800-63-4), breached-password screening, MFA |
| Data Classification & Handling | Levels (Public/Internal/Confidential/Restricted), labeling, handling per level, retention |
| Cryptography | Approved algorithms, key management, TLS versions |
| Logging & Monitoring | What is logged, retention, time sync, review, protection of logs |
| Incident Response | Reporting duty, IR plan reference, notification |
| Vulnerability & Patch Management | Scanning cadence, remediation SLAs (KEV-driven) |
| Change Management | Approval, testing, emergency changes |
| Backup & Recovery | Frequency, immutability, restore testing |
| Remote Work / Mobile | Managed devices, VPN/ZTNA, public Wi-Fi |
| Third-Party Security | Due diligence, contract clauses, monitoring |
| Secure Development | SDLC requirements, code review, scanning |
| AI Acceptable Use | Approved tools, data restrictions, human review, logging |

---

## 3. Writing Rules

- "Shall/must" = mandatory; "should" = recommended; avoid "try to"
- One requirement per sentence; testable (who, what, when, how verified)
- Reference standards for technical specifics (policies change slowly, standards faster)
- Include scope, owner, approval date, review date, version, exceptions clause, enforcement clause
- Keep policies short (1–3 pages); put detail in standards

---

## 4. Framework Mapping

| Framework | Use |
|---|---|
| ISO/IEC 27001:2022 Annex A (93 controls in 4 themes: Organizational, People, Physical, Technological) | Certification, SoA (Statement of Applicability) |
| NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover) | Program structure |
| CIS Controls v8.1 (18 controls, IG1–IG3) | Prioritized technical safeguards |
| Sector/regulatory | PCI DSS 4.0.1, HIPAA, local data privacy laws |

Maintain a control matrix: requirement → document section → technical control → evidence → owner.

---

## 5. Exceptions & Risk Acceptance

```markdown
Exception ID: EX-2026-031
Requirement: STD-IAM-04 (phishing-resistant MFA for admins)
System/scope: Legacy SCADA HMI admin
Reason: Vendor does not support FIDO2
Compensating controls: Jump host with FIDO2 + session recording; network isolation
Risk rating: Medium | Risk owner: Plant Manager | Approved by: CISO
Expiry: 2027-04-30 (max 12 months) | Review: quarterly
```

---

## 6. Lifecycle

Annual review (or after major incidents/regulatory changes), version control (Git or GRC tool), training + annual attestation, compliance measured by technical evidence (e.g., MFA coverage report), enforcement via HR process for violations.

---

## Engagement Cheatsheet

```text
inventory + framework map → hierarchy (policy/standard/baseline/procedure/guideline) → core set incl. AI use → testable shall-statements
→ approval + training + attestation → control matrix (requirement→control→evidence) → exceptions with compensating controls + expiry → annual review
```

---

## Key References

- ISO/IEC 27001:2022 and 27002:2022; NIST CSF 2.0; CIS Controls v8.1; NIST SP 800-63-4; SANS policy templates
- Related: `defensive-frameworks`, `defensive-risk-threat-modeling`, `defensive-security-operating-model`, `defensive-privacy-data-protection`
