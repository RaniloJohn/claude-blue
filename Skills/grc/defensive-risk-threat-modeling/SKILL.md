---
name: defensive-risk-threat-modeling
description: "Threat modeling and cyber risk assessment for defenders: STRIDE and STRIDE-per-element on data flow diagrams, attack trees, PASTA, LINDDUN (privacy), kill-chain/ATT&CK-based threat modeling, trust boundaries, abuse cases, control selection mapped to D3FEND, risk registers with likelihood/impact and FAIR-style quantification basics, risk treatment (mitigate, transfer, accept, avoid), residual risk, and communicating risk to leadership. Use when threat modeling a system or feature, building a risk register, or justifying security investments."
---

# Threat Modeling & Risk Assessment

Threat modeling answers four questions (Shostack): **What are we working on? What can go wrong? What are we going to do about it? Did we do a good job?** Risk assessment turns the answers into prioritized, owned decisions.

## Quick Workflow

1. Scope the system; draw a data flow diagram (DFD) with trust boundaries
2. Enumerate threats (STRIDE per element, ATT&CK for operational threats)
3. Rate risk (likelihood × impact)
4. Select controls (prevent, detect, respond); map to D3FEND/framework
5. Record in risk register with owner and treatment
6. Validate (tests, reviews) and revisit on change

---

## 1. DFD Elements

| Element | Symbol | Examples |
|---|---|---|
| External entity | Rectangle | User, partner API, IdP |
| Process | Circle | Web app, worker, agent |
| Data store | Parallel lines | DB, bucket, queue, vector store |
| Data flow | Arrow | HTTPS, gRPC, message |
| Trust boundary | Dashed line | Internet ↔ DMZ, tenant ↔ tenant, user ↔ admin, app ↔ LLM |

---

## 2. STRIDE

| Threat | Property violated | Typical controls |
|---|---|---|
| **S**poofing | Authentication | MFA, mTLS, signed tokens |
| **T**ampering | Integrity | Signing, hashing, authz on writes, immutable logs |
| **R**epudiation | Non-repudiation | Audit logging with identity, time sync, log integrity |
| **I**nformation disclosure | Confidentiality | Encryption, authz, data minimization |
| **D**enial of service | Availability | Rate limits, quotas, autoscaling, redundancy |
| **E**levation of privilege | Authorization | Least privilege, input validation, sandboxing |

STRIDE-per-element: processes (all six), data stores (T, R, I, D), data flows (T, I, D), external entities (S, R).

---

## 3. Attack Trees

```text
Goal: Exfiltrate customer PII from CRM
├── Compromise user credentials
│   ├── AiTM phishing → session token theft            [Likely]
│   └── Infostealer on unmanaged device                 [Possible]
├── Abuse API authorization
│   └── BOLA on /customers/{id}                         [Possible if no object checks]
├── Compromise integration
│   └── Over-privileged OAuth app with data scope       [Possible]
└── Insider export
    └── Bulk export feature without approval/alerting   [Likely]
```

Annotate leaves with cost/difficulty, detection opportunity, and existing controls.

---

## 4. Operational Threat Modeling (ATT&CK)

For a system, list plausible techniques per tactic and check: telemetry exists? detection exists? prevention exists? Feed gaps into `defensive-attack-mapping` and the detection backlog.

---

## 5. Other Methods

| Method | Use |
|---|---|
| PASTA | Risk-centric, 7 stages from business objectives to attack simulation |
| LINDDUN | Privacy threats (linkability, identifiability, non-repudiation, detectability, disclosure, unawareness, non-compliance) |
| OWASP Threat Dragon / Microsoft Threat Modeling Tool / pytm | Tooling for DFDs and threat lists |
| AI-specific | OWASP LLM/Agentic Top 10, MITRE ATLAS (see `defensive-ai-security`) |

---

## 6. Risk Rating

Qualitative 5×5:

| Likelihood \ Impact | 1 Minimal | 2 Minor | 3 Moderate | 4 Major | 5 Severe |
|---|---|---|---|---|---|
| 5 Almost certain | 5 | 10 | 15 | 20 | 25 |
| 4 Likely | 4 | 8 | 12 | 16 | 20 |
| 3 Possible | 3 | 6 | 9 | 12 | 15 |
| 2 Unlikely | 2 | 4 | 6 | 8 | 10 |
| 1 Rare | 1 | 2 | 3 | 4 | 5 |

Likelihood inputs: threat activity (CTI, KEV, EPSS), exposure, control strength. Impact inputs: data sensitivity, safety, financial, regulatory, operational.

Quantitative (FAIR basics): Risk = Loss Event Frequency × Loss Magnitude; estimate ranges (min/most likely/max) and run Monte Carlo for annualized loss expectancy — useful for investment decisions.

---

## 7. Risk Register Entry

```markdown
| ID | Risk statement | Asset | Threat/ATT&CK | L | I | Score | Existing controls | Treatment | New controls (D3FEND) | Owner | Due | Residual |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R-014 | Attacker with stolen session token accesses M365 mail and initiates payment fraud | Finance mailboxes | T1539, T1550.004 | 4 | 4 | 16 | MFA (non-phishing-resistant) | Mitigate | Phishing-resistant MFA, Token Protection, inbox-rule detection | IAM lead | 2026-12-15 | 8 |
```

Risk statement format: *"[Threat source] could [action] on [asset], resulting in [impact]."*

Treatments: Mitigate (controls), Transfer (insurance/contracts — not a technical fix), Accept (documented, approved, expiry), Avoid (stop the activity).

---

## 8. Communicating to Leadership

- Lead with business impact and likelihood trend, not CVEs
- Show top 5 risks, treatment status, and what decision is needed
- Use ranges, not false precision
- Tie investments to risk reduction (before/after residual)

---

## Engagement Cheatsheet

```text
scope + DFD + trust boundaries → STRIDE per element + attack trees + ATT&CK → rate L×I (CTI/EPSS/exposure)
→ controls (prevent/detect/respond, D3FEND) → register with owner/due/residual → validate → revisit on change
```

---

## Key References

- Adam Shostack, *Threat Modeling: Designing for Security*; Threat Modeling Manifesto
- OWASP Threat Modeling Cheat Sheet; OWASP Threat Dragon; LINDDUN
- FAIR Institute (Open FAIR); NIST SP 800-30r1 Guide for Conducting Risk Assessments
- Related: `defensive-frameworks`, `defensive-attack-mapping`, `defensive-ai-security`
