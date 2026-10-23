---
name: defensive-security-operating-model
description: "Security organization and operating model: security function map (governance, architecture, security engineering, SOC, detection engineering, threat intel, IR, vulnerability management, IAM, AppSec, cloud security, GRC, awareness), sourcing models (in-house, MSSP, MDR, co-managed, hybrid SOC), SOC-CMM maturity domains, MITRE 11 Strategies of a World-Class SOC, IIA Three Lines Model, RACI for security processes, shared responsibility with IT and cloud providers, staffing ratios and on-call design, budgeting, and roadmap planning. Use when designing a security team, choosing MDR vs in-house, writing RACIs, or assessing security program maturity."
---

# Security Operating Model

Tools don't defend organizations — people with clear responsibilities, processes, and authority do. The operating model defines **who does what, with what authority, and how work flows** between security, IT, and the business.

## Quick Workflow

1. Map required security functions (§1) against current owners
2. Choose sourcing per function (§2)
3. Define RACI and escalation paths (§4)
4. Assess maturity (SOC-CMM / CSF tiers) and set 12–24 month targets
5. Fund and staff the roadmap

---

## 1. Function Map

| Function | Core responsibilities |
|---|---|
| Governance & risk (CISO office) | Strategy, policy, risk register, board reporting, budget |
| Security architecture | Standards, design reviews, reference patterns |
| Security engineering | Deploy/operate security tooling (EDR, SIEM, PAM, email security) |
| SOC (L1/L2) | Monitoring, triage, initial response |
| Detection engineering (L3) | Rule development, tuning, detection-as-code |
| Threat intelligence | Requirements, collection, analysis, dissemination |
| Incident response / DFIR | Major incident handling, forensics |
| Threat hunting | Hypothesis-driven searches |
| Vulnerability management | Scanning, prioritization, remediation tracking |
| IAM | Identity lifecycle, access reviews, PAM, SSO/MFA |
| AppSec / product security | SDLC, code review, pentest coordination |
| Cloud security | Guardrails, CSPM, cloud IR |
| OT security | ICS monitoring, segmentation (if applicable) |
| GRC & privacy | Compliance, audits, third-party risk, DPO liaison |
| Awareness & culture | Training, phishing simulation, champions program |
| Offensive security / red team | Validation (internal or contracted) |

---

## 2. Sourcing Models

| Model | Fits | Watch out for |
|---|---|---|
| In-house 24×7 SOC | Large orgs, regulated, complex environments | 24×7 needs ≈ 5–5.5 FTE per seat; two-analyst shifts ≈ 10–12 FTE before L2/L3 |
| MSSP | Log monitoring + device management at scale | Often alert-forwarding only; limited response authority |
| MDR | Mid-size orgs wanting response, not just alerts | Scope of response actions, EDR lock-in, telemetry coverage outside EDR |
| Co-managed SIEM/SOC | Internal team for business hours + provider after hours | Clear handoffs, shared detection content ownership |
| Hybrid | In-house detection engineering + IR, outsourced L1 | Feedback loops from L1 to engineering |

Contract essentials: response actions allowed without asking, SLAs per severity, data ownership/export, detection content ownership, IR retainer hours, reporting.

---

## 3. Maturity Models

| Model | Use |
|---|---|
| SOC-CMM | 5 domains: Business, People, Process, Technology, Services; maturity + capability scoring |
| NIST CSF 2.0 tiers | Partial, Risk Informed, Repeatable, Adaptive |
| MITRE "11 Strategies of a World-Class Cybersecurity Operations Center" (2022) | Practical SOC design guidance: know what you protect, give the SOC authority, build a team, instrument the environment, threat-informed, etc. |
| C2M2 | Energy/OT sector capability maturity |
| CMMI Cybermaturity / CIS IGs | Alternative baselines |

---

## 4. RACI (example)

| Process | CISO | SOC | Det Eng | IR | IT Ops | App Owner | Legal/Comms |
|---|---|---|---|---|---|---|---|
| Alert triage | I | R/A | C | C | — | — | — |
| SEV1 incident | A | R | C | R | R | C | C |
| Containment of prod server | I | R | — | A | R | C | — |
| New detection rule | — | C | R/A | C | — | — | — |
| Patch critical vuln | I | — | — | — | R | A | — |
| Breach notification | A | — | — | C | — | — | R |
| Firewall change | — | C | — | — | R/A | C | — |

R = Responsible, A = Accountable (one per row), C = Consulted, I = Informed.

**Authority:** pre-approve the SOC to isolate endpoints, disable accounts, and block IOCs without waiting for business approval (except listed critical systems).

---

## 5. Three Lines Model (IIA 2020)

| Line | Role in security |
|---|---|
| First line | IT and business own and operate controls day-to-day |
| Second line | Security/risk functions set policy, monitor, challenge |
| Third line | Internal audit provides independent assurance |
| Governing body | Board oversight, risk appetite |

---

## 6. Staffing & On-call

- 24×7 single-seat coverage ≈ 5.0–5.5 FTE per seat after leave/training; L2/L3 on-call rotation weekly with compensation
- Analyst burnout drivers: alert volume, no automation, no career path — budget for SOAR and training time (≥ 10% of hours)
- Career ladder: L1 → L2 → specialization (DE, IR, CTI, hunting)

---

## 7. Shared Responsibility

| Party | Owns |
|---|---|
| Cloud provider | Security **of** the cloud (physical, hypervisor, managed service internals) |
| Customer | Security **in** the cloud (identity, config, data, workloads) |
| IT operations | Patching, configuration, backups |
| Security | Standards, monitoring, response, assurance |
| Business owners | Risk acceptance, data classification, access approval |

---

## Engagement Cheatsheet

```text
function map vs owners → sourcing per function (in-house/MSSP/MDR/co-managed) → RACI + pre-approved SOC authority
→ maturity (SOC-CMM / CSF tiers / MITRE 11 strategies) → staffing (≈5.5 FTE/24×7 seat) → three lines + shared responsibility → roadmap & budget
```

---

## Key References

- SOC-CMM (soc-cmm.com); MITRE "11 Strategies of a World-Class Cybersecurity Operations Center" (2022)
- IIA Three Lines Model (2020); NIST CSF 2.0
- Related: `defensive-soc-building`, `defensive-security-metrics`, `defensive-frameworks`
