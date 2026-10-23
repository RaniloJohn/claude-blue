---
name: defensive-cyber-resilience
description: "Cyber resilience engineering and operations: NIST SP 800-160 Vol 2 Rev 1 goals (anticipate, withstand, recover, adapt), objectives and the 14 cyber resiliency techniques (adaptive response, analytic monitoring, contextual awareness, coordinated protection, deception, diversity, dynamic positioning, non-persistence, privilege restriction, realignment, redundancy, segmentation, substantiated integrity, unpredictability), MITRE CREF, minimum viable company and critical service mapping, impact tolerances (UK operational resilience, EU DORA), immutable recovery, cyber recovery vaults, recovery-time engineering, resilience testing and chaos exercises. Use when designing for survival of a major attack, setting impact tolerances, or assessing resilience."
---

# Cyber Resilience

Resilience assumes a serious attack **will** succeed somewhere and asks: can critical services keep running (degraded) and recover within tolerance? Security keeps attackers out; resilience keeps the business alive when they get in.

## Quick Workflow

1. Identify critical business services and their dependencies (minimum viable company)
2. Set impact tolerances (max tolerable downtime/data loss) per service
3. Apply resiliency techniques (§2) to the dependency chain
4. Build and test recovery (isolated, immutable, rehearsed)
5. Adapt after every incident and exercise

---

## 1. Goals (NIST SP 800-160 Vol 2 Rev 1)

| Goal | Meaning | Example capabilities |
|---|---|---|
| Anticipate | Maintain informed preparedness | Threat intel, exercises, dependency mapping |
| Withstand | Continue essential functions despite adversity | Segmentation, redundancy, graceful degradation, manual workarounds |
| Recover | Restore functions during and after | Immutable backups, clean rebuild, golden images |
| Adapt | Modify functions/capabilities to handle predicted changes | Architecture changes, lessons learned |

---

## 2. The 14 Techniques

| Technique | Practical example |
|---|---|
| Adaptive Response | Automated isolation, dynamic reconfiguration |
| Analytic Monitoring | SIEM/EDR/NDR, behavioral analytics |
| Contextual Awareness | Service dependency maps, mission impact dashboards |
| Coordinated Protection | Layered, integrated controls with shared signals |
| Deception | Decoys, honeytokens |
| Diversity | Different OS/vendors for redundant components, multiple ISPs |
| Dynamic Positioning | Move workloads/data; rotating infrastructure |
| Non-Persistence | Ephemeral containers/VDI, reimage on schedule, short-lived credentials |
| Privilege Restriction | Least privilege, JIT, tiering |
| Realignment | Remove unneeded functions; reduce attack surface |
| Redundancy | Backups, failover sites, spare hardware |
| Segmentation | Network/identity/administrative isolation |
| Substantiated Integrity | Signed code, secure boot, hash verification of backups |
| Unpredictability | Randomized schedules/configs that frustrate attacker planning |

MITRE **CREF** (Cyber Resiliency Engineering Framework) navigator links goals → objectives → techniques → approaches.

---

## 3. Minimum Viable Company

| Step | Output |
|---|---|
| Identify services that must run in days 1–7 of a crisis | e.g., payments, payroll, customer comms, safety systems |
| Map dependencies | Identity (AD/Entra), DNS, DHCP, network, email, key apps, data, third parties |
| Identify recovery order | Identity → network services → security tooling → core apps → others |
| Pre-stage | Clean build media, offline credentials, out-of-band comms, printed runbooks, contact lists |

Typical recovery order after ransomware: isolated recovery environment → AD forest recovery (`defensive-ad-forest-recovery`) → DNS/DHCP/PKI → EDR/SIEM → critical apps → endpoints.

---

## 4. Impact Tolerances

| Regime | Requirement |
|---|---|
| UK FCA/PRA operational resilience | Important business services, impact tolerances, mapping & scenario testing (fully in force March 2025) |
| EU DORA (applies from Jan 17, 2025) | ICT risk management, incident reporting, resilience testing (TLPT), third-party risk for financial entities |
| NIST CSF 2.0 Recover (RC) | Recovery planning, execution, communication |
| ISO 22301 | Business continuity management |

Define per service: **MTD** (maximum tolerable downtime), **RTO**, **RPO**, minimum service level in degraded mode.

---

## 5. Recovery Engineering

| Control | Detail |
|---|---|
| 3-2-1-1-0 backups | 3 copies, 2 media, 1 offsite, 1 immutable/offline, 0 errors on verification |
| Cyber recovery vault | Isolated (air-gapped or logically separated) copies with separate identity and management plane |
| Immutable storage | S3 Object Lock (compliance mode), Azure immutable blob, Veeam hardened Linux repository |
| Clean-room recovery | Isolated environment to restore and scan before reconnecting |
| Golden images & IaC | Rebuild rather than clean; infrastructure as code for redeploy |
| Recovery time testing | Measure actual restore time of crown jewels at least annually |

---

## 6. Resilience Testing

- Tabletop: ransomware with AD + backups compromised (`defensive-incident-response`)
- Technical: full restore of a critical service in an isolated environment, timed
- Chaos engineering for security: kill a security tool, revoke a dependency, fail over an ISP
- Scenario: loss of a key SaaS provider or MSP

---

## Engagement Cheatsheet

```text
critical services + dependencies (MVC) → impact tolerances (MTD/RTO/RPO) → apply 14 techniques along chain
→ isolated immutable recovery + clean room + golden images → timed restore tests + tabletop → adapt
```

---

## Key References

- NIST SP 800-160 Vol 2 Rev 1 (2021); MITRE CREF; NIST CSF 2.0
- EU DORA; UK FCA PS21/3; ISO 22301
- Related: `defensive-ransomware-response`, `defensive-ad-forest-recovery`
