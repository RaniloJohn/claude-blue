---
name: defensive-security-architecture
description: "Enterprise and solution security architecture: architecture frameworks (SABSA layers, TOGAF with security, Zachman), NIST SP 800-160 systems security engineering, reference architectures (Microsoft MCRA, AWS Security Reference Architecture, Google Cloud security foundations, NIST SP 800-215 enterprise network), Microsoft enterprise access model and AD tiering (control/management/data planes), trust zones and boundaries, DMZ and management network design, identity-centric architecture, logging architecture, secure cloud landing zones, architecture review checklist, threat modeling handoff, and architecture decision records. Use when designing or reviewing a system's security architecture or writing an architecture assessment."
---

# Security Architecture

Architecture decides which attacks are even possible. Reviews should trace **trust boundaries**, **privileged planes**, **data flows**, and **failure modes**, then record decisions so they survive staff turnover.

## Quick Workflow

1. Context: business goals, crown jewels, regulatory scope, threat profile
2. Draw the system: components, data flows, trust boundaries, identities
3. Separate planes: control (identity/admin), management, data/workload, user access
4. Apply reference patterns (§3); threat-model the deltas (`defensive-risk-threat-modeling`)
5. Record ADRs and residual risks

---

## 1. Frameworks

| Framework | Use |
|---|---|
| SABSA | Business-driven security architecture; layers Contextual → Conceptual → Logical → Physical → Component, plus Service Management; attributes profiling |
| TOGAF (+ security guidance) | Enterprise architecture method (ADM); embed security in each phase |
| Zachman | Classification grid (what/how/where/who/when/why × perspectives) |
| NIST SP 800-160 Vol 1 Rev 1 | Systems security engineering across lifecycle |
| NIST SP 800-160 Vol 2 Rev 1 | Cyber resiliency engineering (`defensive-cyber-resilience`) |
| NIST SP 800-215 | Secure enterprise network landscape (hybrid, cloud, remote) |

---

## 2. Planes & Tiering

Microsoft enterprise access model (successor to the AD tier 0/1/2 model):

| Plane | Contains | Rule |
|---|---|---|
| Control plane | Identity systems (AD DCs, Entra ID, AD CS, ADFS, PAM, Entra Connect), security tools with admin rights over everything | Highest protection; only PAWs administer; no internet browsing |
| Management plane | Hypervisors, cloud consoles, backup systems, deployment tools, monitoring | Separate admin accounts; MFA; no shared creds with data plane |
| Data / workload plane | Apps, databases, servers | Least privilege; workload identities |
| User & app access | User devices, external access, APIs | Zero trust access policies |

Rule: **no credential from a lower plane is ever exposed on a higher plane's system, and no higher-plane credential is used on a lower-plane system.** Backup, EDR, RMM, and deployment tools that can run code everywhere are control plane.

---

## 3. Reference Patterns

| Pattern | Key elements |
|---|---|
| Internet-facing app | CDN/WAF → load balancer → app tier (private) → data tier (private); secrets in vault; no direct DB exposure |
| DMZ (classic) | Three-legged or dual-firewall; DMZ hosts cannot initiate to internal; reverse proxies preferred over direct exposure |
| Management network | Out-of-band management VLAN/VRF for device interfaces (iLO/iDRAC/IPMI, switch mgmt); reachable only from PAW/jump hosts |
| Logging architecture | Agents → collectors/forwarders → SIEM/data lake; immutable copy in separate account/tenant; NTP synchronized; retention per policy |
| Cloud landing zone | Org/management group hierarchy, separate security/log-archive accounts, guardrails (SCP/Policy), centralized networking (hub/transit), SSO, no long-lived keys |
| Admin access | PAW → PAM/JIT → jump host/bastion → target; session recording |
| Remote access | ZTNA/IAP per app; legacy VPN only with MFA + posture + segmentation |
| Hybrid identity | Entra Connect / Cloud Sync server treated as Tier 0; PHS + cloud MFA; ADFS retired where possible |

Vendor references: Microsoft Cybersecurity Reference Architectures (MCRA), AWS Security Reference Architecture (AWS SRA), Google Cloud enterprise foundations blueprint.

---

## 4. Architecture Review Checklist

| Area | Questions |
|---|---|
| Identity | Single IdP? Phishing-resistant MFA? Service accounts inventoried and least privilege? Workload identity instead of static keys? |
| Trust boundaries | Where does untrusted input cross? Is it validated/authenticated at each crossing? |
| Network | Default-deny between zones? Egress controlled? Management interfaces isolated? |
| Data | Classified? Encrypted at rest/in transit? Key ownership? Where are copies (backups, analytics, logs)? |
| Secrets | Vaulted, rotated, never in code/images? |
| Logging | Security-relevant events logged, centralized, time-synced, tamper-resistant? |
| Resilience | Single points of failure? Backups isolated and tested? RTO/RPO met? |
| Supply chain | Third-party components inventoried (SBOM)? Vendor access controlled? |
| Admin paths | Who can change this system? From where? With what credential? |
| Failure modes | What happens when auth/logging/dependency fails — closed or open? |

---

## 5. Architecture Decision Record (template)

```markdown
# ADR-NNN: <decision>
Status: proposed | accepted | superseded by ADR-MMM
Context: <problem, constraints, threats>
Decision: <what we chose>
Alternatives: <options considered and why rejected>
Security consequences: <risks reduced, risks introduced, residual risk + owner>
Controls required: <list with owners>
Review date: <YYYY-MM-DD>
```

---

## Engagement Cheatsheet

```text
context + crown jewels → diagram flows/boundaries/identities → separate control/mgmt/data/access planes
→ apply reference pattern → checklist (identity, boundaries, network, data, secrets, logging, resilience, supply chain, admin paths, failure modes)
→ threat model deltas → ADR + residual risk owner
```

---

## Key References

- SABSA Institute; The Open Group TOGAF; NIST SP 800-160 Vol 1/2; NIST SP 800-215
- Microsoft enterprise access model & MCRA; AWS SRA; Google Cloud security foundations
- Related: `defensive-zero-trust-architecture`, `defensive-network-security-architecture`, `defensive-ad-hardening`, `defensive-risk-threat-modeling`
