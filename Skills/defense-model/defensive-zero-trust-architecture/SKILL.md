---
name: defensive-zero-trust-architecture
description: "Zero Trust Architecture design and maturity: NIST SP 800-207 tenets and logical components (PE, PA, PEP), deployment models (enhanced identity governance, micro-segmentation, software-defined perimeter), NIST SP 1800-35 example implementations, CISA Zero Trust Maturity Model v2.0 pillars (Identity, Devices, Networks, Applications and Workloads, Data) and cross-cutting capabilities with Traditional/Initial/Advanced/Optimal stages, DoD ZT pillars, BeyondCorp, ZTNA vs VPN, continuous verification signals (device health, risk, location), policy examples with Entra Conditional Access and identity-aware proxies, and a phased roadmap. Use when planning, assessing, or explaining a zero trust program."
---

# Zero Trust Architecture

Zero trust removes implicit trust based on network location. Every access request is authenticated, authorized against policy using identity, device, and context signals, and granted least privilege for a limited session — then continuously re-evaluated.

## Quick Workflow

1. Identify protect surfaces (crown-jewel data, apps, assets, services)
2. Map transaction flows to them
3. Place Policy Enforcement Points in front of each protect surface
4. Write policy using identity + device + context signals
5. Monitor and iterate; measure against CISA ZTMM stages

---

## 1. NIST SP 800-207 Tenets (condensed)

1. All data sources and computing services are resources
2. All communication is secured regardless of network location
3. Access is granted per session
4. Access is determined by dynamic policy (identity, app, device state, behavior, environment)
5. The enterprise monitors and measures integrity and posture of all owned assets
6. Authentication and authorization are dynamic and strictly enforced before access
7. Collect as much information as possible about assets, infrastructure, and communications to improve posture

### Logical components

| Component | Role | Examples |
|---|---|---|
| Policy Engine (PE) | Decides grant/deny | Entra CA engine, Okta policy, ZTNA controller |
| Policy Administrator (PA) | Establishes/tears down session | Token issuance, tunnel setup |
| Policy Enforcement Point (PEP) | Enforces at the resource | Identity-aware proxy, ZTNA connector, micro-segmentation agent, API gateway |
| Signals | Inputs | IdP, MDM/EDR posture, threat intel, SIEM, data classification, activity logs |

### Deployment approaches

- **Enhanced identity governance** — identity as primary signal (SaaS-heavy orgs)
- **Micro-segmentation** — host/workload-level enforcement (data centers)
- **Software-defined perimeter / ZTNA** — overlay network, resources dark until authorized

---

## 2. CISA Zero Trust Maturity Model v2.0

| Pillar | Traditional → Optimal (examples) |
|---|---|
| Identity | Passwords + static MFA → phishing-resistant MFA everywhere, continuous risk-based validation |
| Devices | Manual inventory → real-time posture feeding every access decision |
| Networks | Flat, perimeter-based → micro-perimeters, encrypted everywhere, dynamic segmentation |
| Applications & Workloads | VPN-exposed apps → apps accessible over internet via authenticated proxies, continuous authz, immutable workloads |
| Data | Ad hoc → automated classification, encryption, DLP tied to access decisions |

Cross-cutting: **Visibility & Analytics, Automation & Orchestration, Governance**. Stages: **Traditional, Initial, Advanced, Optimal**.

DoD ZT strategy uses 7 pillars (User, Device, Application & Workload, Data, Network & Environment, Automation & Orchestration, Visibility & Analytics) with target-level activities due FY2027.

---

## 3. ZTNA vs VPN

| Aspect | Traditional VPN | ZTNA |
|---|---|---|
| Access scope | Network segment | Single application |
| Exposure | Internet-facing concentrator (KEV-heavy class) | Outbound-only connectors; app not internet-exposed |
| Trust | After login, broad lateral reach | Per-app, per-session, posture-checked |
| Visibility | IP-level | User + app + device per request |
| Lateral movement | Easy | Restricted by design |

---

## 4. Policy Examples

### Entra Conditional Access (baseline set)

| Policy | Assignment | Grant |
|---|---|---|
| Phishing-resistant MFA for admins | Directory roles | Auth strength: phishing-resistant |
| MFA for all users | All users, all apps | Require MFA (auth strength) |
| Block legacy auth | All users | Block (client apps: other clients) |
| Compliant device for sensitive apps | Finance/HR apps | Require compliant device |
| Block high sign-in risk | All users | Block or require password change + MFA |
| Token protection / CAE | Supported apps | Enable token protection, CAE strict location |
| Block device code flow | All users except exceptions | Block authentication flows: device code |

### Identity-aware proxy rule (generic)

```yaml
resource: payroll.internal
allow:
  - group: hr-payroll
    device: { managed: true, edr_healthy: true, os_patch_age_days: "<=30" }
    auth: { method: [fido2, cert], max_age_minutes: 720 }
    location: { deny_countries: [sanctioned-list] }
session: { duration: 8h, reevaluate_on: [risk_change, device_noncompliant] }
log: siem
```

---

## 5. Roadmap (phased)

| Phase | Outcomes |
|---|---|
| 0 — Foundation | Asset and identity inventory, single IdP, logging to SIEM |
| 1 — Identity | MFA everywhere → phishing-resistant for admins, legacy auth blocked, PAM/JIT |
| 2 — Devices | MDM + EDR on all endpoints, posture in access policy |
| 3 — Apps | Move internal apps behind ZTNA/IAP; retire broad VPN |
| 4 — Network | Segment data center/cloud; east-west policy; encrypt internal traffic |
| 5 — Data | Classification + labels drive DLP and access |
| 6 — Automation | Risk signals auto-trigger step-up, revoke, isolate |

---

## 6. Common Mistakes

- Buying a "ZT product" without inventory or policy model
- ZTNA with "allow all apps" policies (VPN with extra steps)
- Exempting service accounts and admins from policy
- Ignoring workload-to-workload (east-west) traffic
- No break-glass accounts, or unmonitored ones

---

## Engagement Cheatsheet

```text
protect surfaces → flows → PEP placement → policy (identity+device+context, least privilege, per session)
→ CISA ZTMM pillar scoring (Traditional/Initial/Advanced/Optimal) → phased roadmap → continuous evaluation + break-glass monitoring
```

---

## Key References

- NIST SP 800-207 (2020); NIST SP 1800-35 Implementing a ZTA (final 2025); CISA ZTMM v2.0 (2023); DoD ZT Strategy & Reference Architecture
- Google BeyondCorp papers; Microsoft Zero Trust deployment guides
- Related: `defensive-remote-access-ztna`, `defensive-entra-id`, `defensive-auth-implementation`, `defensive-network-segmentation`, `defensive-sdwan-sase`
