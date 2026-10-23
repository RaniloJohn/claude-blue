---
name: defensive-defense-in-depth
description: "Defense in depth and layered security model: layers (governance and people, physical, perimeter, network, endpoint/host, application, data, identity, monitoring and response, recovery), Swiss cheese model, control diversity and independence, prevent-detect-respond-recover per layer, mapping layers to NIST CSF 2.0 functions and CIS Controls v8.1, coverage matrices per attack path, single points of failure, and building a layered control stack for SMB, enterprise, cloud, and OT. Use when designing or reviewing a layered security architecture, finding gaps, or explaining defense in depth."
---

# Defense in Depth

No single control is perfect, so stack **independent** controls so that an attacker must defeat several — and each attempt creates a detection opportunity. Independence matters: two controls sharing one failure mode (same credential, same vendor bug, same admin) are one layer.

## Quick Workflow

1. List crown-jewel assets and the attack paths to them
2. For each path, place controls per layer (§1) and per function (prevent/detect/respond/recover)
3. Mark single points of failure and shared failure modes
4. Prioritize gaps on the most likely paths (threat-informed — `defensive-threat-informed-defense`)

---

## 1. Layers

| Layer | Prevent | Detect | Respond / Recover |
|---|---|---|---|
| Governance & people | Policy, awareness, background checks | Reporting culture (phish button) | IR plan, tabletop |
| Physical | Badges, locks, mantraps | CCTV, badge logs | Guard response |
| Perimeter / edge | NGFW, WAF, email gateway, DDoS protection, patched edge devices | IPS, edge logs, EASM | Block/geofence, emergency patch |
| Network | Segmentation, NAC, ACLs, egress filtering, DNS filtering | NDR, Zeek, NetFlow, IDS | Quarantine VLAN, null route |
| Identity | MFA (phishing-resistant), CA policies, PAM, tiering | ITDR, sign-in risk, AD monitoring | Session revoke, credential reset |
| Endpoint / host | Hardening, app control, ASR, patching, least privilege | EDR, Sysmon, FIM | Isolation, reimage |
| Application | Secure SDLC, input validation, authz checks, RASP | App logs, WAF alerts | Feature flags, rollback |
| Data | Classification, encryption, DLP, access reviews | DLP alerts, access analytics | Key revocation, legal/notification |
| Cloud control plane | SCPs/policies, guardrails, CSPM | CloudTrail/Activity, GuardDuty/Defender | Revoke keys, quarantine accounts |
| Monitoring & response | Logging standards | SIEM correlation, hunting | SOAR, IR |
| Recovery | Immutable/offline backups | Backup integrity checks | Tested restores, DR |

---

## 2. Swiss Cheese Model

Each layer has holes (vulnerabilities, misconfigurations, human error). A breach happens when holes align. Goals:

- **Fewer holes** per layer (hardening, patching)
- **Non-aligned holes** — diverse, independent controls (e.g., email gateway + EDR + app control from different mechanisms)
- **Detection between layers** — every layer crossing is a chance to alert

---

## 3. Coverage Matrix (per attack path)

Example path: phishing → macro → credential theft → lateral movement → ransomware.

| Step | Prevent | Detect | Gap? |
|---|---|---|---|
| Phish delivered | Gateway, DMARC | User report, gateway alert | — |
| Macro executes | MOTW macro block, ASR | EDR Office child rule | ASR in audit only → **gap** |
| Credential theft | Credential Guard, LSA PPL | Sysmon 10 LSASS rule | — |
| Lateral movement | Local admin restriction (LAPS), firewall host rules | 4624 workstation↔workstation | Host firewall off → **gap** |
| Encryption | App control, backups immutable | Recovery-inhibition rule → isolate | — |

Rule: every step needs ≥ 1 preventive and ≥ 1 detective control; crown jewels need ≥ 2 independent detectives.

---

## 4. Mapping to Frameworks

| NIST CSF 2.0 function | Defense-in-depth role |
|---|---|
| Govern (GV) | Policy, risk strategy, roles, supply chain |
| Identify (ID) | Asset inventory, risk assessment |
| Protect (PR) | Preventive layers |
| Detect (DE) | Monitoring layers |
| Respond (RS) | IR |
| Recover (RC) | Backups, DR, lessons learned |

CIS Controls v8.1 IG1 (56 safeguards) is the minimum layered baseline for small organizations; IG2/IG3 add depth.

---

## 5. Reference Stacks

| Environment | Minimum layered stack |
|---|---|
| SMB | Patched edge or no edge (ZTNA), M365/Google with phishing-resistant MFA + CA, Defender/EDR with ASR, DNS filtering, LAPS, immutable backups, MDR service |
| Enterprise | + NGFW segmentation, NAC, PAM + AD tiering, SIEM/SOAR, NDR, app control on servers, DLP, vuln management SLAs, purple teaming |
| Cloud-native | Org guardrails (SCP/Azure Policy/Org Policy), SSO + no long-lived keys, CSPM/CNAPP, workload identity, runtime security (Falco/Defender), centralized immutable logs, backups in separate account |
| OT | Purdue/IEC 62443 zones & conduits, unidirectional gateways where justified, passive OT NDR, jump hosts with MFA, offline backups of PLC logic, compensating controls for unpatchable assets |

---

## 6. Anti-Patterns

- "Crunchy shell, soft center" — strong perimeter, flat internal network
- All layers administered by one domain admin account (shared failure mode)
- Detection layers that alert to an inbox nobody reads
- Backups reachable with the same credentials as production
- Many tools, no integration — layers that don't share context

---

## Engagement Cheatsheet

```text
crown jewels → attack paths → per step: prevent + detect (+ respond/recover) across layers → find SPOFs & shared failure modes
→ prioritize gaps on likely paths → map to CSF 2.0 / CIS IG → re-test with purple team
```

---

## Key References

- NSA "Defense in Depth" (2010s); NIST CSF 2.0 (Feb 2024); CIS Controls v8.1 (2024)
- James Reason, Swiss cheese model
- Related: `defensive-security-fundamentals`, `defensive-zero-trust-architecture`, `defensive-security-architecture`, `defensive-frameworks`
