---
name: defensive-adversary-emulation
description: "Threat-informed adversary emulation planning for defenders: building emulation plans from CTI (actor selection, technique extraction, procedure fidelity), using the CTID Adversary Emulation Library and ATT&CK Evaluations scenarios, defining objectives and success metrics, scoping, rules of engagement, deconfliction, lab vs production execution, measuring prevention and detection coverage across the kill chain, and translating results into prioritized control and detection improvements. Use when planning a full adversary emulation, tabletop-to-technical exercise, or validating defenses against a specific threat actor."
---

# Adversary Emulation Planning

Emulation tests your defenses against how a specific adversary actually operates — end-to-end — rather than isolated techniques. The plan is the product: realistic, scoped, measurable, safe.

## Quick Workflow

1. Select adversary based on threat relevance (sector, region, assets)
2. Extract TTPs and procedures from CTI
3. Build plan: phases, procedures, expected telemetry/detections, success criteria
4. Rules of engagement, deconfliction, safety controls
5. Execute (lab first), capture evidence
6. Analyze outcomes; prioritize fixes; re-test

---

## 1. Actor Selection

| Factor | Example |
|---|---|
| Sector targeting | Ransomware affiliates hitting BPO/finance in APAC |
| Initial access vectors seen in peers | Edge VPN exploits, phishing with AiTM |
| Your crown jewels | Customer PII, payment systems, OT |
| Intel availability | Detailed public reporting with procedures |

---

## 2. From CTI to Procedures

| CTI statement | Technique | Emulation procedure (lab) | Expected detection |
|---|---|---|---|
| "Used valid VPN credentials" | T1078 / T1133 | Login to test VPN from new ASN | Impossible travel / new ASN VPN alert |
| "Ran AdFind for domain recon" | T1087.002 / T1482 | Equivalent LDAP enumeration | LDAP volume / tool detection |
| "Dumped LSASS via comsvcs" | T1003.001 | Atomic T1003.001 test | Sysmon 10 rule; ASR block |
| "Moved laterally with PsExec" | T1021.002 / T1569.002 | PsExec to test server | 7045 + 5145 ADMIN$ rule |
| "Exfiltrated with rclone to MEGA" | T1567.002 | rclone to test bucket | Process + egress rule |
| "Deployed ransomware via GPO" | T1484.001 / T1486 | Benign GPO-deployed script creating marker files | GPO change + mass file write detections |

Fidelity levels: **exact tool** (highest realism, highest risk) → **equivalent tool** → **simulated behavior** (benign marker). Choose per risk.

---

## 3. Plan Structure

```markdown
# Emulation Plan — <Actor/Campaign> — v1.0
Objective: Validate prevention/detection for <phases>; measure time-to-detect and response.
Scope: <networks, hosts, accounts>; Out of scope: <prod DCs, OT, customer data>
Rules of engagement: <hours, stop conditions, approvals, comms channel, emergency contact>
Deconfliction: <how SOC distinguishes test vs real — trusted agent; test IDs in hostnames/accounts>
Phases:
  1. Initial Access — procedures, expected telemetry, success criteria
  2. Discovery
  3. Credential Access
  4. Lateral Movement
  5. Collection & Exfiltration
  6. Impact (simulated)
Cleanup: <per procedure>
Reporting: outcome table per procedure; gap list with owners
```

---

## 4. Resources

| Resource | Use |
|---|---|
| CTID Adversary Emulation Library | Ready plans (e.g., FIN6, menuPass, APT29, Sandworm, OceanLotus) with procedures |
| MITRE ATT&CK Evaluations | Public scenarios and vendor detection results |
| Atomic Red Team | Procedure-level building blocks |
| Caldera | Automated multi-step operations |
| CTID Micro Emulation Plans | Small, targeted compound behaviors |

---

## 5. Measuring Outcomes

| Metric | Definition |
|---|---|
| Prevention rate | Procedures blocked / total |
| Detection rate | Procedures alerted / total |
| Visibility rate | Procedures with telemetry / total |
| Mean time to detect (per phase) | Exec time → alert |
| Earliest detection phase | How far did the actor get before first alert? |
| Response effectiveness | Containment correct and timely? |

Primary goal: move earliest detection to the left of the kill chain.

---

## 6. Safety & Deconfliction

- Trusted agent in SOC knows test windows (or blind test with management + IR lead aware)
- Tag test artifacts (account names, hostnames, file markers)
- Never run destructive impact procedures in production — simulate (marker files, benign encryption of test data in lab)
- Stop immediately on unexpected production impact

---

## Engagement Cheatsheet

```text
relevant actor → CTI → procedures with fidelity choice → plan (scope, RoE, deconfliction) → lab run
→ controlled prod run (benign) → outcome metrics per phase → prioritized fixes → re-emulate
```

---

## Key References

- Center for Threat-Informed Defense (CTID) Adversary Emulation Library & Micro Emulation Plans
- MITRE ATT&CK Evaluations
- Related: `defensive-purple-team`, `defensive-cti`, `defensive-attack-mapping`
