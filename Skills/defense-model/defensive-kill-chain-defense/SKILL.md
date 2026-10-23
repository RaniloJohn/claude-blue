---
name: defensive-kill-chain-defense
description: "Intrusion analysis and defense models: Lockheed Martin Cyber Kill Chain (7 phases) with courses-of-action matrix (detect, deny, disrupt, degrade, deceive, destroy), Unified Kill Chain (18 phases across In/Through/Out), Diamond Model of Intrusion Analysis (adversary, capability, infrastructure, victim, pivoting, activity threads), David Bianco's Pyramid of Pain, MITRE ATT&CK as behavior layer, ICS Kill Chain, and how to combine them for campaign analysis, detection prioritization, and reporting. Use when analyzing an intrusion, choosing where to break the chain, or explaining defense models."
---

# Kill Chain & Intrusion Analysis Models

Models give structure to messy intrusions: where the attacker is, what they need next, and where a defender gets the most leverage. Use the kill chain for **phases**, ATT&CK for **behaviors**, the Diamond Model for **relationships**, and the Pyramid of Pain for **indicator value**.

## Quick Workflow

1. Place observed activity on a phase model (CKC or UKC)
2. Map behaviors to ATT&CK techniques
3. Build Diamond events and pivot to find related activity
4. Choose courses of action per phase, prioritizing the top of the Pyramid of Pain

---

## 1. Lockheed Martin Cyber Kill Chain

| Phase | Attacker goal | Defender data |
|---|---|---|
| 1 Reconnaissance | Learn targets | Web logs, EASM, honeypots, social media exposure |
| 2 Weaponization | Build payload | Malware analysis, intel on builders (no direct visibility) |
| 3 Delivery | Transmit | Email gateway, proxy, USB, WAF |
| 4 Exploitation | Trigger code | EDR, app logs, exploit protection |
| 5 Installation | Persist | EDR, autoruns, FIM |
| 6 Command & Control | Remote control | DNS, proxy, NDR |
| 7 Actions on Objectives | Steal, encrypt, destroy | DLP, file activity, backups |

### Courses of Action Matrix

| Phase | Detect | Deny | Disrupt | Degrade | Deceive | Destroy* |
|---|---|---|---|---|---|---|
| Recon | Web analytics, honeypot hits | Minimize exposure | — | — | Fake employee pages | — |
| Delivery | Gateway/IDS | Block attachments, URL filtering | Inline AV | Queuing | Honey mailboxes | — |
| Exploitation | EDR | Patch, app control | Exploit mitigation (DEP/ASR) | — | — | — |
| Installation | EDR/FIM | Least privilege | AV quarantine | — | — | — |
| C2 | NDR/DNS | Egress firewall | DNS sinkhole | Throttle | Honey C2 responses | — |
| Actions | DLP, audit | ACLs, encryption | Isolation | Rate limits | Honey files/canaries | — |

*Destroy (offensive action) is generally reserved for authorized government entities — defenders focus on the other five.

Insight: the attacker must succeed at **every** phase; the defender needs to break **one**. Earlier breaks are cheaper; later detections are often more reliable.

---

## 2. Unified Kill Chain (Pols)

18 phases in 3 stages — better for modern, identity-heavy, multi-hop intrusions:

| Stage | Phases |
|---|---|
| In (initial foothold) | Reconnaissance, Resource Development, Delivery, Social Engineering, Exploitation, Persistence, Defense Evasion, Command & Control |
| Through (network propagation) | Pivoting, Discovery, Privilege Escalation, Execution, Credential Access, Lateral Movement |
| Out (action on objectives) | Collection, Exfiltration, Impact, Objectives |

Phases can repeat (each new host is a new "In").

---

## 3. Diamond Model

Every intrusion event has four vertices:

```text
            Adversary
           /         \
 Infrastructure ——— Capability
           \         /
             Victim
```

Meta-features: timestamp, phase, result, direction, methodology, resources.

**Pivoting:** from one vertex find others — e.g., C2 IP (infrastructure) → passive DNS → other domains → other victims; malware hash (capability) → VirusTotal relationships → related infrastructure. **Activity threads** chain events across phases; **activity groups** cluster threads by shared features (basis for actor tracking).

---

## 4. Pyramid of Pain (Bianco)

| Level (bottom → top) | Pain to adversary when you detect/deny it |
|---|---|
| Hash values | Trivial (recompile) |
| IP addresses | Easy |
| Domain names | Simple |
| Network/host artifacts | Annoying (URI patterns, registry keys, UAs) |
| Tools | Challenging (must change/rebuild tooling) |
| TTPs | Tough (must change behavior) |

Prioritize detections on tools and TTPs; use atomic IOCs for fast blocking and retro-hunting only. MITRE CTID "Summiting the Pyramid" scores analytic robustness (resistance to evasion).

---

## 5. ICS Cyber Kill Chain (SANS, Assante & Lee)

Stage 1: IT intrusion (recon → actions, targeting OT access). Stage 2: ICS attack development & execution (develop, test, deliver, install/modify, execute ICS attack). Long dwell time between stages = detection window in the IT/OT DMZ.

---

## 6. Combining Models (report structure)

| Section | Model |
|---|---|
| Timeline by phase | CKC / UKC |
| Behaviors | ATT&CK technique IDs |
| Actor/infrastructure relationships | Diamond events + pivots |
| Detection gaps & priorities | Pyramid of Pain level of each detection |
| Countermeasures | CoA matrix + D3FEND (`defensive-d3fend-countermeasures`) |

---

## Engagement Cheatsheet

```text
phase (CKC 7 / UKC 18) → ATT&CK behaviors → Diamond events + pivots (infra ↔ capability ↔ victim)
→ CoA matrix (detect/deny/disrupt/degrade/deceive) per phase → favor tools/TTPs over hashes/IPs → report by model
```

---

## Key References

- Hutchins, Cloppert, Amin — "Intelligence-Driven Computer Network Defense…" (Lockheed Martin, 2011)
- Paul Pols — The Unified Kill Chain; Caltagirone, Pendergast, Betz — Diamond Model (2013)
- David Bianco — Pyramid of Pain (2013); SANS ICS Cyber Kill Chain (2015)
- Related: `defensive-attack-mapping`, `defensive-cti`, `defensive-threat-informed-defense`, `defensive-d3fend-countermeasures`
