---
name: defensive-active-defense
description: "Active defense and adversary engagement within legal bounds: Sliding Scale of Cyber Security (architecture, passive defense, active defense, intelligence, offense), MITRE Engage framework (strategic and engagement actions, goals Expose/Affect/Elicit, approaches Collect/Detect/Prevent/Direct/Disrupt/Reassure/Motivate), active defense cycle, deception operations, honeytokens, attacker-cost tactics (tarpits, sinkholes, dynamic blocking), automated containment, hack-back legal boundaries, rules of engagement, and measuring engagement outcomes. Use when planning active defense, adversary engagement, or explaining the difference between active defense and offensive action."
---

# Active Defense & Adversary Engagement

Active defense means **analysts actively monitoring, responding to, and learning from adversaries inside your own environment** — not attacking back. Every action stays on infrastructure you own or are authorized to operate.

## Quick Workflow

1. Confirm foundations: architecture and passive defense are in place
2. Define engagement goals (expose, affect, elicit) and rules of engagement with legal sign-off
3. Deploy engagement activities (deception, monitoring, dynamic response)
4. Collect intelligence; feed detections and hardening
5. Measure outcomes; retire or evolve activities

---

## 1. Sliding Scale of Cyber Security (Robert M. Lee)

| Category | Description | Investment logic |
|---|---|---|
| Architecture | Systems built and maintained securely | Foundation; highest ROI |
| Passive Defense | Systems added to defend without constant human interaction (FW, AV, IDS) | Built on architecture |
| Active Defense | Analysts monitoring, responding to, learning from adversaries internal to the network | Requires mature passive layer |
| Intelligence | Collecting, exploiting data to produce intelligence on adversaries | Informs all layers |
| Offense | Legal countermeasures and self-defense actions against adversary outside the network | Nation-state/authorized only |

---

## 2. MITRE Engage

| Element | Content |
|---|---|
| Strategic actions | Prepare (plan, define objectives, RoE) and Understand (analyze results, lessons learned) |
| Engagement goals | **Expose** adversaries, **Affect** their operations, **Elicit** information about them |
| Engagement approaches | Collect, Detect (Expose); Prevent, Direct, Disrupt (Affect); Reassure, Motivate (Elicit) |
| Engagement activities | Lures, honeytokens, decoy systems/accounts/credentials, network manipulation, software manipulation, isolation, monitoring |

Engage replaced MITRE Shield and maps engagement activities to ATT&CK adversary vulnerabilities (things attackers must do that defenders can exploit).

---

## 3. Active Defense Cycle

```text
Threat intel consumption → asset identification & network security monitoring → incident response / engagement → threat & environment manipulation → (back to intel)
```

---

## 4. Activities (in-bounds)

| Activity | Purpose | Example |
|---|---|---|
| Honeytokens | Expose | Fake AWS keys, honey users/SPNs, canary documents |
| Decoy systems | Expose / Elicit | Fake file server, fake jump host |
| Breadcrumbs | Direct | Fake credentials in LSASS/cmdkey/RDP history pointing to decoys |
| DNS sinkhole | Disrupt | Redirect C2 domains to internal sinkhole for victim identification |
| Tarpits | Affect | Slow SSH/SMTP tarpits (e.g., endlessh) on unused IPs |
| Dynamic blocking | Disrupt | SOAR blocks IP/domain/account on high-confidence detection |
| Session manipulation | Affect | Kill sessions, force reauth, rotate creds mid-intrusion |
| Controlled monitoring | Elicit | Watch (don't evict yet) to scope full access — with leadership approval and risk acceptance |

---

## 5. Rules of Engagement (template)

```text
Objective: <expose lateral movement in finance segment>
Scope: <owned assets, subnets, accounts>
Authorized actions: <deploy decoys, sinkhole, monitor, isolate>
Prohibited: accessing, scanning, or disrupting third-party/attacker infrastructure; deploying malware; deceiving law enforcement
Approval: <CISO + legal + business owner>
Data handling: <how attacker-collected data is stored; privacy review>
Abort criteria: <risk to production, data exfil observed, safety (OT)>
Review: <date>
```

---

## 6. Legal Boundaries

- **Hack-back** (accessing systems you don't own) is generally illegal for private entities (e.g., US CFAA, Philippine Cybercrime Prevention Act RA 10175, UK Computer Misuse Act). Report to law enforcement/CERT instead.
- Takedowns go through registrars, hosting providers, and abuse channels.
- Deception on your own systems is lawful in most jurisdictions; review privacy implications (decoys may capture employee data).

---

## 7. Measuring

| Metric | Meaning |
|---|---|
| Time from decoy interaction to containment | Detection speed |
| Unique TTPs elicited | Intelligence value |
| Detections created from engagement findings | Feedback into passive defense |
| False interaction rate | Decoy hygiene (admins/scanners touching decoys) |

---

## Engagement Cheatsheet

```text
architecture + passive first → Engage goals (expose/affect/elicit) + RoE + legal → honeytokens/decoys/breadcrumbs/sinkhole/tarpit/dynamic block
→ collect intel → new detections/hardening → metrics → never touch infrastructure you don't own
```

---

## Key References

- Robert M. Lee, "The Sliding Scale of Cyber Security" (SANS, 2015)
- MITRE Engage (engage.mitre.org)
- Related: `defensive-deception`, `defensive-soar-automation`, `defensive-cti`, `defensive-kill-chain-defense`
