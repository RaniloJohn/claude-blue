---
name: defensive-soc-playbooks
description: "Authoring SOC playbooks and runbooks: decision trees, containment authority matrices, escalation paths, communication plans, RACI, and SLA definitions. Use when writing or reviewing an incident playbook (phishing, malware, ransomware, BEC, account compromise, data exfiltration, insider, DDoS, cloud key leak), converting tribal knowledge into runbooks, designing SOC tiering and shift handover, defining metrics (MTTD, MTTA, MTTC, MTTR), or aligning to NIST SP 800-61r3 / CSF 2.0 and CISA federal IR playbooks."
---

# SOC Playbooks & Runbooks

A playbook is a decision tree with owners. A runbook is the exact procedure for one step. Write playbooks for decisions, runbooks for keystrokes.

## Quick Workflow

1. Pick incident type and trigger conditions
2. Define scope boundaries (what this playbook does not cover)
3. Build decision tree: triage → scope → contain → eradicate → recover → lessons
4. Attach RACI and containment authority
5. Link runbooks per action
6. Define comms and notification obligations
7. Table-top, then measure

---

## 1. Playbook Template

```markdown
# Playbook: <Incident Type>
Version: <x.y>  Owner: <role>  Last tested: <date>  Review: quarterly

## Trigger
- Alerts/rules: <ids>
- Reports: <user report channels>

## Scope
In: <...>  Out: <...> (→ link other playbook)

## Severity mapping
| Condition | Severity |

## Decision tree
1. Triage → [criteria] → close | continue
2. Scope → entities, blast radius
3. Contain → options ranked by impact; who approves
4. Eradicate → persistence removal, credential rotation
5. Recover → restore, monitor window
6. Post-incident → lessons, detection gaps

## Containment authority
| Action | L1 | L2 | IR Lead | Business owner |

## Evidence to preserve
## Communications
| Audience | When | Channel | Owner |

## Legal/regulatory notifications
## Runbook links
## Metrics captured
```

---

## 2. NIST SP 800-61r3 Alignment

Rev. 3 (April 2025) maps IR to CSF 2.0 functions rather than the old four-phase loop:

| CSF 2.0 function | IR activities |
|---|---|
| Govern (GV) | IR policy, roles, authority, regulatory obligations |
| Identify (ID) | Asset inventory, risk assessment, lessons-learned improvements |
| Protect (PR) | Hardening that reduces incident likelihood/impact |
| Detect (DE) | Monitoring, adverse event analysis |
| Respond (RS) | Incident management, analysis, mitigation, reporting, communication |
| Recover (RC) | Restoration, recovery communication |

---

## 3. Containment Authority Matrix (example)

| Action | L1 | L2 | IR Lead | CISO | Business owner |
|---|---|---|---|---|---|
| Block hash/domain/IP (low prevalence) | ✓ | ✓ | ✓ | | |
| Isolate workstation | | ✓ | ✓ | | inform |
| Isolate server | | | ✓ | inform | approve |
| Disable standard user | | ✓ | ✓ | | inform |
| Disable privileged/service account | | | ✓ | inform | approve |
| Revoke all sessions tenant-wide | | | | ✓ | |
| `krbtgt` double reset | | | | ✓ | AD owner |
| Take internet-facing service offline | | | | ✓ | approve |

Pre-approve L1/L2 actions in writing; uncertainty at 03:00 costs hours.

---

## 4. Core Playbook Set

| Playbook | Key decisions |
|---|---|
| Phishing (reported/detected) | Clicked? Credentials entered? Payload executed? Org-wide purge? |
| Malware on endpoint | Executed? Persistence? Lateral? Reimage vs clean? |
| Account compromise (on-prem) | Privileged? Sessions? Kerberos tickets? Password + token reset |
| Cloud identity compromise | Sessions/tokens, OAuth grants, MFA methods added, inbox rules |
| BEC / payment fraud | Financial recall window, bank contact, mailbox rules |
| Ransomware | Isolate segments, protect backups, encryption scope, extortion/legal |
| Data exfiltration | What data, how much, where, notification obligations |
| Cloud access key leak | Key deactivation, CloudTrail scope, resources created |
| Insider threat | HR/legal involvement, covert evidence preservation |
| DDoS | Upstream/scrubbing provider, rate limiting, comms |
| Vulnerability actively exploited (KEV) | Exposure check, compromise assessment, mitigate/patch |
| Supply chain compromise (package/CI) | Affected versions, secrets rotation, rebuild |

---

## 5. Notification Obligations (verify per jurisdiction)

| Regime | Trigger | Timeline |
|---|---|---|
| GDPR (EU) | Personal data breach | 72 h to supervisory authority |
| NIS2 (EU) | Significant incident (essential/important entities) | Early warning 24 h, notification 72 h, final report 1 month |
| EU CRA (manufacturers) | Actively exploited vuln / severe incident in product | Early warning 24 h, notification 72 h; applies since 11 Sep 2026 via ENISA SRP |
| SEC (US public cos.) | Material cybersecurity incident | Form 8-K Item 1.05 within 4 business days of materiality determination |
| CIRCIA (US critical infra) | Covered incidents / ransom payments | 72 h / 24 h once final rule effective — verify status |
| Philippines Data Privacy Act | Personal data breach | 72 h to NPC |
| PCI DSS | Cardholder data compromise | Per card brand rules |

Legal decides; SOC preserves evidence and timelines that make the decision possible.

---

## 6. Metrics

| Metric | Definition |
|---|---|
| MTTD | First malicious activity → detection |
| MTTA | Alert created → analyst acknowledged |
| MTTC | Detection → containment complete |
| MTTR | Detection → recovery complete |
| Dwell time | First malicious activity → eradication |
| Escalation accuracy | % L1 escalations confirmed by L2 |

Measure by incident type; averages across types hide everything.

---

## 7. Shift Handover

```text
Open incidents: <id, severity, owner, next action, deadline>
Pending approvals: <action, approver, since>
Watches: <entities under monitoring, until when>
Degraded telemetry: <source, impact, ticket>
New suppressions added: <rule, scope, expiry>
```

---

## 8. Table-Top Exercises

- Quarterly, rotating playbooks
- Inject realistic constraints: on-call unreachable, backups encrypted, legal needs answer in 2 h
- Output: action items with owners, playbook updates, detection gaps

---

## Engagement Cheatsheet

```text
Trigger → Scope → Severity → Decision tree → Authority matrix → Evidence list
→ Comms table → Notifications → Runbook links → Metrics → Test date
```

---

## Key References

- NIST SP 800-61r3 (April 2025), NIST CSF 2.0
- CISA Federal Government Cybersecurity Incident & Vulnerability Response Playbooks
- SANS Incident Handler's Handbook
- NIS2 Directive Art. 23; EU CRA Art. 14
- Related: `defensive-incident-response`, `defensive-soar-automation`, `defensive-ir-reporting`
