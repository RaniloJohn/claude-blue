---
name: defensive-ir-reporting
description: "Incident and security reporting: executive summaries, technical incident reports, timelines, root cause analysis, impact statements, IOC appendices, lessons learned / post-incident reviews (blameless), regulatory notification drafts support, sitreps, and audience-specific writing (executives, legal, engineers, customers). Includes templates, confidence and estimative language, defanging, evidence referencing, and quality checklists. Use when writing any incident report, post-mortem, hunt report summary, or security briefing."
---

# IR Reporting

A report is the incident's permanent record and the basis for decisions (legal, regulatory, investment). Write for the reader: executives need impact and decisions; engineers need evidence and actions; lawyers need precise facts and uncertainty.

## Quick Workflow

1. Confirm audience(s) and purpose
2. Assemble facts with sources (timeline, scope, evidence IDs)
3. Write executive summary last, put it first
4. Separate facts, assessments (with confidence), and recommendations
5. Peer review for accuracy, tone, and privilege markings
6. Version and store with case

---

## 1. Report Structure

```markdown
# Incident Report — <ID> — <Title>
Classification: <TLP / Confidential / Privileged & Confidential — Prepared at direction of counsel (if applicable)>
Version: <x.y>  Date: <UTC>  Authors: <names>  Reviewers: <names>

## 1. Executive Summary (≤ 1 page)
- What happened (1–2 sentences, plain language)
- Impact (data, systems, business, customers) — known vs suspected
- Current status (contained / eradicated / recovered)
- Root cause (one sentence)
- Key decisions/asks for leadership

## 2. Scope & Impact
| Category | Affected | Confidence |
|---|---|---|
| Hosts | <n> | High |
| Accounts | <n> | High |
| Data | <types, volume, records> | Medium |
| Duration | first malicious activity → containment | High |

## 3. Timeline (UTC)
| Time | Event | Source/Evidence ID | ATT&CK |

## 4. Technical Analysis
- Initial access
- Execution & persistence
- Privilege escalation & credential access
- Lateral movement
- Collection & exfiltration
- Impact
(Each with evidence references and confidence)

## 5. Root Cause Analysis
- Direct cause, contributing factors, failed/absent controls (5 Whys)

## 6. Response Actions Taken
| Time | Action | Owner | Result |

## 7. Recommendations
| # | Recommendation | Risk addressed | Priority | Owner | Due |

## 8. Lessons Learned
- What went well / what didn't / detection gaps / process gaps

## Appendices
A. IOCs (defanged)  B. Evidence inventory & chain of custody  C. Detection rules added  D. Glossary
```

---

## 2. Executive Summary Example

> On 20 October 2026 an attacker used a phishing page that captured a finance employee's sign-in session, accessed the mailbox for 26 hours, and sent fraudulent payment instructions to two vendors. No payments were released; the bank recalled one transfer before settlement. The account was contained on 21 October 13:40 UTC. The attack succeeded because the account used push-based MFA, which this phishing technique bypasses. We recommend phishing-resistant MFA for finance and executive users by 15 December 2026 (est. cost: <x>).

---

## 3. Language Standards

| Do | Don't |
|---|---|
| "We assess with high confidence…" (state evidence) | "Clearly", "obviously", "definitely" without evidence |
| "No evidence of exfiltration was found in available logs (proxy, EDR, M365 UAL); DNS logs were not retained before 15 Oct" | "No data was stolen" (unless proven) |
| UTC ISO 8601 timestamps | Mixed local times |
| Defang IOCs: `hxxps://evil[.]example` | Live links |
| Name roles/systems | Blame individuals |
| Estimative terms consistently (likely 55–80%, highly likely 80–95%) | Vague "might", "possibly" everywhere |

---

## 4. Audiences

| Audience | Emphasize | Avoid |
|---|---|---|
| Board/executives | Business impact, risk, decisions, cost, trend | Tool names, raw logs |
| Legal/privacy | Precise facts, data categories/records, dates of awareness, uncertainty | Speculation |
| IT/engineering | Evidence, root cause, fixes, owners | Vague recommendations |
| Customers/regulators (via legal) | What happened, what data, what you're doing, what they should do | Technical jargon, attribution speculation |

---

## 5. Blameless Post-Incident Review

- Focus on systems and decisions, not individuals
- Timeline of decisions with information available at the time
- Identify: detection delay causes, decision bottlenecks, tooling gaps, playbook gaps
- Output: tracked action items with owners and dates; follow up in 30/60/90 days

---

## 6. Quality Checklist

```text
[ ] Executive summary readable standalone, no jargon
[ ] Every factual claim has an evidence reference
[ ] Facts vs assessments clearly separated; confidence stated
[ ] Times in UTC; time zone of sources noted
[ ] IOCs defanged; secrets/PII redacted
[ ] Recommendations specific, owned, dated, prioritized
[ ] Privilege/TLP markings correct; distribution list set
[ ] Peer-reviewed by someone not on the incident
```

---

## Engagement Cheatsheet

```text
audience → facts + sources → timeline → analysis by phase → RCA (5 Whys) → recommendations (owner/date)
→ exec summary (write last, place first) → language check → peer review → distribute with markings
```

---

## Key References

- NIST SP 800-61r3 (post-incident activities); SANS incident report guidance
- ICD 203 analytic standards (confidence/likelihood language)
- Google SRE book — blameless postmortem culture
- Related: `defensive-incident-response`, `defensive-timeline-analysis`, `defensive-cti`
