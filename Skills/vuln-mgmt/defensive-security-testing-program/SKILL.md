---
name: defensive-security-testing-program
description: "Running a security testing program from the defender side: choosing test types (vulnerability scanning, penetration testing, red team, purple team, application security testing, cloud configuration review, social engineering, physical, threat-led penetration testing like TIBER-EU/DORA TLPT, bug bounty and vulnerability disclosure), scoping and rules of engagement, vendor selection and qualifications, authorization letters, safety controls during testing, findings triage and retesting, remediation SLAs, metrics, and how results feed detection engineering. Use when planning, procuring, or managing security assessments and tests."
---

# Security Testing Program

Testing is only valuable if findings get fixed and detections improve. Plan tests around **risk and threat models**, manage them safely, and close the loop.

## Quick Workflow

1. Annual test plan driven by risk (crown jewels, recent changes, regulatory needs)
2. Pick test type per objective (§1)
3. Scope + rules of engagement + authorization (§2)
4. Monitor during testing (detections, safety)
5. Triage findings → remediation with SLAs → retest
6. Feed misses into detection engineering and architecture

---

## 1. Test Types

| Type | Answers | Frequency |
|---|---|---|
| Vulnerability scanning (authenticated) | What known weaknesses exist? | Continuous / weekly |
| External attack surface testing | What's exposed and exploitable from internet? | Quarterly + after changes |
| Network/internal pentest | Can an attacker with a foothold reach crown jewels? | Annual |
| Application pentest / AppSec review | Are apps/APIs vulnerable (OWASP Top 10:2025, API Top 10)? | Before major releases |
| Cloud configuration review | Misconfigurations/IAM escalation paths? | Annual + CSPM continuous |
| Red team (objective-based, stealthy) | Can we detect and respond to a realistic adversary? | Annual for mature orgs |
| Purple team | Do detections work for specific TTPs? | Quarterly (`defensive-purple-team`) |
| Social engineering (phishing, vishing, help desk) | Are people and processes resilient? | Quarterly simulations |
| Physical | Can someone enter and plug in? | As needed |
| Threat-led (TIBER-EU, DORA TLPT, CBEST) | Regulator-recognized intelligence-led testing | Per regulation (e.g., every 3 years for in-scope DORA entities) |
| Bug bounty / VDP | Continuous external researcher findings | Ongoing |

---

## 2. Scoping & Rules of Engagement

| Element | Content |
|---|---|
| Objectives | E.g., "obtain read access to customer DB from a phished workstation" |
| In scope / out of scope | IP ranges, apps, cloud accounts, users; exclusions (production payment processing, safety systems) |
| Methods allowed/forbidden | Social engineering? DoS? Data exfil (simulated with canary data)? |
| Timing | Windows, blackout periods |
| Contacts | 24×7 emergency contacts both sides; stop-test word |
| Data handling | Encryption of findings, destruction after engagement |
| Authorization | Signed letter from system owner with authority (and third parties: cloud provider policies, MSPs) |
| Deconfliction | White cell knows; SOC may or may not (red team) — process to verify "is this the test?" |

---

## 3. Vendor Selection

Look for: relevant certifications (OSCP/OSEP/OSWE, GXPN, CREST/CHECK accreditation where required), sample reports, methodology (PTES, OWASP WSTG, NIST SP 800-115), insurance, data handling, references, retest included, no "scanner-only" pentests.

---

## 4. During Testing

- SOC monitors: record detections/alerts with timestamps for later comparison
- Safety: stop conditions (production impact, real attacker discovered), daily check-ins for long engagements
- Real incidents found during testing → switch to IR

---

## 5. Findings to Fixes

| Step | Practice |
|---|---|
| Triage | Validate severity in your context (CVSS v4 + exposure + compensating controls) |
| Assign | Owner + SLA (e.g., critical 7–14 days, high 30, medium 90) |
| Root cause | Fix classes of issues (e.g., missing authorization checks in framework) not just instances |
| Detection gaps | Every successful TTP without alert → detection backlog item |
| Retest | Vendor or internal verification; close with evidence |
| Report | Trends across tests; repeat findings escalate |

---

## 6. Vulnerability Disclosure

Publish a VDP and `/.well-known/security.txt` (RFC 9116) with contact, policy, and safe-harbor language; triage reports within defined SLAs; consider bug bounty once VDP process is mature.

---

## Engagement Cheatsheet

```text
risk-driven annual plan → type per objective (scan/EASM/pentest/appsec/cloud/red/purple/SE/physical/TLPT/VDP) → scope + RoE + signed authorization + deconfliction
→ SOC records detections during test → triage (context) → owners + SLAs + root-cause fixes → detection gaps → retest → trend reporting
```

---

## Key References

- NIST SP 800-115; PTES; OWASP WSTG; TIBER-EU framework; EU DORA TLPT RTS; RFC 9116 (security.txt); CREST
- Related: `defensive-purple-team`, `defensive-vuln-management`, `defensive-tool-dast-scanners`, `defensive-tool-emulation`, `defensive-threat-informed-defense`
