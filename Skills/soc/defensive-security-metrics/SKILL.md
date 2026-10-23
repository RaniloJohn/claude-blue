---
name: defensive-security-metrics
description: "Security metrics, KPIs, KRIs, and reporting: SOC operational metrics (MTTD, MTTA, MTTR/MTTC, dwell time, alert volume, true/false positive rates, escalation rate, automation rate), detection engineering metrics (ATT&CK coverage validated, rule health), vulnerability metrics (SLA compliance, KEV exposure window, mean time to remediate), identity metrics (MFA coverage, phishing-resistant share, privileged accounts), awareness metrics (report rate vs click rate), resilience metrics (restore test success, RTO achieved), board-level KRIs, NIST SP 800-55 guidance, dashboard design, SPL/KQL examples, and avoiding vanity metrics. Use when defining, calculating, or reporting security metrics."
---

# Security Metrics

Good metrics change decisions. Report **outcomes and risk** to leadership, **operations** to managers, and **quality** to engineers. Every metric needs a definition, data source, owner, target, and the action taken when it's off target.

## Quick Workflow

1. Identify audience and decision each metric supports
2. Define precisely (formula, scope, exclusions, data source)
3. Automate collection from SIEM/case/vuln/IdP systems
4. Set targets and thresholds; trend over time, not snapshots
5. Review quarterly; retire metrics nobody acts on

---

## 1. SOC Operations

| Metric | Definition |
|---|---|
| MTTD | Mean time from first malicious activity (or earliest evidence) to detection |
| MTTA | Mean time from alert creation to analyst acknowledgement |
| MTTC | Mean time from detection to containment |
| MTTR | Mean time from detection to resolution/recovery (define which) |
| Dwell time | First malicious activity → containment (incident-level, from IR findings) |
| Alert volume per analyst per shift | Workload / burnout indicator |
| True positive rate | TP / (TP + FP) per rule and overall |
| Escalation rate | L1 → L2 escalations / alerts triaged |
| Automation rate | Alerts fully or partly handled by SOAR / total |
| Reopen rate | Cases reopened after closure (quality) |
| SLA attainment | % cases meeting triage/containment SLA by severity |

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| extend TTA = datetime_diff('minute', FirstModifiedTime, CreatedTime), TTC = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize Incidents = count(), MTTA_min = avg(TTA), MTTC_hr = avg(TTC)/60.0,
            TP = countif(Classification == "TruePositive"), FP = countif(Classification == "FalsePositive") by Severity
| extend TP_Rate = round(100.0 * TP / (TP + FP), 1)
```

```spl
`notable` | search status_label=Closed earliest=-30d
| eval tta=(time_of_first_review - _time)/60, ttc=(closed_time - _time)/3600
| stats count avg(tta) as mtta_min avg(ttc) as mttc_hr by urgency
```

(Field names vary by ES version/case tool — map to your data.)

---

## 2. Detection Engineering

| Metric | Definition |
|---|---|
| Prioritized technique coverage | % of prioritized ATT&CK techniques with validated detection (score ≥ 3, see `defensive-threat-informed-defense`) |
| Detections with tests | % rules with automated test/emulation |
| Rule health | Rules erroring, silent for 30+ days, or broken by log source changes |
| FP rate per rule | Top 10 noisiest rules (tuning backlog) |
| Time to deploy detection for new threat | Intel received → rule in production |
| Log source health | % critical sources reporting within expected interval |

---

## 3. Vulnerability & Exposure

| Metric | Definition |
|---|---|
| SLA compliance | % vulns remediated within SLA by severity/tier |
| KEV exposure window | Days from KEV listing to remediation for affected assets |
| MTTR (vulns) | Mean days from detection to fix |
| Internet-facing critical exposure | Count of exploitable critical vulns on external assets (target 0) |
| Scan coverage | % assets scanned in last 30 days |
| Unsupported software/assets | Count/percentage EoS systems |

---

## 4. Identity, Endpoint, People, Resilience

| Area | Metrics |
|---|---|
| Identity | MFA coverage %, phishing-resistant MFA % (admins: target 100%), standing privileged accounts, stale accounts, legacy auth sign-ins |
| Endpoint | EDR coverage %, sensors healthy %, devices compliant %, local admin rights % |
| People | Phishing simulation **report rate** and time-to-first-report (more useful than click rate), training completion |
| Resilience | Backup success %, restore test success %, actual vs target RTO for crown jewels, tabletop actions closed |
| Third party | Critical vendors assessed %, vendor incidents |

---

## 5. Board-Level KRIs

| KRI | Example threshold |
|---|---|
| Critical internet-facing vulns open > SLA | > 0 = red |
| Privileged accounts without phishing-resistant MFA | > 0 = red |
| EDR coverage of servers | < 98% = amber |
| Crown jewel restore tested in last 12 months | No = red |
| SEV1 incidents this quarter + business impact | Trend + narrative |
| Top risks vs appetite | Risk register heatmap |

Translate to business terms: "Ransomware on finance systems: likelihood reduced from high to medium after X; residual risk accepted by CFO."

---

## 6. Pitfalls

- **Vanity metrics:** "blocked 10 million attacks" (firewall drops), raw alert counts
- **Goodhart's law:** targets on MTTC can push premature closure — pair speed with quality (reopen rate, peer review)
- Averages hide tails — report median and p90
- Changing definitions silently breaks trends — version metric definitions
- Measuring activity instead of outcomes

---

## 7. Dashboard Layout

Executive (quarterly): 5–7 KRIs, trend arrows, top risks, major incidents. Management (monthly): SLAs, coverage, backlogs, staffing. Operational (daily): queue, SLA timers, log source health, noisy rules.

---

## Engagement Cheatsheet

```text
audience → decision → precise definition + source + owner + target → automate (KQL/SPL/APIs) → median + p90 trends
→ SOC (MTTD/MTTA/MTTC/TP rate/automation) + DE (validated coverage, rule health) + vuln (SLA, KEV window) + identity/endpoint/people/resilience
→ board KRIs in business terms → avoid vanity/Goodhart
```

---

## Key References

- NIST SP 800-55 (Measurement Guide for Information Security, Vol 1 & 2); CIS Controls measures; SANS SOC Survey
- Related: `defensive-soc-building`, `defensive-security-operating-model`, `defensive-vuln-management`, `defensive-threat-informed-defense`
