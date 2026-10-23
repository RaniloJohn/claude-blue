---
name: defensive-ueba
description: "User and entity behavior analytics and risk-based alerting: baselining users, hosts, service accounts, and applications; peer group analysis; statistical methods (z-score, median absolute deviation, percentiles, first-seen/rare, entropy, time-of-day), risk scoring and aggregation (Splunk RBA risk index, Sentinel UEBA BehaviorAnalytics and IdentityInfo, Elastic ML anomaly jobs and entity risk scoring), insider and account compromise use cases, tuning to avoid noise, explainability, privacy considerations, and SPL/KQL/ES|QL query patterns. Use when building behavior-based detections, risk-based alerting, or evaluating UEBA."
---

# UEBA & Risk-Based Alerting

Signature rules catch known-bad. Behavior analytics catch **unusual for this entity** — the compromised account that logs in from a new country at 3 a.m. and reads 4,000 files. Risk-based alerting (RBA) turns many weak signals into one strong alert.

## Quick Workflow

1. Define entities (user, host, service account, app, IP) and resolve identities (UPN ↔ SAM ↔ email ↔ device)
2. Build baselines (30–90 days) per entity and per peer group
3. Score deviations; attach risk to entities instead of alerting directly
4. Alert when aggregated risk crosses a threshold within a window
5. Tune with feedback; explain every alert (which behaviors contributed)

---

## 1. Methods

| Method | Use | Example |
|---|---|---|
| First-seen | New behavior for entity | First login from country/ASN/device; first use of a process |
| Rare (fleet prevalence) | Uncommon globally | Process seen on < 3 hosts |
| Z-score / MAD | Volume anomalies | Files accessed today vs 30-day mean/median |
| Percentile thresholds | Robust to outliers | > p99 of user's daily bytes uploaded |
| Peer group | Compare to similar users | Finance user accessing engineering repos |
| Time-of-day | Unusual hours for this user | Activity outside user's usual 08–19 window |
| Sequence | Ordered behaviors | MFA reset → new device → mailbox rule within 1 h |
| Entropy | Randomness | DGA domains, encoded commands |

MAD is preferable to standard deviation for skewed security data: `score = (x − median) / (1.4826 × MAD)`.

---

## 2. Risk-Based Alerting (Splunk ES pattern)

```spl
| tstats summariesonly=t count from datamodel=Authentication where Authentication.action=success by Authentication.user Authentication.src _time span=1h
| ... detection logic ...
| eval risk_object=user, risk_object_type="user", risk_score=30, risk_message="First login from new country ".country
| collect index=risk
```

Risk incident rule:

```spl
index=risk earliest=-24h
| stats sum(risk_score) as total dc(source) as detections values(risk_message) as reasons dc(annotations.mitre_attack.mitre_tactic) as tactics by risk_object
| where total >= 100 AND (detections >= 3 OR tactics >= 2)
```

Weight: low-fidelity signals 10–25, medium 40–60, high 80+; multiply for crown-jewel users/assets.

---

## 3. Microsoft Sentinel UEBA

| Table | Content |
|---|---|
| `BehaviorAnalytics` | Enriched activities with `ActivityInsights` (first time user connected from country, uncommon ISP, etc.) and `InvestigationPriority` |
| `IdentityInfo` | Identity attributes (department, manager, roles, groups) for peer context |
| `UserPeerAnalytics` | Peer rankings |
| `Anomalies` | Output of anomaly rules |

```kql
BehaviorAnalytics
| where TimeGenerated > ago(1d) and InvestigationPriority >= 5
| extend Insights = todynamic(ActivityInsights)
| project TimeGenerated, UserPrincipalName, ActivityType, ActionType, SourceIPAddress, InvestigationPriority,
          FirstCountry = Insights.FirstTimeUserConnectedFromCountry, UncommonISP = Insights.ISPUncommonlyUsedAmongPeers
| order by InvestigationPriority desc
```

Custom baseline (no UEBA license):

```kql
let baseline = OfficeActivity | where TimeGenerated between (ago(31d) .. ago(1d)) and Operation == "FileDownloaded"
  | summarize Daily = count() by UserId, bin(TimeGenerated, 1d)
  | summarize Med = percentile(Daily, 50), P99 = percentile(Daily, 99) by UserId;
OfficeActivity | where TimeGenerated > ago(1d) and Operation == "FileDownloaded"
| summarize Today = count() by UserId
| join kind=inner baseline on UserId
| where Today > max_of(P99 * 3, 200)
```

---

## 4. Elastic

- ML anomaly detection jobs (security prebuilt: rare process by host, unusual login activity, high DNS volume, unusual data exfiltration)
- Entity risk scoring (hosts/users) aggregating alert risk scores
- ES|QL baseline example:

```esql
FROM logs-*
| WHERE event.category == "authentication" AND event.outcome == "success" AND @timestamp > NOW() - 30 days
| STATS countries = COUNT_DISTINCT(source.geo.country_iso_code), logins = COUNT(*) BY user.name
| WHERE countries > 3
```

---

## 5. Use Cases

| Scenario | Signals combined |
|---|---|
| Account takeover | New country/ASN + new device + MFA method added + inbox rule + mass download |
| Insider data theft | Resignation (HR feed) + unusual volume + USB/personal cloud upload + after-hours |
| Privilege misuse | Admin accessing HR/payroll data outside role; access to many mailboxes |
| Service account abuse | Interactive logon by service account; use from new host |
| Compromised host | Rare processes + new outbound destinations + credential access alert |

---

## 6. Tuning & Governance

- Exclude known travel (travel calendar), VPN egress IPs, shared service accounts (or baseline separately)
- Cold start: new users have no baseline — use peer group baselines for first 30 days
- Explainability: every alert lists contributing behaviors and baseline values
- Privacy: document purpose, minimize data, involve HR/legal for insider analytics, comply with local law (e.g., PH Data Privacy Act proportionality)

---

## Engagement Cheatsheet

```text
entities + identity resolution → 30–90d baselines (entity + peer) → first-seen/rare/MAD/percentile/time/sequence
→ risk scores to risk index (not alerts) → threshold on sum + distinct detections/tactics → crown-jewel multipliers
→ Sentinel BehaviorAnalytics / Elastic ML / custom KQL-SPL baselines → explainable alerts + privacy governance
```

---

## Key References

- Splunk Risk-Based Alerting (RBA) guidance; Microsoft Sentinel UEBA docs; Elastic Security ML & entity risk scoring
- Related: `defensive-threat-hunting`, `defensive-alert-triage`, `defensive-splunk`, `defensive-sentinel`
