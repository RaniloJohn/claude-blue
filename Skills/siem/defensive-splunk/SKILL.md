---
name: defensive-splunk
description: "Splunk security operations: data onboarding with Technology Add-ons (Windows, Sysmon, Linux, Zeek, Suricata, AWS, Microsoft cloud), props/transforms, Common Information Model (CIM) normalization, accelerated data models and tstats, Enterprise Security (ES 8) detections and Mission Control, risk-based alerting (RBA) risk rules and risk incident rules, notable events, lookups and KV store, Splunk Security Content (ESCU) detections, SPL performance, and Splunk SOAR handoff. Use when building or tuning Splunk SIEM content or investigating in Splunk."
---

# Splunk for Security

Splunk's power is SPL plus accelerated, CIM-normalized data models. Detections written against data models survive sourcetype changes; detections written against raw fields do not.

## Quick Workflow

1. Install correct TAs on search heads, indexers, and forwarders
2. Validate CIM compliance (CIM Validator / datamodel searches)
3. Accelerate key data models (Endpoint, Authentication, Network_Traffic, Web, Change)
4. Write detections with `tstats` against data models
5. Use RBA: many low-fidelity risk rules → few high-fidelity risk incidents
6. Measure and tune

---

## 1. Onboarding

| Source | TA | Notes |
|---|---|---|
| Windows Event Logs | Splunk Add-on for Microsoft Windows | Use `renderXml=true`; sourcetype `XmlWinEventLog` |
| Sysmon | Splunk Add-on for Sysmon | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Linux | Splunk Add-on for Unix and Linux | auditd via `linux:audit` |
| Zeek / Suricata | Corelight / Suricata TAs | JSON |
| AWS | Splunk Add-on for AWS | CloudTrail via SQS-based S3 |
| Microsoft cloud | Splunk Add-on for Microsoft Cloud Services / Microsoft Security | Entra, Defender |

`inputs.conf` (UF on Windows):

```ini
[WinEventLog://Security]
renderXml = true
blacklist1 = EventCode="5156|5158"
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
renderXml = true
index = sysmon
```

---

## 2. CIM & Data Models

| Data model | Detections |
|---|---|
| Endpoint (Processes, Filesystem, Registry, Services) | Execution, persistence |
| Authentication | Brute force, spray, anomalous logon |
| Network_Traffic / Network_Resolution (DNS) | C2, exfil, tunneling |
| Web | Proxy, web attacks |
| Change | Account/group changes, cloud config changes |
| Email | Phishing |

```spl
| tstats summariesonly=true count from datamodel=Authentication
  where Authentication.action=failure by Authentication.src Authentication.user _time span=5m
| `drop_dm_object_name(Authentication)`
| stats dc(user) as users sum(count) as failures by src _time
| where users > 15
```

---

## 3. Enterprise Security (ES 8)

- ES 8 unifies detection management and Mission Control (investigation/response) in one UI; findings and investigations replace older notable-event workflow terminology
- Detections = saved searches with adaptive response actions (create finding, add risk, run SOAR playbook)
- Asset & Identity framework: enrich with criticality, owner, priority — feed it from CMDB/IdP

---

## 4. Risk-Based Alerting (RBA)

```spl
# Risk rule: assign risk, don't alert
| tstats summariesonly=true count from datamodel=Endpoint.Processes
  where Processes.process_name="certutil.exe" Processes.process IN ("*urlcache*","*-decode*")
  by Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
| eval risk_score=40, risk_object=dest, risk_object_type="system",
       risk_message="certutil download/decode on ".dest
```

Risk incident rule (alerts):

```spl
| tstats summariesonly=true sum(All_Risk.calculated_risk_score) as score
  dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactics
  dc(source) as sources
  from datamodel=Risk.All_Risk by All_Risk.risk_object All_Risk.risk_object_type
| `drop_dm_object_name(All_Risk)`
| where score > 100 AND tactics >= 3
```

RBA cuts alert volume by aggregating weak signals per entity; tune scores by asset/identity priority.

---

## 5. Splunk Security Content (ESCU)

- research.splunk.com — hundreds of detections with SPL, ATT&CK, data requirements, and tests (attack_data)
- Install via ESCU app; enable only where `required_fields` exist

---

## 6. SPL Performance Rules

1. Specify `index` and `sourcetype` always
2. `tstats` over accelerated data models first
3. Filter before `stats`; avoid `*` leading wildcards
4. `stats` over `transaction`/`join`
5. `fields` early to reduce data moved
6. Lookups: `| lookup` with CSV/KV store; `inputlookup` for allowlists

---

## 7. Investigation Snippets

```spl
# Process tree for a host in window
index=sysmon host=WS01 EventCode=1 earliest=-2h
| table _time ParentImage ParentCommandLine Image CommandLine User ProcessGuid ParentProcessGuid

# First-seen process per host (30 d)
index=sysmon EventCode=1 earliest=-30d
| stats earliest(_time) as first by host Image
| where first > relative_time(now(), "-24h")

# DNS: rare domains
index=dns earliest=-7d | stats count dc(src) as clients by query
| where clients=1 AND count<5
```

---

## Engagement Cheatsheet

```text
TAs → CIM validate → accelerate DMs → tstats detections → RBA risk rules
→ risk incident rules → asset/identity enrichment → ESCU coverage → tune
```

---

## Key References

- Splunk Security Content — https://research.splunk.com
- Splunk CIM documentation; Splunk ES 8 docs
- Splunk SURGe PEAK hunting framework
- Related: `defensive-query-languages`, `defensive-sigma`, `defensive-threat-hunting`
