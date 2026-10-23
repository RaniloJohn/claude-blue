---
name: defensive-query-languages
description: "Security query language translation and optimization across SIEM/XDR platforms: Splunk SPL (tstats, datamodels, stats, transaction, streamstats), Microsoft KQL for Sentinel and Defender XDR advanced hunting (summarize, join, make_set, parse_json, series_decompose_anomalies), Elastic EQL (sequence, until, maxspan), ES|QL, Lucene/KQL (Kibana), Wazuh rule XML, Graylog query syntax, Google SecOps YARA-L/UDM search, and AWS Athena SQL over CloudTrail. Use when translating a detection between platforms, writing hunts, fixing slow queries, or explaining query output."
---

# Security Query Languages

Same logic, different dialects. Learn the operator map, then write each query so it filters early, aggregates late, and returns analyst-ready columns.

## Quick Workflow

1. Express logic in pseudocode / Sigma
2. Pick the narrowest index/table and time range
3. Filter on indexed fields first
4. Aggregate (`stats`/`summarize`/`STATS`)
5. Project only needed fields
6. Validate on known TP and known-noise windows

---

## 1. Operator Map

| Concept | SPL | KQL | ES\|QL | EQL | Lucene |
|---|---|---|---|---|---|
| Source | `index=x sourcetype=y` | `TableName` | `FROM logs-*` | `process where` | index pattern |
| Filter | `field=value` / `where` | `where` | `WHERE` | `and` | `field:value` |
| Contains | `field="*abc*"` | `has` (term) / `contains` | `LIKE "*abc*"` | `: "*abc*"` | `field:*abc*` |
| Case-insens. equal | default | `=~` | `TO_LOWER(x)==` | `:` | default (keyword dependent) |
| In list | `IN (a,b)` | `in~ (a,b)` | `IN (a,b)` | `in~ (a,b)` | `(a OR b)` |
| Regex | `regex f="..."` / `match()` | `matches regex` | `RLIKE` | `regex~` | `/regex/` |
| Count by | `stats count by f` | `summarize count() by f` | `STATS c=COUNT(*) BY f` | — | — |
| Distinct count | `dc(f)` | `dcount(f)` | `COUNT_DISTINCT(f)` | — | — |
| Values list | `values(f)` | `make_set(f)` | `VALUES(f)` | — | — |
| Time bucket | `bin _time span=1h` | `bin(TimeGenerated,1h)` | `BUCKET(@timestamp,1 hour)` | — | — |
| Join | `join` (avoid) / `stats` | `join kind=inner` | `LOOKUP JOIN` (recent) | `sequence by` | — |
| Sort/limit | `sort - c \| head 20` | `top 20 by c` | `SORT c DESC \| LIMIT 20` | `\| head 20` | — |

KQL performance: `has` uses the term index; `contains` scans. Prefer `has`, `has_any`, `has_all`.

---

## 2. Splunk SPL Patterns

```spl
# Fast: accelerated datamodel
| tstats summariesonly=true count min(_time) as first max(_time) as last
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("winword.exe","excel.exe")
        Processes.process_name IN ("powershell.exe","cmd.exe","mshta.exe")
  by Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`

# Rare parent-child pairs (stacking)
index=sysmon EventCode=1
| stats count dc(host) as hosts by ParentImage Image
| where count < 5 AND hosts < 3

# Beacon candidates: low interval variance
index=proxy
| sort 0 _time | streamstats current=f last(_time) as prev by src dest
| eval delta=_time-prev
| stats count avg(delta) as avg stdev(delta) as sd by src dest
| where count > 50 AND sd/avg < 0.1
```

Avoid `transaction` and `join` on large sets; use `stats` with `values()`/`min()`/`max()`.

---

## 3. KQL Patterns (Sentinel / Defender XDR)

```kql
// Defender XDR: Office spawning shells
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine, SHA256

// Process → network correlation
DeviceProcessEvents
| where FileName =~ "rundll32.exe" and ProcessCommandLine !has ".dll"
| join kind=inner (DeviceNetworkEvents | where RemoteIPType == "Public")
    on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, ProcessCommandLine, RemoteIP, RemoteUrl

// Anomaly on a time series
SigninLogs
| make-series c=count() default=0 on TimeGenerated from ago(14d) to now() step 1h by UserPrincipalName
| extend (anoms, score, baseline) = series_decompose_anomalies(c, 3)
| mv-expand TimeGenerated, c, anoms
| where toint(anoms) == 1
```

Key Defender tables: `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceLogonEvents`, `DeviceEvents`, `IdentityLogonEvents`, `IdentityDirectoryEvents`, `EmailEvents`, `EmailUrlInfo`, `CloudAppEvents`, `AlertEvidence`.
Key Sentinel tables: `SecurityEvent`, `Event`, `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `AzureActivity`, `OfficeActivity`, `CommonSecurityLog`, `Syslog`, `AWSCloudTrail`.

Sentinel management moves to the Defender portal (Azure portal experience retires 31 March 2027); KQL is unchanged.

---

## 4. Elastic EQL

```eql
// Sequence: file written then executed from same path within 5 min
sequence by host.id with maxspan=5m
  [file where event.type == "creation" and file.extension : ("exe","dll")] by file.path
  [process where event.type == "start"] by process.executable

// Until: process started, network connect, until process ends
sequence by process.entity_id
  [process where event.type == "start" and process.name : "rundll32.exe"]
  [network where destination.ip != null and not cidrmatch(destination.ip, "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")]
until [process where event.type == "end"]
```

`:` is case-insensitive with wildcards; `==` is exact. `~` suffix on functions = case-insensitive.

---

## 5. ES|QL

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 7 days
  AND process.parent.name IN ("winword.exe","excel.exe")
  AND process.name IN ("powershell.exe","cmd.exe")
| STATS hits = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.command_line
| SORT hits DESC
| LIMIT 50
```

ES|QL supports detection rules in Elastic Security and aggregations EQL cannot do.

---

## 6. Lucene / Kibana KQL

```text
# Lucene
event.code:4625 AND NOT user.name:*$ AND source.ip:(10.0.0.0/8)
# Kibana KQL
event.code : "4625" and not user.name : *$ and process.name : ("powershell.exe" or "cmd.exe")
```

---

## 7. Wazuh Rules (XML)

```xml
<group name="local,windows,">
  <rule id="100300" level="10">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(winword|excel|powerpnt)\.exe$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh|cmd|mshta|wscript)\.exe$</field>
    <description>Office spawned $(win.eventdata.image)</description>
    <mitre><id>T1204.002</id></mitre>
  </rule>
</group>
```

Frequency rules: `frequency="10" timeframe="120"` with `<if_matched_sid>` / `<same_source_ip />`. Test: `/var/ossec/bin/wazuh-logtest`.

---

## 8. Graylog

```text
source:dc01 AND EventID:4625 AND NOT TargetUserName:*$
```

Graylog uses Lucene-like syntax in search; pipelines (rule language) for enrichment.

---

## 9. Athena SQL (CloudTrail)

```sql
SELECT useridentity.arn, eventname, COUNT(*) AS c
FROM cloudtrail_logs
WHERE errorcode = 'AccessDenied' AND eventtime > date_format(current_timestamp - interval '1' day, '%Y-%m-%dT%H:%i:%sZ')
GROUP BY 1,2 ORDER BY c DESC LIMIT 50;
```

---

## Engagement Cheatsheet

```text
pseudocode → narrow source + time → indexed filters → negative filters
→ aggregate → project → test on TP window → test on noisy window → save
```

---

## Key References

- Splunk SPL reference; Splunk Security Content (research.splunk.com)
- Microsoft KQL reference; Defender XDR advanced hunting schema
- Elastic EQL and ES|QL references; elastic/detection-rules
- Wazuh ruleset syntax; Graylog search query language
- Related: `defensive-sigma`, `defensive-splunk`, `defensive-sentinel`, `defensive-elastic`, `defensive-wazuh`
