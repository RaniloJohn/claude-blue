---
name: defensive-qradar
description: "IBM QRadar SIEM operations and detection: architecture (console, event/flow processors, collectors, data nodes), DSMs and log source management, custom event properties, QID mapping, AQL (Ariel Query Language) for events and flows with functions (QIDNAME, LOGSOURCENAME, CATEGORYNAME, REFERENCESETCONTAINS), Custom Rule Engine rules and building blocks, offenses and magnitude, reference sets/maps for watchlists, network hierarchy, tuning (false positive rules, coalescing), QRadar apps (Use Case Manager, Log Source Management), and the QRadar SaaS transition to Palo Alto Cortex. Use when querying QRadar, writing CRE rules, or tuning offenses."
---

# IBM QRadar

QRadar correlates normalized events and flows into **offenses**. Detection quality depends on correct DSM parsing, an accurate **network hierarchy**, and well-tuned **building blocks**.

## Quick Workflow

1. Confirm log sources are parsed (not "Unknown"/stored) and mapped to QIDs
2. Define network hierarchy (internal ranges, DMZ, critical servers)
3. Write AQL to investigate; convert to CRE rules with building blocks
4. Use reference sets for watchlists (IOCs, privileged users, critical assets)
5. Tune offenses; review rule performance

Note: IBM sold the QRadar SaaS business to Palo Alto Networks (2024, migrating to Cortex XSIAM); QRadar SIEM on-prem/software continues under IBM — check your support path.

---

## 1. Architecture

| Component | Role |
|---|---|
| Console | UI, rules, offenses |
| Event Processor (EP) | Parse, correlate, store events |
| Flow Processor (FP)/QFlow | Network flows (NetFlow/IPFIX/QNI) |
| Event Collector (EC) | Remote collection, buffering |
| Data Node | Storage scaling |
| WinCollect | Windows agent |

---

## 2. AQL Essentials

```sql
-- Failed logons by source in last 24h
SELECT sourceip, username, COUNT(*) AS fails
FROM events
WHERE QIDNAME(qid) ILIKE '%failed%logon%' OR "EventID" = '4625'
GROUP BY sourceip, username
HAVING fails > 20
ORDER BY fails DESC
LAST 24 HOURS
```

```sql
-- Process creation with encoded PowerShell (custom property "Process CommandLine")
SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm:ss') AS t, LOGSOURCENAME(logsourceid) AS src, username, "Process CommandLine"
FROM events
WHERE "Process CommandLine" IMATCHES '.*powershell.*(-enc|-encodedcommand).*'
LAST 7 DAYS
```

```sql
-- Event categories for a host
SELECT CATEGORYNAME(category) AS cat, QIDNAME(qid) AS name, COUNT(*) FROM events
WHERE sourceip = '10.1.1.10' GROUP BY cat, name ORDER BY 3 DESC
START '2026-10-20 00:00' STOP '2026-10-21 00:00'
```

```sql
-- Reference set IOC hits
SELECT sourceip, destinationip, destinationport, LOGSOURCENAME(logsourceid)
FROM events WHERE REFERENCESETCONTAINS('Malicious IPs', destinationip) LAST 24 HOURS
```

```sql
-- Flows: large outbound transfers
SELECT sourceip, destinationip, SUM(sourcebytes) AS out_bytes FROM flows
WHERE flowdirection = 'L2R' GROUP BY sourceip, destinationip HAVING out_bytes > 1073741824 LAST 24 HOURS
```

Tips: custom properties are double-quoted; string literals single-quoted; `ILIKE`/`IMATCHES` case-insensitive; avoid regex on huge ranges — filter by `logsourcetypeid`/`qid` first; `LAST n MINUTES|HOURS|DAYS` or `START/STOP`.

---

## 3. Custom Rule Engine (CRE)

| Concept | Use |
|---|---|
| Building blocks (BB) | Reusable conditions (e.g., `BB:HostDefinition: Domain Controllers`, `BB:CategoryDefinition: Authentication Failures`) — tune once, used by many rules |
| Event / flow / common / offense rules | Scope of tests |
| Tests | "when the event QID is one of…", "when at least N events are seen with same source IP in M minutes", "when any of these properties are contained in reference set" |
| Responses | Create offense, set severity/credibility/relevance, add to reference set, email, SNMP, custom action script |

Example rule (logic): "Password spray"

```text
Apply "Password Spray" on events which are detected by the Local system
 and when the event(s) were detected by one or more of Microsoft Windows Security Event Log
 and when the event QID is one of (Failed Logon / 4625, 4771)
 and when at least 20 events are seen with the same Source IP and different Username in 10 minutes
Response: create offense indexed on Source IP; severity 7; add Source IP to reference set "Spray Sources"
```

---

## 4. Offenses & Tuning

- **Magnitude** = f(severity, credibility, relevance); relevance increases with network hierarchy weight of target
- Tune false positives with "False Positive" rule/BB (`BB:FalsePositive:*`) rather than disabling detection rules
- Review **rule performance** (expensive rules disabled automatically under load — check System Notifications)
- Offense chaining and coalescing: index on the right property to avoid offense floods
- Use Case Manager app: map rules to ATT&CK, see coverage, find rule tuning opportunities

---

## 5. Log Source Health

```sql
SELECT LOGSOURCENAME(logsourceid) AS src, MAX(starttime) AS last
FROM events GROUP BY logsourceid LAST 2 HOURS
```

Alert on critical sources silent > 30 min (rule: "log source stopped sending events" via health metrics). Check "Unknown" and "Stored" events — parsing gaps; build custom DSM/property extensions with the DSM Editor.

---

## Engagement Cheatsheet

```text
DSM parsing (no Unknown/Stored) → network hierarchy → AQL (events/flows, QIDNAME/LOGSOURCENAME/REFERENCESETCONTAINS, LAST/START-STOP)
→ CRE rules from building blocks + reference sets → offense magnitude & indexing → FP building blocks → Use Case Manager ATT&CK coverage → source health
```

---

## Key References

- IBM QRadar AQL guide; QRadar CRE documentation; QRadar Use Case Manager
- Related: `defensive-query-languages`, `defensive-log-parsing`, `defensive-detection-as-code`, `defensive-alert-triage`
