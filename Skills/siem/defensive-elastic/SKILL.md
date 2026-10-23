---
name: defensive-elastic
description: "Elastic Security / ELK SIEM engineering: Elastic Agent and Fleet integrations (Windows, System, Sysmon, Elastic Defend, AWS, Azure, Okta), ingest pipelines, Elastic Common Schema (ECS) field mapping, index lifecycle, detection rule types (custom query, EQL, ES|QL, threshold, indicator match, new terms, machine learning), prebuilt rules and elastic/detection-rules repo, exceptions and value lists, Timeline investigations, Osquery Manager, entity analytics, and Kibana/Lucene/KQL/EQL/ES|QL querying. Use for ELK-based SOC builds, detection authoring, and tuning."
---

# Elastic Security

Elastic Security = Elasticsearch + Kibana Security app + Elastic Agent/Fleet. Detection quality depends on ECS-correct data; get ingestion right first.

## Quick Workflow

1. Deploy Fleet Server; enroll Elastic Agents with policies per role
2. Add integrations (Windows, Sysmon, Elastic Defend, cloud)
3. Verify ECS fields populate (`event.category`, `process.*`, `user.*`)
4. Enable prebuilt rules matching your data; disable what lacks data
5. Author custom rules (EQL for sequences, ES|QL for aggregations)
6. Tune with exceptions and value lists

---

## 1. Ingestion

| Integration | Data stream example |
|---|---|
| Windows | `logs-windows.forwarded-*`, `logs-system.security-*`, `logs-windows.powershell_operational-*` |
| Sysmon | `logs-windows.sysmon_operational-*` |
| Elastic Defend | `logs-endpoint.events.process-*`, `.network-*`, `.file-*`, `.registry-*`, `.library-*` |
| AWS | `logs-aws.cloudtrail-*`, `logs-aws.guardduty-*`, `logs-aws.vpcflow-*` |
| Azure / Entra | `logs-azure.signinlogs-*`, `logs-azure.auditlogs-*`, `logs-azure.activitylogs-*` |
| Network | `logs-zeek.*`, `logs-suricata.eve-*` |

Custom logs: ingest pipeline with `grok`/`dissect` → map to ECS → `event.kind`, `event.category`, `event.type`, `event.outcome`.

```json
PUT _ingest/pipeline/cb-app
{
  "processors": [
    { "dissect": { "field": "message", "pattern": "user=%{user.name} action=%{event.action} src=%{source.ip}" } },
    { "set": { "field": "event.category", "value": ["authentication"] } },
    { "geoip": { "field": "source.ip", "target_field": "source.geo", "ignore_missing": true } }
  ]
}
```

---

## 2. Key ECS Fields

| Domain | Fields |
|---|---|
| Event | `@timestamp`, `event.code`, `event.action`, `event.category`, `event.type`, `event.outcome` |
| Process | `process.name`, `process.executable`, `process.command_line`, `process.pid`, `process.entity_id`, `process.parent.*`, `process.hash.sha256`, `process.code_signature.*`, `process.pe.original_file_name` |
| User | `user.name`, `user.domain`, `user.id` |
| Host | `host.name`, `host.id`, `host.os.type` |
| Network | `source.ip`, `destination.ip`, `destination.port`, `dns.question.name`, `tls.server.ja3s`, `url.full` |
| File | `file.path`, `file.extension`, `file.hash.sha256` |
| Registry | `registry.path`, `registry.value`, `registry.data.strings` |

---

## 3. Rule Types

| Type | Use |
|---|---|
| Custom query (KQL/Lucene) | Single-event matches |
| EQL | Sequences, `until`, process lineage |
| ES\|QL | Aggregations, stats-based detections |
| Threshold | Count per field over window |
| Indicator match | Join events to threat intel indices |
| New terms | First-seen values (new process for user, new country) |
| Machine learning | Anomaly jobs (rare process, unusual login) |

EQL rule:

```eql
sequence by host.id with maxspan=1m
  [process where event.type == "start" and process.name : "certutil.exe"
     and process.args : ("-urlcache", "/urlcache", "-decode", "/decode")]
  [network where process.name : "certutil.exe" and destination.ip != null]
```

New terms rule: field `process.executable`, history window 14 d, query `host.os.type:windows and event.category:process` → alerts on first-seen binaries per host.

ES|QL rule:

```esql
FROM logs-system.security-*
| WHERE event.code == "4625"
| STATS failures = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip
| WHERE users >= 15
```

---

## 4. Prebuilt Rules & detection-rules Repo

- Install/update prebuilt rules from Kibana Security → Rules
- Each rule lists required integrations — enable only where data exists
- `elastic/detection-rules` (GitHub): TOML rule format, `python -m detection_rules` CLI for testing, exporting, and DaC workflows

---

## 5. Tuning

- **Exceptions**: rule-level or shared exception lists; match on combination (`process.executable` + `process.code_signature.subject_name`)
- **Value lists**: upload lists (IPs, hashes) and reference in exceptions
- **Alert suppression**: group alerts by fields per window to reduce duplicates
- Avoid editing prebuilt rule logic directly — duplicate or use exceptions so updates still apply

---

## 6. Investigation

- **Timeline**: pin events, add notes, EQL tab for sequences
- **Session view / Analyzer**: process trees from Elastic Defend
- **Osquery Manager**: live queries across agents

```sql
SELECT name, path, cmdline, parent FROM processes WHERE on_disk = 0;
SELECT * FROM startup_items;
SELECT * FROM listening_ports WHERE address != '127.0.0.1';
```

- **Entity analytics**: host/user risk scores; asset criticality

---

## 7. Index Lifecycle

- ILM: hot (7–30 d) → warm → cold → frozen (searchable snapshots) → delete
- Detection rules query hot/warm; hunts may span frozen (slower)

---

## Engagement Cheatsheet

```text
Fleet + agents → integrations → verify ECS → enable matching prebuilt rules
→ custom EQL/ES|QL rules → exceptions/value lists → Timeline/Osquery for IR
```

---

## Key References

- Elastic Security docs — https://www.elastic.co/docs/solutions/security
- ECS reference — https://www.elastic.co/docs/reference/ecs
- elastic/detection-rules — https://github.com/elastic/detection-rules
- Related: `defensive-query-languages`, `defensive-sigma`
