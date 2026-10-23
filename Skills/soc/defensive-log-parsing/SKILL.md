---
name: defensive-log-parsing
description: "Log ingestion, parsing, and normalization pipelines: syslog formats (RFC 3164, RFC 5424), CEF, LEEF, JSON, key-value, Windows XML/EVTX, multiline logs; normalization schemas (Elastic ECS, OCSF, Microsoft Sentinel ASIM, Google UDM, Splunk CIM); pipeline tools (rsyslog, syslog-ng, Logstash grok, Elastic ingest pipelines, Vector VRL, Fluent Bit, Cribl, NXLog, OpenTelemetry Collector, Sentinel DCR transformations); timestamp and timezone handling, field extraction and regex pitfalls, enrichment (GeoIP, asset, identity), volume reduction, parser testing, and source health monitoring. Use when onboarding a log source, writing a parser, normalizing fields, or troubleshooting missing/broken logs."
---

# Log Parsing & Normalization

Detection quality is capped by parsing quality. A rule on `user.name` silently fails if half your sources put the user in `Account_Name`. Normalize to one schema, test parsers, and monitor for drift.

## Quick Workflow

1. Identify format, transport, volume, and timestamp format of the source
2. Choose target schema (ECS, OCSF, ASIM, UDM, CIM) and map fields
3. Build parser in the pipeline tool; enrich (asset, identity, GeoIP)
4. Test with real samples (including edge cases); validate timestamps/timezones
5. Deploy; monitor parse failures and source silence

---

## 1. Formats

| Format | Example / notes |
|---|---|
| RFC 3164 (BSD syslog) | `<34>Oct 23 10:15:02 fw01 sshd[123]: Failed password...` — no year, no TZ |
| RFC 5424 | `<34>1 2026-10-23T10:15:02.123+08:00 fw01 sshd 123 - [meta x="y"] msg` — structured data, TZ |
| CEF | `CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1 dst=8.8.8.8 suser=bob` — escape `|` in header, `=` and `\` in extensions |
| LEEF | `LEEF:2.0|Vendor|Product|1.0|EventID|^|src=10.0.0.1^dst=...` (QRadar) — delimiter defined in header |
| JSON / NDJSON | Cloud logs; watch nested arrays and stringified JSON inside fields |
| Key=value | Fortinet, Palo Alto (CSV variants) |
| Windows EVTX | Forward via WEF/agents; render XML → fields (`EventData/Data[@Name]`) |
| Multiline | Java stack traces, PowerShell 4104 split blocks (`MessageNumber`/`MessageTotal`) |

---

## 2. Schemas

| Schema | Platform | Example fields |
|---|---|---|
| ECS | Elastic | `source.ip`, `user.name`, `process.command_line`, `event.category` |
| OCSF | Vendor-neutral (AWS Security Lake, many vendors) | `src_endpoint.ip`, `actor.user.name`, `class_uid` |
| ASIM | Microsoft Sentinel | `SrcIpAddr`, `TargetUsername`, `EventResult`; parsers `_Im_ProcessEvent`, `_Im_Authentication` |
| UDM | Google SecOps | `principal.ip`, `target.user.userid`, `metadata.event_type` |
| CIM | Splunk | Data models: `Authentication.user`, `Network_Traffic.src` |

Mapping table per source is a deliverable: source field → schema field → type → notes.

---

## 3. Pipeline Examples

### Logstash grok

```ruby
filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP:ts} %{HOSTNAME:host} sshd\[%{POSINT:pid}\]: %{WORD:outcome} password for (invalid user )?%{USERNAME:user} from %{IP:src_ip} port %{POSINT:src_port}" }
  }
  date { match => ["ts", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"] timezone => "Asia/Manila" target => "@timestamp" }
  mutate { rename => { "user" => "[user][name]" "src_ip" => "[source][ip]" } }
  geoip { source => "[source][ip]" target => "[source][geo]" }
}
```

### Elastic ingest pipeline (dissect)

```json
{ "processors": [
  { "dissect": { "field": "message", "pattern": "%{ts} %{host.name} %{process.name}[%{process.pid}]: %{event.original}" } },
  { "date": { "field": "ts", "formats": ["ISO8601"], "target_field": "@timestamp" } },
  { "remove": { "field": "ts" } }
] }
```

### Vector (VRL)

```toml
[transforms.parse_fw]
type = "remap"
inputs = ["syslog_in"]
source = '''
. = merge(., parse_key_value!(.message, field_delimiter: " ", key_value_delimiter: "="))
.source.ip = del(.srcip)
.destination.ip = del(.dstip)
.event.action = del(.action)
'''
```

### rsyslog forwarding with TLS + queue

```text
module(load="omfwd")
action(type="omfwd" target="siem.example.local" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
       queue.type="LinkedList" queue.filename="fwdq" queue.maxdiskspace="2g" queue.saveonshutdown="on" action.resumeRetryCount="-1")
```

### Sentinel DCR transformation (KQL)

```kql
source
| extend SrcIpAddr = tostring(parse_json(RawData).src), TargetUsername = tostring(parse_json(RawData).user)
| where EventType != "heartbeat"
| project-away RawData
```

---

## 4. Timestamps & Timezones

- Prefer UTC at source; if impossible, set TZ explicitly in parser
- RFC 3164 lacks year — handle year rollover (Dec 31 → Jan 1)
- Distinguish event time vs ingest time; alert on large deltas (delayed sources)
- NTP on all sources; skew breaks correlation

---

## 5. Regex & Parsing Pitfalls

- Greedy `.*` capturing too much; anchor patterns and use specific classes
- Catastrophic backtracking on long lines — test performance
- Quoted values with spaces/escapes in KV and CEF
- Locale-dependent formats (dates, decimal separators)
- Vendors changing formats on firmware upgrade → parse failure spikes
- Truncation of long messages (UDP syslog ~1–8 KB limits); use TCP/TLS

---

## 6. Enrichment & Reduction

| Enrichment | Source |
|---|---|
| Asset criticality, owner, role | CMDB/asset inventory lookup |
| Identity attributes | IdP/HR (department, manager, privileged flag) |
| GeoIP / ASN | MaxMind GeoLite2/ASN |
| Threat intel | TIP lookups (sparingly at ingest; prefer query-time) |

Reduction: drop debug/heartbeat noise, sample high-volume low-value flows, route verbose data to cheaper tiers (Sentinel Basic/Auxiliary logs, Splunk Federated Search to S3, data lakes) — never drop security-relevant fields.

---

## 7. Testing & Health

- Keep sample corpus per source (benign + malicious + edge cases) in repo; CI tests parser output fields
- Monitor `_grokparsefailure`/ingest pipeline failures, ASIM parser coverage, CIM validation (Splunk CIM Validator)
- Silence detection per source (expected EPS, last event time) — see `defensive-log-sources`

---

## Engagement Cheatsheet

```text
format (3164/5424/CEF/LEEF/JSON/KV/EVTX/multiline) → target schema (ECS/OCSF/ASIM/UDM/CIM) + mapping table
→ parser (grok/dissect/VRL/DCR) + UTC timestamps → enrich (asset/identity/GeoIP) → reduce noise not fields
→ sample-corpus tests in CI → monitor parse failures + silence + ingest lag
```

---

## Key References

- RFC 3164, RFC 5424, RFC 5425 (syslog over TLS); ArcSight CEF spec; IBM LEEF spec
- Elastic ECS; OCSF (schema.ocsf.io); Microsoft ASIM; Google UDM; Splunk CIM
- Related: `defensive-log-sources`, `defensive-elastic`, `defensive-sentinel`, `defensive-splunk`, `defensive-graylog`
