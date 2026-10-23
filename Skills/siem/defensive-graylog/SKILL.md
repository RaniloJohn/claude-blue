---
name: defensive-graylog
description: "Graylog for security monitoring: architecture (Graylog server, Data Node/OpenSearch, MongoDB), inputs (Syslog, GELF, Beats, Raw, CEF), streams and index sets with retention, processing pipelines and rule language, lookup tables and data adapters (GeoIP, CSV, threat intel), extractors (legacy), search query syntax, event definitions and correlation (aggregation and filter conditions), notifications, Graylog Security features (Sigma rules, investigations, anomaly detection), content packs, Sidecar for agent management, hardening, and example security pipelines. Use when deploying, querying, or writing detections in Graylog."
---

# Graylog

Graylog is a log management platform popular with smaller SOCs and MSPs: cheap to run, fast search, flexible pipelines. Graylog Open covers ingestion/search/alerts; Graylog Security adds SIEM features (Sigma, investigations, anomaly detection).

## Quick Workflow

1. Inputs per source type; route to **streams** with dedicated **index sets** (retention per data type)
2. Normalize with **pipelines** (prefer over extractors) to a consistent schema (GIM — Graylog Information Model — or ECS-like)
3. Enrich via **lookup tables** (GeoIP, assets, threat intel)
4. Build **event definitions** (filter + aggregation) with notifications
5. Monitor input throughput, journal, and processing errors

---

## 1. Architecture

| Component | Role |
|---|---|
| Graylog server | Inputs, processing, web UI, alerting |
| Data Node / OpenSearch | Storage and search |
| MongoDB | Configuration metadata |
| Sidecar | Manages Beats/NXLog collectors on endpoints |
| Forwarder (Enterprise/Cloud) | Ship from on-prem to Graylog Cloud |

Harden: TLS on inputs and web UI, authentication via LDAP/AD or SSO with MFA, roles per team, no inputs bound to 0.0.0.0 on internet-exposed hosts, separate admin users, audit log enabled (Enterprise).

---

## 2. Inputs & Streams

| Source | Input |
|---|---|
| Linux/network syslog | Syslog TCP/TLS (6514) or UDP |
| Windows (Winlogbeat/NXLog via Sidecar) | Beats / GELF TCP |
| Applications | GELF HTTP/TCP |
| Firewalls with CEF | CEF TCP |

Stream rules route messages (e.g., `source` matches `fw-*` → "Firewall" stream) and assign index sets: e.g., firewall 90 days, Windows security 180 days, debug 7 days.

---

## 3. Pipeline Rules

```text
rule "windows_failed_logon"
when
  has_field("winlogbeat_event_code") && to_string($message.winlogbeat_event_code) == "4625"
then
  set_field("event_category", "authentication");
  set_field("event_outcome", "failure");
  set_field("user_name", to_string($message.winlogbeat_event_data_TargetUserName));
  set_field("source_ip", to_string($message.winlogbeat_event_data_IpAddress));
end
```

```text
rule "geoip_and_ti_enrich"
when
  has_field("source_ip") && !cidr_match("10.0.0.0/8", to_ip($message.source_ip))
then
  let geo = lookup("geoip-city", to_string($message.source_ip));
  set_field("source_geo_country", geo["country"].iso_code);
  let ti = lookup_value("ti-bad-ips", to_string($message.source_ip));
  set_field("ti_match", ti);
end
```

```text
rule "parse_sshd_failure"
when
  contains(to_string($message.message), "Failed password")
then
  let m = grok(pattern: "Failed password for (invalid user )?%{USERNAME:user_name} from %{IP:source_ip} port %{INT:source_port}", value: to_string($message.message), only_named_captures: true);
  set_fields(m);
  set_field("event_outcome", "failure");
end
```

Attach pipelines to streams; order stages (parse → normalize → enrich → tag).

---

## 4. Search Syntax

```text
event_category:authentication AND event_outcome:failure AND NOT source_ip:10.*
winlogbeat_event_code:4688 AND winlogbeat_event_data_CommandLine:/.*-enc.*/
source:fw-* AND action:deny AND destination_port:(445 OR 3389)
_exists_:ti_match
user_name:"svc_backup" AND source_geo_country:(NOT PH)
```

Lucene-style: wildcards `*`, ranges `bytes:>1000000`, regex `/…/` (expensive), field existence `_exists_:field`. Time ranges set in UI or API.

---

## 5. Event Definitions (Alerts)

| Type | Example |
|---|---|
| Filter | `winlogbeat_event_code:1102` (Security log cleared) — any match |
| Aggregation | `event_outcome:failure AND event_category:authentication` grouped by `source_ip`, `count() >= 50` in 10 min, with `card(user_name) >= 20` (spray) |
| Correlation (Security) | Sequence of events, e.g., failures then success from same IP |

Notifications: email, HTTP (webhook to SOAR/TheHive/Slack/Teams), PagerDuty. Include fields and a search link in templates.

---

## 6. Graylog Security Features

Sigma rule import and management, Investigations (case collection of evidence), anomaly detection (ML on log volume/fields), Illuminate content packs (prebuilt parsing + dashboards for Windows, Okta, M365, firewalls). Verify licensing for your deployment.

---

## 7. Operations

| Check | Where |
|---|---|
| Input throughput & errors | System → Inputs |
| Journal utilization (backpressure) | System → Nodes |
| Processing/indexing failures | System → Overview; failure processing stream |
| Index retention & size | System → Indices |
| Source silence | Event definition: aggregation `count() < 1` over 30 min per critical source |

---

## Engagement Cheatsheet

```text
inputs (TLS) → streams + index sets (retention per type) → pipelines (parse → normalize → enrich → tag) + lookup tables
→ Lucene searches → event definitions (filter/aggregation/correlation) → webhook to SOAR → monitor journal, failures, silence
```

---

## Key References

- Graylog documentation (go2docs.graylog.org); Graylog pipeline functions reference; Graylog Illuminate
- Related: `defensive-log-parsing`, `defensive-sigma`, `defensive-wazuh`, `defensive-query-languages`
