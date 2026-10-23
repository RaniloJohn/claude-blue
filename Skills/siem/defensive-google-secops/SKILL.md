---
name: defensive-google-secops
description: "Google Security Operations (formerly Chronicle) SIEM and SOAR: Unified Data Model (UDM) fields and event types, UDM search syntax, raw log search, parsers and parser extensions, YARA-L 2.0 detection rules (meta, events, match, outcome, condition sections, multi-event correlation, risk scoring, reference lists and data tables), curated detections from Google threat intelligence, entity graph and aliasing, retrohunts, composite detections, SOAR playbooks and cases, Gemini-assisted investigation, and BigQuery export. Use when writing YARA-L rules, searching UDM, or operating Google SecOps."
---

# Google Security Operations (SecOps)

Google SecOps ingests logs into the **Unified Data Model (UDM)**, enriches entities (users, assets, IPs) automatically, and detects with **YARA-L 2.0** rules that can correlate multiple events over time windows.

## Quick Workflow

1. Confirm logs parse to UDM (default parsers or parser extensions)
2. Investigate with UDM search; pivot via entity views
3. Write YARA-L rules; test with retrohunts
4. Enable curated detections relevant to your telemetry
5. Route detections to SOAR cases and playbooks

---

## 1. UDM Basics

| Noun | Meaning |
|---|---|
| `principal` | Actor initiating (user, host, process) |
| `target` | Object acted upon |
| `src` / `observer` / `intermediary` | Other participants |
| `metadata.event_type` | `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `NETWORK_DNS`, `USER_LOGIN`, `FILE_CREATION`, `REGISTRY_MODIFICATION`, `NETWORK_HTTP`, `EMAIL_TRANSACTION`, … |
| `security_result` | Action, severity, rule name from source product |

---

## 2. UDM Search

```text
metadata.event_type = "PROCESS_LAUNCH" AND target.process.file.full_path = /\\powershell\.exe$/ nocase AND target.process.command_line = /-enc/ nocase
metadata.event_type = "NETWORK_DNS" AND network.dns.questions.name = /\.ngrok-free\.app$/
metadata.event_type = "USER_LOGIN" AND security_result.action = "BLOCK" AND principal.ip_geo_artifact.location.country_or_region != "Philippines"
principal.hostname = "ws-042" AND metadata.event_type = "NETWORK_CONNECTION" AND target.port = 445
```

Statistics in search: append `| match: principal.hostname | outcome: $count = count(metadata.id)` style aggregations (search stats syntax — verify current UI support).

---

## 3. YARA-L 2.0

### Single-event rule

```text
rule office_spawns_script_host {
  meta:
    author = "claude-blue"
    description = "Office application spawning script interpreter"
    severity = "HIGH"
    mitre_attack_technique = "T1566.001"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.file.full_path = /\\(winword|excel|powerpnt|outlook)\.exe$/ nocase
    $e.target.process.file.full_path = /\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32)\.exe$/ nocase
  condition:
    $e
}
```

### Multi-event correlation with match window

```text
rule password_spray_then_success {
  meta:
    severity = "HIGH"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.principal.ip = $ip
    $fail.target.user.userid = $u_fail
    $ok.metadata.event_type = "USER_LOGIN"
    $ok.security_result.action = "ALLOW"
    $ok.principal.ip = $ip
    $fail.metadata.event_timestamp.seconds < $ok.metadata.event_timestamp.seconds
  match:
    $ip over 30m
  outcome:
    $users_tried = count_distinct($fail.target.user.userid)
    $risk_score = if($users_tried > 20, 90, 60)
  condition:
    #u_fail >= 15 and $ok
}
```

### Reference list / data table

```text
events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.target.ip in %malicious_ips
```

Rule types: single event, multi-event (match section required), with outcome variables for risk scoring; composite detections chain detections of other rules. Use **retrohunt** to run a new rule over historical data before enabling alerting.

---

## 4. Curated Detections

Google-maintained rule packs (Windows threats, cloud threats for GCP/AWS/Azure, UEBA, applied threat intelligence from Mandiant/VirusTotal matches). Enable those matching your data sources; set alerting per rule set; tune exclusions.

---

## 5. Entities & Context

Entity graph merges asset and user context (from CMDB/IdP feeds) — rules can join event fields to `graph.entity` attributes, e.g., alert only if `target.user` is in a privileged group, or the asset is tagged critical. Aliasing maps IP → hostname → MAC over time (DHCP-aware).

---

## 6. SOAR

Cases group alerts; playbooks automate enrichment (VirusTotal, WHOIS, EDR lookup), containment (EDR isolate, IdP disable, firewall block), and notifications. Build approval steps for disruptive actions.

---

## 7. Operations

- Parser coverage: monitor unparsed log counts per log type; write parser extensions for missing fields
- Ingestion health: feed status, silent log types → alert
- Export UDM to BigQuery for long-range analytics and metrics

---

## Engagement Cheatsheet

```text
UDM parsing (extensions) → UDM search (event_type + principal/target fields, regex /…/ nocase) → YARA-L (meta/events/match/outcome/condition)
→ reference lists & entity graph context → retrohunt before enable → curated detections → SOAR playbooks with approvals → parser/feed health
```

---

## Key References

- Google SecOps docs: UDM field list, YARA-L 2.0 syntax, curated detections; Chronicle detection-rules GitHub repo
- Related: `defensive-query-languages`, `defensive-detection-as-code`, `defensive-soar-automation`, `defensive-yara`
