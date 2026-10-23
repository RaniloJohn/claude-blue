---
name: defensive-sigma
description: "Sigma detection rule engineering. Use when writing, reviewing, converting, or tuning Sigma rules; choosing logsource product/category/service; using modifiers (contains, startswith, endswith, all, re, cidr, windash, base64offset, fieldref, exists, gt/lt); writing Sigma correlation rules (event_count, value_count, temporal, temporal_ordered) and Sigma filters; converting with pySigma/sigma-cli to Splunk SPL, Microsoft Sentinel/Defender KQL (kusto backend, microsoft_xdr / sentinel_asim pipelines), Elastic Lucene/EQL/ES|QL, QRadar, Wazuh; and running Sigma directly on EVTX with Hayabusa or Chainsaw."
---

# Sigma Rules

Sigma is the vendor-neutral detection language. Write logic once, convert per backend, version in Git. A Sigma rule is only as good as the field mapping that converts it.

## Quick Workflow

1. Define the behavior and required telemetry
2. Choose `logsource` precisely
3. Write `detection` with selections + filters
4. Add FP, level, ATT&CK tags, references
5. `sigma check` → convert → test against TP/FP samples
6. Deploy in log-only, tune, promote

---

## 1. Rule Anatomy

```yaml
title: Suspicious Process Spawned by Office Application
id: 0f6c3b5e-7a9d-4c2e-b1f8-6d4a2e9c7b10      # UUIDv4, never reuse
status: experimental                           # experimental | test | stable | deprecated | unsupported
description: Detects Office applications spawning script interpreters or LOLBins, common in macro/OLE-based initial access.
references:
  - https://attack.mitre.org/techniques/T1204/002/
author: claude-blue
date: 2026-10-23
modified: 2026-10-23
tags:
  - attack.execution
  - attack.t1204.002
  - attack.initial-access
  - attack.t1566.001
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: all of selection_*
falsepositives:
  - Legitimate add-ins invoking scripts — allowlist by add-in path and signer
level: high
```

Tags use lowercase hyphenated tactic names (`attack.credential-access`) and technique IDs (`attack.t1003.001`).

---

## 2. Logsource

| Field | Examples |
|---|---|
| `product` | windows, linux, macos, aws, azure, gcp, m365, okta, github, kubernetes, zeek |
| `category` | process_creation, network_connection, file_event, registry_set, image_load, process_access, dns_query, ps_script, pipe_created, create_remote_thread |
| `service` | security, system, sysmon, powershell, cloudtrail, signinlogs, auditlogs, auditd, sshd |

Use `category` for generic Sysmon/EDR-style events (portable). Use `service` for specific channels (e.g. `service: security` for 4769).

---

## 3. Modifiers

| Modifier | Meaning |
|---|---|
| `contains` / `startswith` / `endswith` | Substring/anchor match (case-insensitive by default) |
| `all` | All list values must match (default for lists is OR) |
| `re` | Regex (backend-dependent flavor; keep simple) |
| `cased` | Case-sensitive |
| `windash` | Expands `-` to `/`, `–`, `—`, `―` variants for CLI flags |
| `base64` / `base64offset` | Match Base64-encoded forms (offset handles alignment) |
| `utf16le` / `wide` | Encode before base64 (PowerShell `-enc`) |
| `cidr` | IP in network range |
| `exists` | Field present/absent |
| `fieldref` | Compare field to another field |
| `gt` `gte` `lt` `lte` | Numeric comparisons |
| `expand` | Placeholder expansion (`%DomainControllers%`) via pipeline |

Example — encoded PowerShell catching both flag styles:

```yaml
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|windash|contains:
      - ' -e '
      - ' -enc '
      - ' -encodedcommand '
  condition: selection
```

---

## 4. Conditions

```yaml
condition: selection and not 1 of filter_*
condition: 1 of selection_* and not filter_main
condition: all of them
```

Naming convention: `selection_*` for positives, `filter_main_*` for always-applicable exclusions, `filter_optional_*` for environment-specific ones.

---

## 5. Correlation Rules (Sigma v2)

```yaml
title: Failed Logon
name: failed_logon
logsource: { product: windows, service: security }
detection:
  selection: { EventID: 4625 }
  condition: selection
---
title: Password Spray From Single Source
correlation:
  type: value_count           # event_count | value_count | temporal | temporal_ordered
  rules:
    - failed_logon
  group-by:
    - IpAddress
  timespan: 10m
  condition:
    field: TargetUserName
    gte: 15
level: high
```

Backend support for correlation varies (Splunk, Elastic ES|QL/EQL, Kusto supported in recent pySigma backends) — verify with `sigma convert` output.

### Sigma Filters

Separate environment exclusions from the shared rule:

```yaml
title: Exclude SCCM from Office child process rule
filter:
  rules:
    - 0f6c3b5e-7a9d-4c2e-b1f8-6d4a2e9c7b10
  selection:
    ParentCommandLine|contains: '\ccmcache\'
  condition: not selection
```

---

## 6. Conversion (pySigma / sigma-cli)

```bash
pip install sigma-cli
sigma plugin install splunk kusto elasticsearch
sigma list targets ; sigma list pipelines

sigma check rules/
sigma convert -t splunk -p sysmon rules/office_child.yml
sigma convert -t kusto -p microsoft_xdr rules/office_child.yml
sigma convert -t kusto -p sentinel_asim rules/office_child.yml
sigma convert -t lucene -p ecs_windows rules/office_child.yml
sigma convert -t eql -p ecs_windows rules/office_child.yml
sigma convert -t esql -p ecs_windows rules/office_child.yml
sigma convert -t elasticsearch -p ecs_windows -f kibana_ndjson -o export.ndjson rules/
```

Kusto backend (formerly `microsoft365defender`) ships `microsoft_xdr`, `sentinel_asim`, and `azure_monitor` pipelines. Stack custom pipelines with multiple `-p` flags for local field names.

---

## 7. Run Sigma Directly on EVTX

```bash
hayabusa csv-timeline -d ./evtx -o timeline.csv            # built-in Sigma + Hayabusa rules
chainsaw hunt ./evtx -s sigma/rules --mapping mappings/sigma-event-logs-all.yml -o out.csv --csv
```

---

## 8. Quality Checklist

```text
[ ] Logic targets attacker-invariant behavior (parent/child, access mask, API), not tool names
[ ] Uses OriginalFileName where renaming is plausible
[ ] windash on CLI flags
[ ] Filters named and justified
[ ] falsepositives non-empty and specific
[ ] level justified (informational/low/medium/high/critical)
[ ] ATT&CK tags present
[ ] Converted output inspected per backend (pipelines can silently drop fields)
[ ] TP sample fires, FP sample does not
```

---

## Engagement Cheatsheet

```bash
sigma check rules/ && \
sigma convert -t splunk -p sysmon rules/ -o build/splunk.spl && \
sigma convert -t kusto -p microsoft_xdr rules/ -o build/xdr.kql && \
sigma convert -t lucene -p ecs_windows rules/ -o build/elastic.lucene
```

---

## Key References

- Sigma specification v2 — https://github.com/SigmaHQ/sigma-specification
- SigmaHQ rules — https://github.com/SigmaHQ/sigma
- pySigma / sigma-cli — https://github.com/SigmaHQ/pySigma
- pySigma-backend-kusto — https://github.com/AttackIQ/pySigma-backend-kusto
- Hayabusa (Yamato Security), Chainsaw (WithSecure)
- Related: `defensive-query-languages`, `defensive-detection-as-code`
