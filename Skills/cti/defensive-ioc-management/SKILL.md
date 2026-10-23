---
name: defensive-ioc-management
description: "Indicator of compromise lifecycle and threat intel platform operations: IOC types and Pyramid of Pain, quality scoring, deduplication, aging and expiry, allowlisting (CDNs, cloud ranges, popular domains) to prevent self-inflicted outages, MISP (events, attributes, galaxies, warning lists, sightings, feeds) and OpenCTI (STIX 2.1 knowledge graph, connectors), STIX/TAXII, pushing IOCs to SIEM/EDR/firewall/DNS, retro-hunting, defanging, and sharing with communities under TLP. Use when ingesting, curating, distributing, or hunting with indicators."
---

# IOC Management

Indicators decay fast and break things when wrong. A good IOC pipeline adds context, filters noise, expires stale data, and measures whether indicators ever match.

## Quick Workflow

1. Ingest from rated sources
2. Normalize (STIX 2.1), deduplicate, enrich
3. Score and filter against warning lists / allowlists
4. Distribute by type to the right control (block vs alert)
5. Retro-hunt historical logs
6. Track sightings; expire and prune

---

## 1. IOC Types & Shelf Life

| Type | Pain to change | Typical useful life | Use |
|---|---|---|---|
| Hash (SHA-256) | Trivial | Campaign-specific | EDR block/alert |
| IP address | Easy | Days–weeks | Alert; block only with context |
| Domain | Simple | Weeks | DNS sinkhole, proxy block |
| URL | Simple | Days | Proxy/email |
| Host/network artifacts (mutex, pipe, UA, JA4, URI pattern) | Annoying | Months | Detection rules |
| Tools | Challenging | Months–years | Behavioral detection |
| TTPs | Tough | Years | Hunting/detection engineering |

---

## 2. Quality Gate

```text
[ ] Source rated (Admiralty) and TLP recorded
[ ] Not in warning lists (MISP warninglists: top domains, CDN ranges, cloud IPs, RFC1918, public DNS resolvers)
[ ] Context: actor/campaign, kill-chain phase, first/last seen
[ ] Confidence score
[ ] Expiry set by type (e.g., IP 30 d, domain 90 d, hash 365 d)
[ ] Action decided: block | alert | hunt-only
```

Blocking a shared CDN or cloud IP can take down business services — IPs default to alert/hunt unless dedicated infrastructure is confirmed.

---

## 3. MISP

| Concept | Meaning |
|---|---|
| Event | Container for an incident/report |
| Attribute | Single indicator (type, category, `to_ids` flag) |
| Object | Grouped attributes (file object: name+hashes+size) |
| Galaxy / cluster | ATT&CK, actors, malware families |
| Tags / taxonomies | TLP, PAP, admiralty-scale, confidence |
| Warning lists | Known-benign values to suppress false positives |
| Sightings | Indicator observed / false positive / expired |
| Feeds | Pull external sources (CIRCL OSINT, abuse.ch) |

```python
from pymisp import PyMISP
misp = PyMISP("https://misp.local", "API_KEY", ssl=True)
r = misp.search(controller="attributes", type_attribute=["domain","ip-dst"], to_ids=True,
                published=True, last="30d", enforce_warninglist=True, pythonify=True)
for a in r: print(a.type, a.value, a.Event.info)
```

---

## 4. OpenCTI

- STIX 2.1 knowledge graph: Indicators, Observables, Malware, Intrusion Sets, Campaigns, Attack Patterns, Reports, Relationships
- Connectors: MISP, CISA KEV, abuse.ch, AlienVault, MITRE ATT&CK, VirusTotal enrichment, and export to SIEM (Sentinel, Splunk, Elastic)
- Indicator `valid_until` and decay rules automate aging

---

## 5. STIX/TAXII

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--1f6a2c47-7d9e-4b8a-9b3c-2a5e6f7d8c90",
  "created": "2026-10-23T00:00:00.000Z",
  "modified": "2026-10-23T00:00:00.000Z",
  "name": "Loader C2 domain",
  "pattern": "[domain-name:value = 'update-cdn-check.example']",
  "pattern_type": "stix",
  "valid_from": "2026-10-23T00:00:00Z",
  "valid_until": "2027-01-21T00:00:00Z",
  "indicator_types": ["malicious-activity"],
  "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
}
```

(The marking-definition above is the predefined STIX 2.1 TLP:AMBER marking from the TLP 1.0 era; TLP 2.0 labels such as AMBER+STRICT use separate marking-definition objects — use the IDs your platform ships.)

TAXII 2.1: collections served over HTTPS; SIEMs (Sentinel TI connector, Splunk, Elastic Threat Intel) poll collections.

---

## 6. Distribution Map

| IOC | Control | Action |
|---|---|---|
| Hash | EDR custom indicators | Alert/block (low FP risk) |
| Domain | DNS RPZ / protective DNS, proxy | Block (after warning-list check) |
| URL | Proxy, email gateway | Block |
| IP | Firewall/SIEM | Alert; block if dedicated infra |
| JA4/UA/URI pattern | NIDS/SIEM rule | Alert |
| Email sender/subject | Email gateway | Quarantine + retro-search |

---

## 7. Retro-Hunting

New IOC → search back over retention window (DNS, proxy, EDR, email). A historical hit can mean pre-existing compromise — escalate.

```spl
| inputlookup new_iocs.csv | rename value as query | fields query
| join type=inner query [ search index=dns earliest=-90d | fields _time src query ]
```

```kql
let iocs = externaldata(Domain:string)[@"https://storage/iocs.csv"] with(format="csv");
DnsEvents | where TimeGenerated > ago(90d) | where Name in~ (iocs)
```

---

## 8. Metrics

- % IOCs with ≥1 sighting (most never match — prune sources with ~0%)
- FP sightings per source
- Mean time from publication → deployed
- Blocks causing business tickets

---

## 9. Defanging

`https://evil.example/a` → `hxxps://evil[.]example/a`; `203.0.113.5` → `203.0.113[.]5`; emails `user[@]evil[.]example`. Refang only inside tools.

---

## Engagement Cheatsheet

```text
ingest (rated) → STIX normalize → warning lists → score + expiry → route (block/alert/hunt)
→ retro-hunt 90 d → sightings → prune
```

---

## Key References

- MISP — https://www.misp-project.org ; MISP warninglists
- OpenCTI — https://docs.opencti.io
- OASIS STIX 2.1 / TAXII 2.1
- Pyramid of Pain (David Bianco)
- Related: `defensive-cti`, `defensive-soar-automation`
