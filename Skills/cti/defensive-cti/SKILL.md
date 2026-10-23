---
name: defensive-cti
description: "Cyber threat intelligence for SOC and detection teams: intelligence lifecycle (direction, collection, processing, analysis, dissemination, feedback), Priority Intelligence Requirements (PIRs), strategic/operational/tactical intel, Diamond Model, Cyber Kill Chain, ATT&CK-based TTP extraction from reports, source evaluation (Admiralty/NATO code), confidence language (estimative probability), TLP 2.0, actor tracking and naming, attribution caution, and writing intel products that drive hunts and detections. Use when analyzing a threat report, building an actor profile, or producing intel for stakeholders."
---

# Cyber Threat Intelligence

Intel is useful only if it changes a decision: what to hunt, what to detect, what to patch, what to tell leadership. Start from requirements, end with action.

## Quick Workflow

1. Define PIRs (what decisions need intel)
2. Collect from sources mapped to PIRs
3. Process: normalize, deduplicate, extract TTPs/IOCs
4. Analyze: relevance, confidence, implications
5. Disseminate tailored products (TLP-marked)
6. Feedback: did it drive action?

---

## 1. Intelligence Levels

| Level | Audience | Content | Example |
|---|---|---|---|
| Strategic | Executives | Trends, risk, intent | "Ransomware groups targeting PH BPO sector rose in 2026" |
| Operational | SOC/IR leads | Campaigns, actor TTPs, timing | "Actor X uses edge VPN exploits then RMM tools" |
| Tactical | Analysts/engineers | IOCs, detections, signatures | Hashes, domains, Sigma rules |

---

## 2. PIRs (examples)

- Which threat actors target our sector/region and with what initial access methods?
- Which actively exploited vulnerabilities affect our internet-facing assets?
- Are our credentials, data, or brands exposed (leaks, infostealer logs, phishing kits)?
- Which TTPs used against peers are we unable to detect?

---

## 3. Analytic Models

**Diamond Model**: Adversary — Capability — Infrastructure — Victim, linked by events. Pivot on any vertex (e.g., infrastructure → other victims).

**Cyber Kill Chain**: Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives. Useful for describing where a campaign was stopped.

**ATT&CK**: Map every behavior in a report to technique/sub-technique; store as Navigator layer per actor/campaign.

---

## 4. Extracting TTPs from a Report

| Report sentence | Technique | Detection idea |
|---|---|---|
| "Exploited CVE in FortiOS SSL-VPN for access" | T1190 | Edge appliance log anomalies; KEV patch status |
| "Used AnyDesk installed via PowerShell" | T1219, T1059.001 | RMM install from script parent |
| "Dumped LSASS with comsvcs MiniDump" | T1003.001 | `rundll32 comsvcs MiniDump` |
| "Exfiltrated with rclone to MEGA" | T1567.002 | rclone process + MEGA domains |

Then: check detection coverage for each → hunt → build missing detections.

---

## 5. Source Evaluation (Admiralty Code)

| Reliability | | Credibility | |
|---|---|---|---|
| A | Completely reliable | 1 | Confirmed by other sources |
| B | Usually reliable | 2 | Probably true |
| C | Fairly reliable | 3 | Possibly true |
| D | Not usually reliable | 4 | Doubtful |
| E | Unreliable | 5 | Improbable |
| F | Cannot be judged | 6 | Cannot be judged |

Rate as e.g. **B2**.

---

## 6. Estimative Language

| Term | Probability |
|---|---|
| Almost certain | 95–99% |
| Highly likely | 80–95% |
| Likely | 55–80% |
| Roughly even chance | 45–55% |
| Unlikely | 20–45% |
| Highly unlikely | 5–20% |
| Remote | 1–5% |

Separate **confidence** (quality of evidence: high/moderate/low) from **likelihood**.

---

## 7. TLP 2.0

| Label | Sharing |
|---|---|
| TLP:RED | Named recipients only |
| TLP:AMBER+STRICT | Recipient's organization only |
| TLP:AMBER | Organization and its clients/need-to-know |
| TLP:GREEN | Community, not public |
| TLP:CLEAR | Public |

---

## 8. Attribution Caution

- Distinguish **activity cluster** from **named actor**; vendors use different names for overlapping clusters
- Shared tooling (Cobalt Strike, open-source loaders) ≠ same actor
- Attribution rarely changes SOC actions; TTPs do. State attribution with confidence and evidence, or omit

---

## 9. Sources

| Type | Examples |
|---|---|
| Government | CISA advisories & KEV, NCSC, ACSC, CERT-PH/DICT advisories |
| Vendor research | Microsoft Threat Intelligence, Mandiant/Google, Unit 42, Talos, CrowdStrike, Sophos, Kaspersky, ESET, Check Point |
| Community | abuse.ch (URLhaus, ThreatFox, MalwareBazaar), AlienVault OTX, MISP communities |
| Sector ISACs | FS-ISAC, H-ISAC, regional ISACs |
| Internal | Incidents, phishing reports, hunt findings (highest relevance) |

---

## 10. Intel Product Template

```markdown
## <Title> — TLP:<label> — <date>
Bottom line up front: <1–3 sentences with likelihood + confidence>
Relevance to us: <assets, sector, exposure>
Key TTPs (ATT&CK): <table>
Indicators: <table, defanged, with first/last seen + source rating>
Detection coverage: <covered / partial / gap per TTP>
Recommended actions: <hunt, detect, patch, block — owners>
Sources: <list with Admiralty ratings>
```

---

## Engagement Cheatsheet

```text
PIR → collect → extract TTPs → map ATT&CK → coverage check → hunt + detect + patch
→ product (BLUF, TLP, confidence) → feedback
```

---

## Key References

- Diamond Model of Intrusion Analysis (Caltagirone, Pendergast, Betz)
- FIRST TLP 2.0 — https://www.first.org/tlp/
- ICD 203 Analytic Standards (estimative language)
- MITRE ATT&CK v18
- Related: `defensive-attack-mapping`, `defensive-ioc-management`, `defensive-threat-hunting`
