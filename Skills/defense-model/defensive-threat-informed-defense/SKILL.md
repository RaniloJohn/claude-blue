---
name: defensive-threat-informed-defense
description: "Threat-informed defense program: using CTI and MITRE ATT&CK to prioritize what to defend, MITRE Center for Threat-Informed Defense (CTID) resources (Top ATT&CK Techniques, Mappings Explorer for NIST 800-53/CIS/cloud controls, Sensor Mappings to ATT&CK, Summiting the Pyramid, Attack Flow, adversary emulation library), threat profiles per sector, technique prioritization by prevalence/choke points/actionability, coverage heatmaps with ATT&CK Navigator and DeTT&CT, validating with emulation and BAS, and a continuous loop of intel to detection to test to metrics. Use when deciding which threats and techniques to prioritize or building a coverage-driven roadmap."
---

# Threat-Informed Defense

Defend against what adversaries actually do to organizations like yours. The loop: **know the threat → map your defenses → test them → close gaps → measure**.

## Quick Workflow

1. Build a threat profile (actors and techniques relevant to your sector/region/tech stack)
2. Prioritize techniques (prevalence × choke point × actionability)
3. Map existing controls and detections to those techniques
4. Validate with emulation (Atomic Red Team, Caldera, BAS)
5. Close gaps; track coverage and validated-detection metrics

---

## 1. Threat Profile

| Input | Source |
|---|---|
| Sector threats | ISAC reports (FS-ISAC, H-ISAC, etc.), national CERT advisories (CISA, CERT-PH, JPCERT), vendor annual reports (Mandiant M-Trends, CrowdStrike GTR, Red Canary Threat Detection Report, DBIR) |
| Actor TTPs | ATT&CK Groups/Campaigns pages, CISA advisories with ATT&CK tables |
| Your incidents | Internal IR history, red team findings |
| Your tech stack | Which platforms the techniques require (no point prioritizing macOS techniques in an all-Windows fleet) |

Output: a Navigator layer of techniques with a score per technique.

---

## 2. Prioritization Criteria

| Criterion | Meaning |
|---|---|
| Prevalence | How often seen in the wild (Red Canary top techniques, CTID Top ATT&CK Techniques calculator) |
| Choke point | Many attack paths converge (e.g., T1059 interpreters, T1003 credential dumping, T1021 remote services) |
| Actionability | You have data sources and controls to detect/mitigate it |
| Impact | Consequence if successful (T1486, T1490) |
| Relevance | Used by actors in your profile |

CTID Top ATT&CK Techniques methodology weighs prevalence, choke-point, and actionability — use its calculator with your own platform filters.

---

## 3. Map Defenses

| Mapping | Tool/resource |
|---|---|
| Detections → techniques | Sigma/SIEM rule tags; detection repo metadata |
| Controls → techniques | CTID **Mappings Explorer** (NIST 800-53, CIS Controls, AWS, Azure, GCP, M365, Veris, KEV → ATT&CK) |
| Sensors → techniques | CTID **Sensor Mappings to ATT&CK** (which telemetry sees which technique) |
| Data source coverage | DeTT&CT (data source quality scoring + visibility/detection layers) |
| Mitigations | ATT&CK Mitigations (M####) and D3FEND countermeasures |

```bash
# Example: export Sigma rule ATT&CK tags into a Navigator layer (sigma-cli plugin or custom script)
grep -rhoE 'attack\.t[0-9]{4}(\.[0-9]{3})?' rules/ | sort | uniq -c | sort -rn | head
```

---

## 4. Coverage Heatmap Levels

| Score | Meaning |
|---|---|
| 0 | No visibility |
| 1 | Telemetry collected, no analytic |
| 2 | Analytic exists, untested |
| 3 | Analytic validated by emulation |
| 4 | Validated + automated response + regularly re-tested |

Report coverage as "% of prioritized techniques at ≥ 3", not "% of ATT&CK covered" (100% ATT&CK coverage is neither possible nor meaningful).

---

## 5. Validate

| Method | Use |
|---|---|
| Atomic Red Team | Single-technique tests mapped to ATT&CK |
| MITRE Caldera | Automated adversary emulation chains |
| CTID Adversary Emulation Library | Full actor emulation plans (e.g., FIN6, APT29, menuPass) |
| BAS platforms | Continuous automated validation |
| Purple team exercises | Collaborative test → tune → retest (`defensive-purple-team`) |

Robustness check: CTID **Summiting the Pyramid** — does the analytic survive trivial changes (renamed binary, different parent, obfuscated cmdline)?

---

## 6. Communicate

- **Attack Flow** (CTID) diagrams to show how techniques chain in a real incident
- Before/after Navigator layers for leadership
- Metrics: prioritized technique coverage ≥ 3, mean time to detect in exercises, % detections with tests

---

## Engagement Cheatsheet

```text
threat profile (sector/actors/stack) → prioritize (prevalence × choke point × actionability × impact) → map detections/controls/sensors
(Mappings Explorer, Sensor Mappings, DeTT&CT) → score 0–4 → validate (Atomic/Caldera/BAS/purple) → Summiting robustness → report prioritized coverage
```

---

## Key References

- MITRE CTID: Top ATT&CK Techniques, Mappings Explorer, Sensor Mappings to ATT&CK, Summiting the Pyramid, Attack Flow, Adversary Emulation Library
- ATT&CK Navigator; DeTT&CT; Red Canary Threat Detection Report
- Related: `defensive-attack-mapping`, `defensive-cti`, `defensive-purple-team`, `defensive-adversary-emulation`, `defensive-detection-as-code`
