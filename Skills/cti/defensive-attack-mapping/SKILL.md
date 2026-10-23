---
name: defensive-attack-mapping
description: "MITRE ATT&CK and D3FEND mapping for detection coverage and defensive architecture: ATT&CK v18 structure (tactics, techniques, sub-techniques, Detection Strategies, Analytics, Data Components — Data Sources deprecated), mapping alerts/rules/incidents to techniques, ATT&CK Navigator layers, coverage heatmaps and scoring, DeTT&CT, prioritizing gaps by threat relevance, MITRE ATT&CK for ICS and Mobile, MITRE ATLAS for AI, and D3FEND 1.0 defensive technique mapping. Use when building coverage reports, mapping detections, or justifying security investments."
---

# ATT&CK & D3FEND Mapping

ATT&CK describes adversary behavior; D3FEND describes defensive countermeasures. Map both to answer: which behaviors can we see, stop, or neither?

## Quick Workflow

1. Inventory detections and controls
2. Map each to ATT&CK technique(s) and v18 Detection Strategy
3. Score coverage (none / logged / detected / tested / prevented)
4. Weight by threat relevance (actors targeting you)
5. Map gaps to D3FEND countermeasures
6. Publish Navigator layer; prioritize roadmap

---

## 1. ATT&CK v18 Structure (Oct 2025)

| Object | Meaning |
|---|---|
| Tactic | Adversary goal (TA00xx) — 14 Enterprise tactics |
| Technique / Sub-technique | How (T1003 / T1003.001) |
| Detection Strategy | Behavior-focused approach to detect a technique (new in v18) |
| Analytic | Platform-specific detection logic with tunable fields (new in v18) |
| Data Component | Specific telemetry (e.g., Process Creation, Logon Session Creation) |
| Mitigation | M10xx preventive controls |
| Group / Software / Campaign | CTI objects |

v18 removed the old single-sentence "Detection" field and deprecated **Data Sources**; Data Components link directly to Analytics. Enterprise v18: 14 tactics, 216 techniques, 475 sub-techniques, 691 Detection Strategies, 1,739 Analytics.

Enterprise tactics: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

---

## 2. Mapping Rules

- Map to the **most specific** sub-technique supported by evidence
- One behavior can map to multiple techniques (e.g., scheduled task = Execution + Persistence T1053.005)
- Map what the detection actually sees, not what the attacker eventually achieved
- Record procedure-level detail; technique-level coverage is coarse ("we detect T1059" means little)

---

## 3. Coverage Scoring

| Score | Meaning |
|---|---|
| 0 | No telemetry |
| 1 | Telemetry collected, no detection |
| 2 | Detection exists, untested |
| 3 | Detection tested (emulation passed) |
| 4 | Detection tested + prevention control |

Weight: `priority = threat_relevance × impact × (4 − score)`.

---

## 4. Navigator Layer (JSON skeleton)

```json
{
  "name": "Detection Coverage 2026-Q4",
  "versions": { "attack": "18", "navigator": "5.1", "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [
    { "techniqueID": "T1003.001", "score": 3, "comment": "Sysmon10 LSASS rule; ART T1003.001-1 pass" },
    { "techniqueID": "T1558.003", "score": 2, "comment": "4769 RC4 rule; untested" }
  ],
  "gradient": { "colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 4 }
}
```

Generate automatically from detection repo tags (see `defensive-detection-as-code`). Verify version fields against your Navigator release.

---

## 5. Threat-Informed Prioritization

1. Select actors/campaigns relevant to sector/region
2. Build union layer of their techniques
3. Overlay coverage layer → gaps = high-relevance, low-score techniques
4. Plan: telemetry fixes → detections → tests → preventive controls

Tools: ATT&CK Navigator, DeTT&CT (data source + visibility + detection scoring), CTID Top ATT&CK Techniques, CTID Mappings Explorer (security controls → ATT&CK).

---

## 6. D3FEND 1.0

D3FEND (MITRE, 1.0 released Dec 2024/Jan 2025) is an ontology of defensive techniques with inferred mappings to ATT&CK via digital artifacts.

| D3FEND tactic | Example techniques |
|---|---|
| Model | Asset inventory, network mapping |
| Harden | Credential hardening, application hardening, platform hardening |
| Detect | Process analysis, network traffic analysis, user behavior analysis, file analysis |
| Isolate | Network isolation, execution isolation |
| Deceive | Decoy environment, decoy object |
| Evict | Credential eviction, process eviction |
| Restore | Restore access, restore object |

Use D3FEND to describe *what kind* of control closes a gap (vendor-neutral), e.g., T1003.001 → Credential Hardening (LSA protection / Credential Guard) + Process Analysis (LSASS access monitoring). Use D3FEND CAD tool to diagram attack/defense graphs.

---

## 7. Other Matrices

| Matrix | Scope |
|---|---|
| ATT&CK for ICS | OT/ICS (Purdue L0–L3) |
| ATT&CK Mobile | Android/iOS |
| MITRE ATLAS | Adversarial ML / AI systems |
| MITRE ENGAGE | Adversary engagement / deception planning |

---

## 8. Reporting

```markdown
## ATT&CK Coverage — <scope> — <date>
Techniques in threat profile: <n>  | Covered (score ≥3): <n> (<%>)
Top gaps (priority order):
| Technique | Relevance | Score | Needed telemetry | Planned control (D3FEND) | Owner | ETA |
```

---

## Engagement Cheatsheet

```text
inventory → map (sub-technique + Detection Strategy) → score 0–4 → threat overlay
→ gaps → D3FEND controls → roadmap → re-test quarterly
```

---

## Key References

- MITRE ATT&CK v18 release notes (Oct 2025) — https://attack.mitre.org/resources/updates/
- ATT&CK Navigator — https://mitre-attack.github.io/attack-navigator/
- MITRE D3FEND — https://d3fend.mitre.org
- DeTT&CT; CTID Mappings Explorer
- Related: `defensive-detection-as-code`, `defensive-purple-team`, `defensive-cti`
