---
name: defensive-threat-hunting
description: "Threat hunting methodology and program design: PEAK framework (hypothesis-driven, baseline/exploratory, model-assisted M-ATH), TaHiTI (intel-driven), Hunting Maturity Model, Pyramid of Pain, hypothesis writing, data source readiness, stacking/long-tail analysis, frequency and temporal analysis, behavioral baselining, anomaly detection, hunt documentation, and converting hunts into detections. Use when planning or running a hunt, writing hunt hypotheses, building a hunt backlog from threat intel or ATT&CK, or reporting hunt outcomes."
---

# Threat Hunting

Hunting is a structured search for adversary behavior that detections miss. A hunt is successful if it produces knowledge: a finding, a new detection, a closed telemetry gap, or a refuted hypothesis.

## Quick Workflow (PEAK)

1. **Prepare** — topic, hypothesis, data, scope, timebox
2. **Execute** — gather data, baseline, analyze, refine
3. **Act with Knowledge** — document, escalate findings, create detections, close gaps

---

## 1. Hunt Types

| Type | Driver | Example |
|---|---|---|
| Hypothesis-driven | Specific TTP or intel | "Kerberoasting via RC4 requests from workstations" |
| Baseline (exploratory) | Understand normal, find outliers | Stack all services installed in 90 d |
| Model-assisted (M-ATH) | ML/statistics surface anomalies | Beacon scoring, rare logon patterns |
| Intel-driven (TaHiTI) | CTI report on actor/campaign | IOCs + TTPs from a vendor report |
| Situational | New exposure/vuln/incident | Edge appliance CVE in KEV → hunt for exploitation |

---

## 2. Writing Hypotheses

Format: **If [actor/technique] is present in [scope], we will observe [observable] in [data source] during [window].**

Good hypothesis properties: testable, scoped, tied to ATT&CK, names data source, can be refuted.

| Weak | Strong |
|---|---|
| "Look for bad PowerShell" | "If adversaries use PowerShell download cradles on workstations, 4104 script blocks will contain `Net.WebClient`/`Invoke-WebRequest`/`IWR` with non-corporate URLs in the last 30 d" |
| "Find C2" | "If an implant beacons over HTTPS, Zeek conn.log will show ≥50 connections from one host to one destination with interval coefficient of variation <0.1 over 24 h" |

---

## 3. Data Readiness Check

| Question | Fail action |
|---|---|
| Is the source collected for ≥90% of scope? | Narrow scope or open collection ticket |
| Are required fields parsed? | Fix parsing first |
| Is retention ≥ hunt window? | Shorten window, note limitation |
| Is clock sync reliable? | Note skew |

---

## 4. Analysis Techniques

| Technique | How | Finds |
|---|---|---|
| Stacking / long tail | Count by attribute; review the bottom | Rare binaries, services, autoruns |
| Frequency | Events per entity per time | Spikes, low-and-slow |
| Temporal | Interval/jitter; off-hours | Beacons, scheduled persistence |
| Relational | Parent-child, user-host, process-network | Abnormal lineage, lateral movement |
| Sequence | A then B within N | Download→execute, logon→service install |
| Clustering | Group similar cmdlines | Obfuscation variants |
| First-seen | New value vs history | New admin tool, new country |
| Peer comparison | Entity vs peers | Server with workstation behavior |

Stacking example (any platform):

```text
group by (ParentImage, Image) → count, distinct hosts → sort ascending → review count<5 and hosts<3
```

---

## 5. Hunt Backlog Sources

- ATT&CK v18 techniques with no detection coverage (from coverage heatmap)
- CTI reports relevant to sector/region
- CISA KEV additions affecting your exposed assets
- Post-incident lessons ("how would we have found this earlier?")
- Red/purple team findings
- New telemetry onboarded (hunt it before writing detections)

Prioritize: likelihood (threat relevance) × impact × data readiness.

---

## 6. Maturity Model (HMM)

| Level | Characteristic |
|---|---|
| HMM0 | Relies on automated alerts only |
| HMM1 | Searches IOCs from intel |
| HMM2 | Follows published hunt procedures |
| HMM3 | Creates own procedures |
| HMM4 | Automates successful hunts into detections |

---

## 7. Validating Findings

For each anomaly:
1. Is there a benign explanation? (change ticket, IT tool, software rollout) — test it
2. Corroborate with a second source (EDR + network, or auth + process)
3. Scope: other hosts/users with same pattern
4. Confidence level (High/Medium/Low) with rationale

---

## 8. Hunt Report Template

```markdown
## Hunt — <name>   ID: H-2026-xxx
Hypothesis: If <technique> in <scope>, then <observable> in <source> during <window>.
Type: Hypothesis | Baseline | Model-assisted | Intel | Situational
ATT&CK: <IDs>   Window: <UTC range>   Analyst: <name>   Timebox: <h>

### Data sources
| Source | Coverage | Retention | Gaps |

### Method & queries
<queries with purpose>

### Findings
| # | Observation | Evidence | Benign tested | Disposition |

### Outcome
Hypothesis: Supported | Refuted | Inconclusive
Incidents: <ids> | Detections created: <ids> | Gaps logged: <tickets> | Hardening: <items>
```

---

## Engagement Cheatsheet

```text
Pick topic → hypothesis → data readiness → baseline → analyze (stack/temporal/relational)
→ validate (benign? corroborate?) → document → detection or gap ticket
```

---

## Key References

- Splunk SURGe — PEAK Threat Hunting Framework (2023)
- TaHiTI — Targeted Hunting integrating Threat Intelligence (FI-ISAC NL)
- David Bianco — Hunting Maturity Model; Pyramid of Pain
- ThreatHunter-Playbook (OTRF)
- Related: `defensive-hunt-windows`, `defensive-hunt-network`, `defensive-cti`, `defensive-detection-as-code`
