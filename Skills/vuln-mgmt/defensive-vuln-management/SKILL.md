---
name: defensive-vuln-management
description: "Risk-based vulnerability management: asset inventory and exposure context, scanning (OpenVAS/Greenbone, Nessus, Qualys, Rapid7, cloud-native Inspector/Defender/SCC), CVSS v4.0 (Base, Threat, Environmental, Supplemental; CVSS-B/BT/BE/BTE), EPSS v4 probabilities, CISA KEV, SSVC decision trees and CISA BOD 26-04 risk-based remediation timelines (exposure, KEV, automatable, technical impact), the 2026 NVD enrichment triage change and alternative data sources (OSV, GHSA, vendor advisories, CNA scores), exception handling, metrics, and EU CRA vulnerability reporting obligations for manufacturers. Use when prioritizing findings, designing VM programs, or explaining scores."
---

# Vulnerability Management

You cannot patch everything; attackers exploit a small fraction of CVEs. Prioritize by **exploitation evidence + exposure + impact**, not CVSS base score alone.

## Quick Workflow

1. Inventory assets with owner, criticality, exposure (internet-facing?)
2. Scan (authenticated) + agent + cloud-native + SCA
3. Enrich: KEV, EPSS, CVSS-BT/BTE, exploit availability, reachability
4. Decide with SSVC / BOD 26-04-style matrix → deadline
5. Remediate or mitigate; verify with rescan
6. Track exceptions, SLAs, and metrics

---

## 1. Scoring Systems

### CVSS v4.0

| Group | Metrics |
|---|---|
| Base | AV, AC, **AT (Attack Requirements, new)**, PR, UI (None/Passive/Active), VC/VI/VA (vulnerable system), SC/SI/SA (subsequent system) |
| Threat | E — Exploit Maturity: Attacked / POC / Unreported |
| Environmental | Security requirements (CR/IR/AR) + modified base metrics |
| Supplemental | Safety, Automatable, Recovery, Value Density, Response Effort, Provider Urgency (informational, no score effect) |

Nomenclature: **CVSS-B** (base only), **CVSS-BT**, **CVSS-BE**, **CVSS-BTE**. Report which one you use. CVSS v3.1 still common in feeds — state version.

### EPSS (FIRST)

- Probability of exploitation activity in next 30 days (0–1) + percentile
- **v4** released 17 March 2025; scores update daily — record the date with each score
- Severity ≠ likelihood: use EPSS with CVSS, not instead

### CISA KEV

- Catalog of vulnerabilities with confirmed exploitation; strongest "act now" signal
- Under **BOD 26-04** (10 June 2026; supersedes BOD 22-01 and BOD 19-02) federal agencies set deadlines from four decision points informed by SSVC: **publicly exposed? in KEV? automatable? technical impact (partial/total)?** — fastest tier is 3 days for exposed + KEV + automatable (+ forensic triage on total control). Full timelines effective for agencies by Dec 2026. Private orgs can adopt the same model; only the exposure variable requires your own data

### SSVC (CERT/CC, CISA)

Decision outcomes: **Track**, **Track\***, **Attend**, **Act**. Decision points include Exploitation (none/PoC/active), Automatable, Technical Impact, Mission/Well-being impact.

---

## 2. Data Sources After the NVD Change

Since **15 April 2026**, NIST NVD only fully enriches CVEs that are in KEV (target 1 business day), affect federal-use software, or are EO 14028 critical software; older backlog moved to "Not Scheduled". Many CVEs now lack NVD CVSS/CPE.

| Source | Use |
|---|---|
| CNA-provided CVSS (in CVE record) | Base score when NVD absent |
| Vendor advisories / PSIRTs | Authoritative affected versions + fixes |
| OSV.dev, GitHub Advisory Database | Open-source ecosystems with precise ranges |
| CISA Vulnrichment (ADP) | SSVC decision points + CVSS for many CVEs |
| EPSS, KEV | Likelihood/exploitation |
| Commercial intel (VulnCheck, etc.) | Exploit/KEV-like extended coverage |
| EUVD (ENISA) | EU vulnerability database |

Scanners that match purely on NVD CPEs will miss findings — validate tool coverage.

---

## 3. Prioritization Matrix (adaptable, BOD 26-04-inspired)

| Exposed | KEV | Automatable | Impact | Target |
|---|---|---|---|---|
| Yes | Yes | Yes | Total | 3 days + compromise assessment |
| Yes | Yes | Yes/No | Partial/Total | 3–7 days |
| No | Yes | — | — | 14 days |
| Yes | No, EPSS ≥ 0.1 | — | Total | 14 days |
| No | No, EPSS ≥ 0.01 or CVSS-BT ≥ 7 on critical asset | — | — | 30 days |
| Else | | | | 90 days / next cycle |

KEV on exposed asset older than patch release → assume compromise possible; hunt before/after patching.

---

## 4. Scanning Practice

```text
[ ] Authenticated scans (credentialed) — unauthenticated misses most local vulns
[ ] Agents for laptops/cloud instances; cloud-native for serverless/containers
[ ] External attack surface scans (what the internet sees)
[ ] Scan windows agreed with ops; exclude fragile OT (passive only)
[ ] Rescan to verify fix; track "reopened" findings
```

Greenbone/OpenVAS: `gvm-cli` / GSA web UI; Nessus: policies with credentials; Nuclei for exposure checks on edge assets.

---

## 5. Mitigation When Patching Isn't Possible

- Disable vulnerable feature/service; restrict exposure (firewall, ZTNA)
- WAF virtual patch; IPS signature
- Application control; EDR prevention rules
- Increased monitoring + specific detection for exploitation
- Document exception: owner, compensating controls, expiry, risk acceptance by business owner

---

## 6. Metrics

| Metric | Meaning |
|---|---|
| KEV exposure count & age | Most important |
| MTTR by priority tier | Program speed |
| SLA compliance % | Accountability |
| Internet-facing critical findings | Attack surface |
| Exceptions past expiry | Hygiene |
| Scan coverage % of inventory | Visibility |

---

## 7. EU Cyber Resilience Act (manufacturers)

From **11 September 2026**, manufacturers of products with digital elements on the EU market must report **actively exploited vulnerabilities** and **severe incidents** via ENISA's Single Reporting Platform: early warning within 24 h, notification within 72 h, final report (14 days after a fix is available for vulnerabilities; one month for incidents). Applies to products already on the market. Full CRA obligations apply from 11 December 2027. PSIRT and VM processes must detect "aware of active exploitation" moments and route to legal.

---

## Engagement Cheatsheet

```text
inventory + exposure → authenticated scans → enrich (KEV, EPSS dated, CVSS-BT, vendor/OSV/Vulnrichment)
→ SSVC/BOD 26-04 matrix → patch or mitigate → verify → exceptions w/ expiry → metrics → CRA reporting if manufacturer
```

---

## Key References

- FIRST CVSS v4.0 spec; FIRST EPSS (v4, March 2025)
- CISA KEV; CISA BOD 26-04 "Prioritizing Security Updates Based on Risk" (June 2026); CERT/CC SSVC
- NIST NVD announcement on enrichment prioritization (April 2026); CISA Vulnrichment
- EU Cyber Resilience Act Art. 14
- Related: `defensive-patch-management`, `defensive-sast-dast`, `defensive-cti`
