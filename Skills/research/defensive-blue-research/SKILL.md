---
name: defensive-blue-research
description: "Research methodology for blue teams, applied before any defensive decision: framing the research question, source hierarchy (vendor docs and advisories, standards, CVE/KEV/PSIRT, release notes and source code, peer-reviewed and vendor research, community), verifying currency (versions, dates, changelogs, git tags), triangulating at least two independent sources, grading evidence (Admiralty/NATO reliability and credibility), lab reproduction and detection validation, analyzing applicability and impact in your environment, generating options with trade-offs, writing recommendations, and documenting with citations. Workflows for CVEs, tools, detections, threat actors, products, and AI-assisted research. Use whenever a defensive task depends on facts that may have changed."
---

# Blue Team Research Methodology

Defensive decisions made from stale or unverified facts fail quietly: a mitigation that no longer works, a tool version with a known compromise, a detection for a field that was renamed. **Research first, verify currency, test in a lab, then recommend.** Every claim in a deliverable should trace to a source with a date.

## Quick Workflow

1. **Frame**: write the question, the decision it supports, scope, and deadline
2. **Collect**: primary sources first (§2), then secondary sources
3. **Verify currency**: versions, publication dates, "last updated", changelogs (§3)
4. **Triangulate**: at least two independent sources for key claims; grade them (§4)
5. **Reproduce**: test in a lab — behavior, detection, mitigation side effects (§5)
6. **Analyze**: applicability to *your* environment, impact, options and trade-offs (§6)
7. **Recommend**: decision, rationale, confidence, residual risk, owner, review date (§7)
8. **Document**: research log with citations, retrieval dates, open questions

---

## 1. Framing the Question

| Element | Example |
|---|---|
| Question | "Are we exposed to CVE-2026-XXXX, and what should we do in 72 h?" |
| Decision supported | Emergency patch vs mitigation vs accept |
| Scope | Internet-facing Fortinet devices, all sites |
| Constraints | Change freeze, no downtime on payment systems |
| Deadline | KEV due date / BOD 26-04 tier / leadership meeting |
| Definition of done | Exposure list + mitigation plan + detection + verification steps |

Bad questions ("tell me about ransomware") produce bad research. Narrow to a decision.

---

## 2. Source Hierarchy

| Tier | Sources | Use for |
|---|---|---|
| 1. Primary / authoritative | Vendor security advisories (PSIRT), official documentation, release notes, source code and commit history, standards text (NIST, RFC, ISO, CIS), regulator texts, CISA KEV/advisories, national CERTs (CERT-PH, JPCERT, NCSC) | Facts: affected versions, fixed versions, configuration, legal requirements |
| 2. Structured data | NVD/CVE records, EPSS, OSV, GitHub Security Advisories, ATT&CK/D3FEND, vendor bulletins APIs | Correlation, prioritization (note NVD enrichment limits since April 2026) |
| 3. Expert analysis | Vendor threat research (Mandiant, Microsoft, Talos, Unit 42, CrowdStrike, Red Canary), DFIR Report, peer-reviewed papers, conference talks | Tradecraft, detection ideas, context |
| 4. Community | Blogs, GitHub PoCs, mailing lists, social media, forums | Leads only — verify before use |
| 5. AI-generated text | LLM answers, auto-summaries | Drafting and leads only — verify every factual claim against tiers 1–3 |

Rules:
- Prefer the **source closest to the fact** (the vendor advisory, not a news article about it)
- A secondary source repeating a primary source is **not** independent corroboration
- Note what each source does **not** say (missing affected versions, unclear workarounds)

---

## 3. Verifying Currency

| Check | How |
|---|---|
| Publication and last-updated date | Page metadata, advisory revision history |
| Current tool version | Official releases page, `git ls-remote --tags <repo>`, package registry, vendor download portal |
| Changelog/breaking changes | Release notes between your version and current |
| Advisory revisions | Vendors update affected/fixed versions — re-check before acting |
| Product lifecycle | End-of-support dates (vendor lifecycle pages) |
| Standards versions | e.g., NIST CSF 2.0, ATT&CK v18, OWASP Top 10:2025, PCI DSS 4.0.1 |
| Field and schema names | Current docs for log schemas (renamed tables/fields break queries) |

```bash
git ls-remote --tags --refs https://github.com/<org>/<tool> | awk -F'refs/tags/' '{print $2}' | sed 's/^v//' | sort -V | tail -5
pip index versions <package> 2>/dev/null | head -1
npm view <package> version time.modified
```

Write the retrieval date next to every version-sensitive fact: "Velociraptor 0.77.3 (checked 2026-10-23)".

---

## 4. Triangulation & Evidence Grading

Admiralty / NATO system:

| Source reliability | | Information credibility | |
|---|---|---|---|
| A | Completely reliable | 1 | Confirmed by other independent sources |
| B | Usually reliable | 2 | Probably true |
| C | Fairly reliable | 3 | Possibly true |
| D | Not usually reliable | 4 | Doubtful |
| E | Unreliable | 5 | Improbable |
| F | Cannot be judged | 6 | Cannot be judged |

Report key claims as e.g. "B2". Confidence language (from intelligence practice): **high** (multiple reliable sources, consistent, tested), **moderate** (credible but gaps), **low** (single or questionable source). Never upgrade confidence because a claim is repeated widely.

Counter-checks:
- Seek **disconfirming** evidence (Is there a vendor statement that the PoC doesn't work on patched builds?)
- Check for conflicts of interest (vendor marketing, competitor research)
- Separate facts, assessments, and assumptions explicitly

---

## 5. Lab Reproduction

| What | Why |
|---|---|
| Reproduce behavior in an isolated lab (`defensive-soc-building`) | Confirms claims and generates real telemetry |
| Test detections against the reproduced behavior | A rule untested against real events is a hypothesis |
| Test mitigation side effects | Registry/GPO changes can break apps (e.g., NTLM restrictions, RC4 removal) |
| Record exact versions/configs | Results depend on them |
| Use safe material | Benign simulations (Atomic Red Team), vendor-provided test files (EICAR, AMTSO), never live malware outside a contained analysis lab |

Never test against production or third-party systems without written authorization.

---

## 6. Analysis — What Should Be Done

| Question | Output |
|---|---|
| Does it apply to us? | Asset/version match from inventory, configuration preconditions, exposure (internet-facing?) |
| What's the impact if exploited? | Business impact on crown jewels, data, safety |
| How likely? | KEV/EPSS/exploitation reports, attacker interest in our sector, compensating controls |
| What are the options? | Patch, mitigate/workaround, compensating control, isolate/decommission, accept, transfer |
| Trade-offs | Effort, downtime, risk reduction, side effects, reversibility, time to implement |
| How will we know it worked? | Verification test, detection, metric |
| What's still uncertain? | Gaps and assumptions; triggers for re-evaluation |

Option comparison template:

| Option | Risk reduction | Effort | Downtime | Side effects | Time | Reversible |
|---|---|---|---|---|---|---|
| Patch to fixed version | High | Medium | 30 min/device | Low | 3 days | Yes (rollback image) |
| Disable feature (workaround) | Medium–High | Low | None | Feature loss | 1 day | Yes |
| Restrict exposure (ACL/geo) | Medium | Low | None | Partner access | Hours | Yes |
| Accept | None | — | — | — | — | — |

---

## 7. Recommendation Format

```markdown
## Recommendation: <action>
Decision needed by: <date> | Owner: <name/team> | Confidence: <high/moderate/low>
Bottom line: <one or two sentences>
Why: <evidence summary with source grades>
Applicability: <affected assets / not affected>
Plan: <steps, sequencing, rollback>
Verification: <how we confirm success>
Residual risk: <what remains, who accepts it>
Re-evaluate if: <new advisory revision, exploitation change, date>
Sources: <list with retrieval dates>
```

---

## 8. Workflows by Research Type

| Type | Steps |
|---|---|
| CVE / vulnerability | Vendor advisory → affected/fixed versions → KEV/EPSS/exploitation reports → our inventory match → exposure → patch/mitigate options → detection for exploitation attempts → verify (`defensive-vuln-management`) |
| Tool evaluation | Official docs + releases → maintenance activity (commits, releases, issues) → security advisories for the tool itself → license → supply chain (signatures, provenance) → lab test → deployment hardening (`defensive-tool-safety`) |
| Detection research | Technique (ATT&CK) → real procedures from reports → telemetry available → reproduce → write rule → test FP against baseline → document (`defensive-detection-as-code`) |
| Threat actor | Reputable reports (tier 3) + government advisories → TTPs mapped to ATT&CK → relevance to our sector → prioritized defenses (`defensive-threat-informed-defense`) |
| Product/vendor | Requirements → independent tests (MITRE ATT&CK Evaluations, AV-TEST, SE Labs) → references → PoC in our environment → security posture of the vendor itself → contract terms |
| Regulation/compliance | Official legal text and regulator guidance → effective dates → applicability → gap analysis → legal review |
| Incident research (during IR) | Artifacts → known-good baselines → intel lookups (hash/domain/IP) → technique identification → scoping queries; record every lookup in the case log |

---

## 9. AI-Assisted Research Discipline

- Treat model output as a draft: verify **every** version number, CVE ID, date, command flag, event ID, and field name against primary sources
- Ask for sources, then open them; never cite a source you have not read
- Prefer live retrieval (search, docs, release APIs) over recall for anything that changes
- Don't paste sensitive incident data into external tools without approval
- Keep a log of prompts/answers used in decisions for auditability

---

## 10. Pitfalls

| Pitfall | Countermeasure |
|---|---|
| Anchoring on the first source | Collect several before concluding |
| Recency blind spot (outdated blog post) | Check dates; check for advisory revisions |
| Version drift (docs for wrong version) | Match docs to deployed version |
| Lab ≠ production | Note differences; pilot before fleet rollout |
| Copy-paste commands from untrusted sources | Read and understand before running; test in lab |
| Over-confidence | State confidence and gaps explicitly |

---

## Engagement Cheatsheet

```text
frame (question → decision → scope → deadline) → primary sources first → verify currency (dates, versions, changelogs, git tags)
→ triangulate ≥2 independent + Admiralty grade → lab reproduce + test detection/mitigation → analyze applicability/impact/options/trade-offs
→ recommendation (bottom line, confidence, plan, verification, residual risk, re-evaluate triggers) → cite with retrieval dates
```

---

## Key References

- NATO AJP-2.1 / Admiralty Code (source & information grading); Sherman Kent / ICD 203 analytic standards (confidence language)
- CISA KEV; FIRST EPSS; NVD; OSV; vendor PSIRT pages
- Heuer, "Psychology of Intelligence Analysis" (cognitive biases, Analysis of Competing Hypotheses)
- Related: `defensive-tool-safety`, `defensive-cti`, `defensive-vuln-management`, `defensive-soc-building`, `defensive-threat-informed-defense`
