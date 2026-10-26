---
name: defensive-psirt-disclosure-handling
description: "Running the vendor or maintainer side of coordinated vulnerability disclosure (PSIRT): CVD policy and safe harbor (ISO/IEC 29147:2018, 30111:2019, FIRST PSIRT Services Framework 1.1, disclose.io, DOJ 2022 CFAA policy), intake channels (RFC 9116 security.txt, GitHub Private Vulnerability Reporting, platforms), triage SLAs and AI-generated report floods, EU CRA Article 14 reporting via the ENISA Single Reporting Platform (24h/72h/14-day clocks since 11 Sep 2026), CVE assignment as a CNA (CNA Rules 4.2.6, CVE JSON 5.2.0) given reduced NVD enrichment, CVSS 4.0/SSVC supplier prioritization, fix and variant validation, CSAF 2.0 advisories and VEX, embargo and multi-party coordination, and PSIRT metrics. Use when receiving vulnerability reports about your own product or project, setting up a PSIRT or VDP, or publishing advisories."
---

# PSIRT & Disclosure Handling

The receiving side of `defensive-cve-researcher`. A report about your product starts several clocks at once: the reporter's deadline (typically 90 days), possible legal reporting (EU CRA: 24 hours when actively exploited), and attackers diffing your patch. Treat intake as an operational process with owners and SLAs, not an inbox.

## Quick Workflow

1. Publish a CVD policy + safe harbor + `security.txt`; enable private reporting channels
2. Acknowledge fast; open a private tracking case per report
3. Triage: reproduce, scope affected versions, score (CVSS 4.0 + 3.1, SSVC supplier tree), **decide "actively exploited?" the same day**
4. If exploited and you sell into the EU → CRA early warning ≤24h via ENISA SRP
5. Fix privately; test against the PoC **and variants**; backport to supported versions
6. Reserve/assign CVE (your CNA, GitHub CNA, or a Root/CNA-LR); write a complete record
7. Coordinate date with reporter and downstreams; publish advisory (CSAF 2.0 + human page) and VEX
8. Credit reporter; post-incident review; feed metrics

---

## 1. Policy & Safe Harbor

| Element | Guidance |
|---|---|
| Standards | ISO/IEC 29147:2018 (disclosure) and 30111:2019 (handling) are current; 29147 Ed. 3 is early-stage (registered Oct 2025). FIRST PSIRT Services Framework v1.1 for service areas. |
| Scope | Products, versions, and services covered; out-of-scope list (DoS against prod, social engineering, physical) |
| Safe harbor | Base on disclose.io terms: good-faith research authorized, no legal action, CFAA/anti-circumvention waiver for in-scope testing. DOJ's 19 May 2022 policy says not to charge good-faith security research under CFAA, but your own written authorization is stronger. |
| Commitments | Ack time, update cadence, target fix window, credit policy, CVE assignment, disclosure deadline |
| AI-assisted reports | State that reports must include a reproducible PoC and a human-verified impact; repeat unverified submitters may be blocked |
| EU CRA | A CVD policy with a contact address is a mandatory essential requirement from 11 Dec 2027 (Annex I Part II) — publish now |

`/.well-known/security.txt` (RFC 9116) — over HTTPS; `Contact` and `Expires` are required; keep `Expires` under one year; sign with OpenPGP:

```text
Contact: mailto:security@example.com
Contact: https://github.com/example/product/security/advisories/new
Expires: 2027-10-01T00:00:00Z
Encryption: https://example.com/pgp-key.txt
Policy: https://example.com/security/cvd-policy
Acknowledgments: https://example.com/security/hall-of-fame
Preferred-Languages: en
Canonical: https://example.com/.well-known/security.txt
```

Add `SECURITY.md` to every repo (supported versions table, how to report, what to expect). Calendar-alert the `Expires` date.

---

## 2. Intake Channels

| Channel | Notes |
|---|---|
| security@ mailbox + PGP | Route to a ticket queue, not a person; monitored by a rota |
| GitHub Private Vulnerability Reporting | Repo Settings → Code security → enable. Reporter opens a draft GHSA and becomes a collaborator. Accept, ask questions, or reject. |
| GitHub temporary private fork | Fix privately from the advisory; PRs in it merge together, not individually |
| GitLab | Confidential issues + SECURITY.md; GitLab CNA for GitLab.com projects |
| Bug bounty / VDP platform | HackerOne, Bugcrowd, Intigriti, YesWeHack — buys triage capacity; costs money and gives platform-specific rules |
| Coordinators | CERT/CC (VINCE), national CSIRTs (NIS2 Art. 12 CVD coordinators), ENISA — expect cases from them |

Never let reports land in public issue trackers: add an issue template that redirects security reports.

---

## 3. Triage & SLAs

Suggested internal SLAs (not mandated; set your own and publish them):

| Stage | Target |
|---|---|
| Acknowledge | 1–3 business days |
| Exploited-in-the-wild decision | Same day (CRA 24h clock) |
| Validate + score | 7–10 days |
| Fix (critical/high) | Well under 90 days |
| Reporter updates | At least every 2 weeks |

Benchmarks reporters hold you to: Google Project Zero 90 days + 30 days after a patch (and since July 2025 it publicly lists vendor, product and deadline about a week after reporting); ZDI 120 days, faulty patches 30/60/90 days.

Triage checklist:

```text
[ ] Reproduced in an isolated lab on a supported version (record exact commit/build)
[ ] Root cause + CWE identified; affected version range (introduced/fixed commits)
[ ] Independent bugs split — CNA Rules: separate IDs for independently fixable vulnerabilities
[ ] Duplicates checked (own tracker, GHSA, OSV, EUVD, CVE list)
[ ] Severity: CVSS 4.0 + 3.1 vectors; SSVC supplier decision (patch development priority)
[ ] Exploitation evidence? (KEV, threat intel, customer IR, reporter info) → CRA gate
[ ] Third-party component at fault? → report upstream (CRA Art. 13(6)), coordinate
[ ] Not a vulnerability? → explain why with evidence; EoL status alone is not a vulnerability (CNA Rules 4.1.13)
```

### AI-generated report floods

2026 lesson: curl ended its paid bounty on 31 Jan 2026 (confirmed rate fell below 5%) and paused all intake 1 Jul–3 Aug 2026; HackerOne paused the Internet Bug Bounty in Mar 2026; Nextcloud ended its bounty in Apr 2026. AI tools also find real bugs at scale, so volume rises either way.

- Require a minimal reproducer and exact version; close "theoretical" reports with a template
- Keep a fast-reject path (≤10 minutes) and a reporter reputation list
- Consider unpaid intake or invite-only bounties if signal collapses
- Budget triage headcount for growth; it is now the bottleneck

---

## 4. EU CRA Article 14 Reporting

Applies since **11 Sep 2026** to manufacturers placing products with digital elements on the EU market. Clocks start at awareness and do not pause for weekends. Exploitation known before 11 Sep 2026 is not retroactively reportable (per Commission guidance as reported).

| Trigger | Early warning | Notification | Final report |
|---|---|---|---|
| Actively exploited vulnerability | ≤24h (incl. Member States where product is available) | ≤72h | ≤14 days after a fix or mitigation is available |
| Severe incident affecting product security | ≤24h | ≤72h | ≤1 month after the notification |

- Submit via ENISA **Single Reporting Platform**: `https://portal.cra-srp.enisa.europa.eu/` (EU Login). One submission reaches the coordinating CSIRT and ENISA.
- Register one Primary and up to 20 Secondary Assigned Representatives; cover nights and holidays.
- Pre-template all three reports; store the evidence used for the "actively exploited" decision.
- Also from 11 Dec 2027: SBOM (at least top-level dependencies), free security updates separate from feature updates where feasible, declared support period (generally ≥5 years).
- OSS stewards have lighter duties (Art. 24) — check whether you are a manufacturer or a steward.

Not legal advice — confirm scope with counsel.

---

## 5. CVE Assignment

| Path | When |
|---|---|
| Become a CNA | Regular volume; apply via cve.org, onboard under a Root (MITRE, CISA, ENISA Root since Nov 2025, others) with a scope, disclosure policy, and advisory URL |
| GitHub CNA | Project on GitHub: request CVE from the draft GHSA; usually reviewed within 72h; request stays private |
| Other CNA / CNA-LR | Upstream vendor CNA, VulDB, CERT/CC, MITRE CNA-LR |

Rules and format:

- CNA Operational Rules **v4.2.6** effective 20 Oct 2026 (deprecates 4.2.0)
- CVE Record Format **5.2.0** — adds optional `packageURL` (PURL) in `affected`; validate before publishing (Vulnogram supports it)
- **Write a complete record yourself**: since 15 Apr 2026 NVD enriches mainly KEV, federal and EO 14028 critical-software CVEs and relies on the CNA's severity score. CISA ADP Vulnrichment adds SSVC points in its own container but won't fix your data.

Minimum record content: description (product, versions, CWE-style weakness, impact, attack vector), affected version ranges + PURL, CWE ID, CVSS 4.0 and 3.1 vectors, references (advisory, fix commit, release notes), credits.

Program context: the April 2025 MITRE contract near-lapse was resolved (renegotiated; CISA says fully funded), but keep alternatives in mind — EUVD (ENISA, launched 13 May 2025) aliases CVE/GHSA IDs; GCVE exists as a decentralized scheme.

---

## 6. Fix & Validate

- Fix on a private branch/fork; minimize descriptive commit messages until disclosure
- Regression-test against the reporter's PoC **and** variants (same sink elsewhere, encoding bypasses, alternate entry points) — run Semgrep/CodeQL for the pattern across the codebase
- Backport to every supported version; list unfixed-but-supported branches explicitly
- Offer the reporter a fix review before release
- Patch diffing is fast (AI-accelerated) — release fix and advisory together; don't ship silent fixes days earlier

A bypass of your fix is a new CVE with a shorter clock (ZDI faulty-patch timelines start at 30 days).

---

## 7. Coordination & Embargo

- Agree the disclosure date with the reporter in writing; renegotiate early, not on day 89
- Multi-vendor issues: follow FIRST Multi-Party Coordination Guidelines v1.1; use CERT/CC VINCE or the national CSIRT as coordinator
- Pre-notify downstream distributors/major customers under NDA only when necessary; every extra party raises leak risk
- Leak plan: have the advisory and mitigation drafted from day one so you can publish within hours if details go public

---

## 8. Advisories & VEX

| Format | Status |
|---|---|
| CSAF 2.0 | OASIS Standard (Nov 2022) — publish this; VEX profile uses `/document/category` = `csaf_vex` |
| CSAF 2.1 | Not approved; CSD04 public review ends 6 Nov 2026 — track, don't depend on |
| CycloneDX VEX / OpenVEX v0.2.0 | Alternatives; both map to CISA minimum statuses |

CISA VEX minimum requirements: statuses `not_affected`, `affected`, `fixed`, `under_investigation`; `not_affected` needs a justification (5 CISA justifications) or impact statement; `affected` needs an action statement; include author, ID, version, timestamps.

Human advisory template:

```markdown
# [ID] <Weakness> in <Product> <affected versions>

**Severity:** CVSS:4.0/... (score) | CVSS:3.1/... (score)
**CVE:** CVE-YYYY-NNNNN  **CWE:** CWE-NNN
**Affected:** >= x.y.0, < x.y.5   **Fixed:** x.y.5
**Exploited in the wild:** No / Yes (since <date>)

## Impact
## Patches
## Workarounds / mitigations
## Detection (logs or IOCs defenders can check)
## Timeline (reported, acknowledged, fixed, published)
## Credit
```

Tools: Secvisogram (CSAF editor), csaf-validator-lib, Vulnogram (CVE JSON). Publish CSAF under a discoverable `provider-metadata.json` (CSAF trusted provider rules).

---

## 9. Metrics

| Metric | Use |
|---|---|
| Median time to acknowledge / triage / fix / disclose | SLA tracking |
| Reports by validity (valid, duplicate, invalid, AI-slop) | Capacity planning, policy changes |
| Fixes needing a second patch (incomplete fix rate) | Fix quality |
| CRA reports filed on time | Compliance |
| Records with full CVSS/CWE/affected/PURL | Data quality |
| Root-cause CWE trends | Feed secure SDLC (`defensive-secure-code-review`) |

---

## Engagement Cheatsheet

```text
policy (29147/30111, disclose.io safe harbor, AI-report rule) + security.txt (Contact, Expires <1y) + SECURITY.md + GitHub PVR
→ ack ≤3 business days → reproduce in lab, scope versions, split independent bugs, CVSS 4.0+3.1, SSVC supplier
→ exploited? same-day decision → CRA SRP: 24h early warning / 72h notification / 14 days after fix
→ private fix + PoC/variant regression + backports → CVE via own CNA / GitHub CNA (Rules 4.2.6, JSON 5.2.0, complete record — NVD won't enrich)
→ agreed date, multi-party via CERT/CC or national CSIRT → CSAF 2.0 advisory + VEX + human page with detection → credit → metrics
```

---

## Key References

- ISO/IEC 29147:2018; ISO/IEC 30111:2019; FIRST PSIRT Services Framework v1.1; FIRST Multi-Party Coordination Guidelines v1.1; CERT/CC Guide to CVD; OpenSSF OSS Vulnerability Guide
- RFC 9116; disclose.io; DOJ CFAA charging policy (19 May 2022)
- CVE CNA Operational Rules v4.2.6; CVE Record Format 5.2.0 (github.com/CVEProject/cve-schema); NIST NVD operations update (15 Apr 2026); CISA Vulnrichment
- Regulation (EU) 2024/2847 (CRA) Art. 13–14, Annex I; ENISA CRA Single Reporting Platform; ENISA EUVD
- OASIS CSAF 2.0; CISA Minimum Requirements for VEX (Apr 2023); OpenVEX; CycloneDX VEX
- GitHub docs: privately reporting vulnerabilities, repository security advisories, temporary private forks
- Google Project Zero disclosure policy & Reporting Transparency (Jul 2025); ZDI disclosure policy
- Related: `defensive-cve-researcher`, `defensive-vuln-management`, `defensive-security-testing-program`, `defensive-sbom-slsa`, `defensive-secure-code-review`
