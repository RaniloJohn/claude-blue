---
name: defensive-tool-sast
description: "Static analysis tooling for secure code: Semgrep Community Edition (LGPL engine, Semgrep Rules License restrictions on registry rules, metrics opt-out, semgrep scan/ci, custom rules with patterns and taint mode), Opengrep fork (from Semgrep CE 1.100.0, intrafile taint, signed binaries, bring-your-own rules), GitHub CodeQL (licensing for private repos, database creation, security-extended suites, custom queries, code scanning SARIF upload), safe scanning of untrusted repositories (build steps execute code), CI gating, baselining and diff-aware scans, false-positive triage, and SARIF workflows. Use when selecting, running, or tuning SAST in CI or reviewing results."
---

# SAST Tools (Semgrep, Opengrep, CodeQL)

SAST finds dangerous patterns before release. Pick tools by **license fit**, **language coverage**, and **analysis depth**, then tune aggressively — a noisy SAST gets ignored. Observed versions 2026-10-23: Semgrep 1.182.0, Opengrep 1.32.0.

## Quick Workflow

1. Choose engine(s) and confirm license for your use case
2. Run diff-aware scans on PRs; full scans nightly
3. Start with a curated ruleset; add org-specific rules for your frameworks
4. Gate only on high-confidence, high-severity rules; triage others
5. Upload SARIF to code scanning dashboards; track fix SLAs

---

## 1. Licensing (verify before adopting)

| Tool | License notes |
|---|---|
| Semgrep CE engine | LGPL 2.1 |
| Semgrep-maintained rules (`semgrep-rules`, Registry Community + Pro) | **Semgrep Rules License v1.0** (not open source): internal use by individuals/companies OK; vendors may not use in competing products/SaaS |
| Opengrep | LGPL 2.1 fork of Semgrep CE 1.100.0 (not affiliated with Semgrep Inc.); ships no rules — supply your own |
| CodeQL CLI/queries | Free for open-source and research; analyzing private/commercial code generally requires a GitHub Advanced Security / Code Security license — check current GitHub terms |

---

## 2. Semgrep / Opengrep

```bash
semgrep scan --config p/default --metrics=off --sarif -o semgrep.sarif .
semgrep scan --config ./rules --baseline-commit origin/main --error .      # only new findings, non-zero exit on findings
semgrep ci                                                                   # with platform/CI config
opengrep scan -f ./rules --sarif-output=opengrep.sarif .
opengrep scan -f ./rules --taint-intrafile .
```

Custom rule (taint mode):

```yaml
rules:
  - id: flask-ssrf-requests
    mode: taint
    languages: [python]
    severity: ERROR
    message: User-controlled URL reaches requests.* (SSRF)
    metadata: { cwe: "CWE-918", owasp: "A01:2025", confidence: HIGH }
    pattern-sources:
      - pattern: flask.request.args.get(...)
      - pattern: flask.request.json[...]
    pattern-sanitizers:
      - pattern: is_allowed_url(...)
    pattern-sinks:
      - pattern: requests.$METHOD($URL, ...)
        focus-metavariable: $URL
```

Test rules with `# ruleid:` / `# ok:` annotated fixtures: `semgrep --test rules/`.

---

## 3. CodeQL

```bash
codeql database create db-py --language=python --source-root .
codeql database create db-java --language=java --command "./mvnw -B -DskipTests package"     # compiled: build executes!
codeql database analyze db-py codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=codeql.sarif
codeql github upload-results --repository=org/app --ref=refs/heads/main --commit=$SHA --sarif=codeql.sarif
```

Suites: `security-extended` (more queries, more FPs) vs default `code-scanning`. Custom QL queries for internal frameworks (sources/sinks via data extensions/models-as-data YAML).

---

## 4. Scanning Safely

| Risk | Control |
|---|---|
| Building untrusted code executes scripts (CodeQL compiled languages, dependency install) | Isolated ephemeral runners without secrets; no network or allowlisted network |
| Fork PRs exfiltrating secrets | Don't run privileged workflows (`pull_request_target`) on untrusted code |
| Telemetry | `--metrics=off` for Semgrep where policy requires |
| Rule supply chain | Pin rule repos/registry rulesets by version/commit; review third-party rules |
| SARIF with code snippets | Treat as sensitive (may include secrets) |

---

## 5. Triage & Tuning

- Classify findings: true positive / false positive / won't fix (with justification) — feed back into rules
- Use `nosemgrep` / CodeQL dismissals sparingly with reason; review periodically
- Measure precision per rule; disable rules below ~50% precision or rewrite them
- Pair SAST with SCA (dependencies), secrets scanning, IaC scanning, and DAST — each catches different classes

---

## Engagement Cheatsheet

```text
license check (Semgrep Rules License / Opengrep BYO rules / CodeQL private-repo terms) → diff-aware PR scans + nightly full
→ curated + custom taint rules with tests → gate high-confidence only → SARIF to code scanning → isolated runners for untrusted builds
→ pin rule versions → precision tuning
```

---

## Key References

- semgrep.dev docs (rule syntax, Semgrep CE vs Opengrep FAQ); github.com/opengrep/opengrep; docs.github.com CodeQL CLI
- OWASP Top 10:2025; CWE Top 25
- Related: `defensive-sast-dast`, `defensive-secure-code-review`, `defensive-tool-secret-scanners`
