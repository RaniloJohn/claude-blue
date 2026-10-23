---
name: defensive-sast-dast
description: "Application security testing in the SDLC: SAST (Semgrep, CodeQL, SonarQube, Bandit, Brakeman, gosec), SCA (Dependabot, Renovate, OSV-Scanner, Trivy, Grype, npm audit, pip-audit), secret scanning (gitleaks, trufflehog, GitHub push protection), IaC scanning (Checkov, tfsec/Trivy config, KICS), DAST (OWASP ZAP baseline/full/API scans, Nuclei), container image scanning, CI integration with SARIF, finding triage and false positive management, severity and reachability prioritization, and custom Semgrep/CodeQL rules. Use when building or tuning an AppSec pipeline or triaging scanner findings."
---

# SAST, DAST & Pipeline Scanning

Scanners are only useful if developers fix what they find. Optimize for signal: few, high-confidence findings at PR time; broader scans on schedule; reachability and exploitability to prioritize.

## Quick Workflow

1. PR-time: secrets, SAST (diff-aware), SCA (new deps), IaC
2. Merge/main: full SAST + SCA + container scan
3. Staging: DAST (authenticated), API scans
4. Upload SARIF to code scanning dashboard
5. Triage: true positive / false positive / accepted risk with expiry
6. Track SLA by severity and exploitability

---

## 1. Tool Map

| Category | Tools |
|---|---|
| SAST | Semgrep (fast, custom rules), CodeQL (deep dataflow), SonarQube, Bandit (Python), Brakeman (Rails), gosec (Go), SpotBugs+FindSecBugs (Java) |
| SCA | OSV-Scanner, Trivy, Grype, Dependabot, Renovate, npm/pnpm audit, pip-audit, Snyk |
| Secrets | gitleaks, trufflehog (verifies live secrets), GitHub secret scanning + push protection |
| IaC | Checkov, Trivy (`trivy config`), KICS, tfsec (merged into Trivy) |
| Containers | Trivy, Grype, Docker Scout |
| DAST | OWASP ZAP (baseline/full/API), Nuclei (template-based), Burp Suite Enterprise |
| API fuzzing | Schemathesis, RESTler |

---

## 2. CI Example (GitHub Actions)

```yaml
name: appsec
on: [pull_request]
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>
        with: { fetch-depth: 0 }
      - name: gitleaks
        run: |
          docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect -s /repo --redact --exit-code 1
      - name: semgrep
        run: |
          pip install semgrep
          semgrep scan --config p/owasp-top-ten --config p/secrets --sarif -o semgrep.sarif --error
      - name: osv-scanner
        run: |
          go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
          ~/go/bin/osv-scanner scan -r . --format sarif --output osv.sarif || true
      - name: trivy config
        run: |
          docker run --rm -v "$PWD:/src" aquasec/trivy:latest config /src --exit-code 1 --severity HIGH,CRITICAL
      - uses: github/codeql-action/upload-sarif@<full-commit-sha>
        with: { sarif_file: semgrep.sarif }
```

Pin actions and scanner images to digests/SHAs in production pipelines (supply-chain lesson from compromised CI dependencies). Verify CLI paths/flags against current tool versions.

---

## 3. Custom Semgrep Rule

```yaml
rules:
  - id: python-sql-fstring
    languages: [python]
    severity: ERROR
    message: SQL built with f-string; use parameterized query
    patterns:
      - pattern-either:
          - pattern: $CUR.execute(f"...", ...)
          - pattern: $CUR.execute("..." + $X, ...)
          - pattern: $CUR.execute("..." % $X, ...)
    metadata:
      cwe: "CWE-89"
      owasp: "A05:2025"
```

CodeQL: use `security-extended` query suite; write custom queries for org frameworks (sources/sinks models).

---

## 4. DAST

```bash
# Baseline (passive) scan
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.example.com -r zap.html
# API scan from OpenAPI
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t https://staging.example.com/openapi.json -f openapi -r api.html
# Nuclei with curated templates, rate-limited
nuclei -u https://staging.example.com -severity medium,high,critical -rl 50
```

- Authenticate DAST (context + session handling) or it tests only the login page
- Run against staging, never production without approval and rate limits
- Exclude destructive endpoints (delete, payment) or use test data

---

## 5. Triage

| Status | Requirement |
|---|---|
| True positive | Ticket with owner, SLA |
| False positive | Reason + rule/path suppression in code (`# nosemgrep: rule-id` with comment) |
| Accepted risk | Approver, compensating control, expiry date |
| Duplicate | Link to canonical |

Prioritize SCA by: reachable vulnerable function (reachability analysis), exploit availability, CISA KEV listing, EPSS, internet exposure — not CVSS alone. NVD enrichment is now limited (since April 2026 NIST prioritizes KEV, federal, and EO 14028 software), so rely on OSV/GitHub Advisory/vendor data for CVSS and affected ranges.

---

## 6. SLAs (example)

| Severity | Internet-facing | Internal |
|---|---|---|
| Critical / KEV | 3–7 days | 14 days |
| High | 30 days | 60 days |
| Medium | 90 days | 180 days |
| Low | Backlog | Backlog |

---

## Engagement Cheatsheet

```text
PR: gitleaks + semgrep diff + SCA new deps + IaC → main: full SAST/SCA/container → staging: auth DAST + API scan
→ SARIF dashboard → triage with reasons/expiry → prioritize by reachability/KEV/EPSS/exposure
```

---

## Key References

- Semgrep registry; GitHub CodeQL docs; OSV-Scanner; Trivy; gitleaks; trufflehog
- OWASP ZAP automation docs; ProjectDiscovery Nuclei
- OWASP DevSecOps Guideline; OWASP SAMM
- Related: `defensive-secure-code-review`, `defensive-cicd-hardening`, `defensive-vuln-management`
