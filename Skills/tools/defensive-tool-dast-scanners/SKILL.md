---
name: defensive-tool-dast-scanners
description: "Dynamic application and exposure scanning with OWASP-originated ZAP (ZAP by Checkmarx) and ProjectDiscovery Nuclei used defensively and safely: written authorization and scope, staging-first, passive baseline vs active full scans and their side effects, API scans from OpenAPI/GraphQL, Automation Framework plans, authenticated scanning, rate limiting, excluding destructive/intrusive templates, Nuclei template signing (unsigned code templates blocked), custom templates for your own exposures, scanning your external attack surface, CI integration and triage. Use when running DAST or exposure validation against your own applications and infrastructure."
---

# DAST & Exposure Scanners (ZAP, Nuclei)

DAST tests running applications the way an attacker would — which means it can **change data, lock accounts, and break things**. Scan only what you own or are authorized to test, start in staging, and control intensity. Observed versions 2026-10-23: ZAP 2.17.0, Nuclei 3.11.x.

## Quick Workflow

1. Written authorization: targets, time window, intensity, contacts, stop conditions
2. Staging first with test accounts and test data
3. Passive/baseline scan → API scan → authenticated active scan (staging)
4. Production: passive/baseline and non-intrusive templates only, rate-limited
5. Triage findings, verify manually, track remediation

---

## 1. ZAP

| Scan | Behavior | Where |
|---|---|---|
| Baseline (`zap-baseline.py`) | Spider + passive rules, no attacks | Prod OK (low impact) |
| API (`zap-api-scan.py`) | Imports OpenAPI/SOAP/GraphQL, active rules against API | Staging |
| Full (`zap-full-scan.py`) | Spider + active scan (injection payloads, form submissions) | Staging only |
| Automation Framework (`-autorun plan.yaml`) | Reproducible plans (contexts, auth, jobs, reports) | CI |

```bash
docker run --rm -v $(pwd):/zap/wrk:rw -t zaproxy/zap-stable zap-baseline.py -t https://staging.example.com -r baseline.html -J baseline.json
docker run --rm -v $(pwd):/zap/wrk:rw -t zaproxy/zap-stable zap-api-scan.py -t https://staging.example.com/openapi.json -f openapi -r api.html
docker run --rm -v $(pwd):/zap/wrk:rw -t zaproxy/zap-stable zap.sh -cmd -autorun /zap/wrk/plan.yaml
```

Plan essentials: context with include/exclude regexes (exclude `/logout`, `/delete`, payment endpoints), authentication (form/JSON/header token, verification indicator), users, spider limits, active-scan policy strength/threshold, `maxRuleDurationInMins`, report job.

Pin the Docker image by digest; ZAP add-ons update from the marketplace — control in CI for reproducibility.

---

## 2. Nuclei

```bash
nuclei -ut                                                    # update templates
nuclei -u https://staging.example.com -s high,critical -rl 50 -c 10 -o findings.txt
nuclei -l assets.txt -tags cve,exposure,misconfig -etags intrusive,dos,fuzz -rl 30 -jsonl -o out.jsonl
nuclei -u https://app.example.com -t ./custom-templates/ -rl 20
nuclei -t custom-code-template.yaml -sign                     # sign your reviewed code templates
```

Template safety (official docs):
- Signing is optional except for the **code** protocol — unsigned or tampered code templates are blocked; only templates signed by you or ProjectDiscovery run
- Review any code template before signing; protect your signing key (`$CONFIG/nuclei/keys`)
- Nuclei warns on unsigned custom templates; `HIDE_TEMPLATE_SIG_WARNING` only hides the warning
- Exclude intrusive/DoS/fuzzing tags on production; set rate limits (`-rl`) and concurrency (`-c`)
- Community templates are code you didn't write — pin template versions for audits

Custom template for your own exposure (e.g., exposed admin panel):

```yaml
id: corp-exposed-admin-panel
info:
  name: Corp admin panel exposed
  author: blue-team
  severity: high
  tags: exposure,corp
http:
  - method: GET
    path: ["{{BaseURL}}/admin/login"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Corp Admin Console"]
```

---

## 3. Safety Rules

| Rule | Why |
|---|---|
| Authorization in writing | Legal (e.g., PH RA 10175, US CFAA); cloud provider policies |
| Notify ops/SOC | Avoid incident response to your own scan; whitelist scanner IPs in SIEM context, not WAF bypass by default |
| Test accounts only | Active scans create/modify data |
| Exclusions | Logout, delete, payment, email-sending, password reset endpoints |
| Rate limits and windows | Prevent outages and lockouts |
| Stop conditions | Error rate spike, latency increase, account lockouts |
| Data handling | Reports contain vulnerabilities and possibly data — restrict access |

---

## 4. CI Integration & Triage

- PR: ZAP baseline against ephemeral preview env; fail on new High
- Nightly: API + full scan in staging; Nuclei on staging and external attack surface (non-intrusive)
- Triage: confirm manually, map to CWE/OWASP, dedupe with SAST/SCA, assign owner with SLA (`defensive-vuln-management`)

---

## Engagement Cheatsheet

```text
written authorization + scope + window → staging test accounts → ZAP baseline → API scan → AF full scan (exclusions, auth)
→ prod: baseline + nuclei -etags intrusive,dos,fuzz -rl → sign reviewed code templates only → notify SOC → manual verification → SLA tracking
```

---

## Key References

- zaproxy.org docs (packaged scans, Automation Framework); docs.projectdiscovery.io (template signing, templates)
- OWASP WSTG; OWASP Top 10:2025
- Related: `defensive-sast-dast`, `defensive-vuln-management`, `defensive-api-security`, `defensive-tool-safety`
