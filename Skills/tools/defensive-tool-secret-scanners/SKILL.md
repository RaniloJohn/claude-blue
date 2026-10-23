---
name: defensive-tool-secret-scanners
description: "Secret detection with Gitleaks and TruffleHog plus platform push protection: Gitleaks 8.x subcommands (git, dir, stdin replacing detect/protect), redaction, custom rules and allowlists in .gitleaks.toml, baselines, pre-commit hooks; TruffleHog v3 sources (git, GitHub org, filesystem, S3, Docker), credential verification behavior and its privacy/legal implications (--no-verification, --results=verified,unknown), GitHub secret scanning and push protection, response playbook (revoke first, rotate, then purge history with git filter-repo), and preventing secrets in CI logs and images. Use when scanning code/repos for secrets or responding to a leaked credential."
---

# Secret Scanners (Gitleaks, TruffleHog)

A leaked secret is an incident from the moment it's pushed — bots scrape public repos within minutes. Prevent at commit, detect in CI and history, and **revoke before cleaning**. Observed versions 2026-10-23: Gitleaks 8.30.1, TruffleHog 3.99.x.

## Quick Workflow

1. Pre-commit hook + platform push protection (prevention)
2. CI scan on every PR with redacted output (detection)
3. Periodic full-history and org-wide scans
4. On a hit: revoke/rotate → assess usage in provider logs → purge history → add rule/allowlist

---

## 1. Gitleaks

Gitleaks 8.19+ uses `git`, `dir`, and `stdin` subcommands (older `detect`/`protect` are deprecated).

```bash
gitleaks git -v --redact --report-format sarif --report-path gitleaks.sarif .        # full git history
gitleaks git --redact --log-opts="origin/main..HEAD" .                               # only new commits (PR)
gitleaks dir --redact ./build-output                                                  # files, not git
cat app.log | gitleaks stdin --redact
gitleaks git --baseline-path gitleaks-baseline.json --report-path new.json .          # ignore known findings
```

`.gitleaks.toml`:

```toml
[extend]
useDefault = true

[[rules]]
id = "corp-internal-api-key"
description = "Internal API key"
regex = '''corp_live_[A-Za-z0-9]{32}'''
keywords = ["corp_live_"]

[allowlist]
description = "Test fixtures"
paths = ['''tests/fixtures/.*''']
regexes = ['''EXAMPLE_KEY_DO_NOT_USE''']
```

pre-commit:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks: [ { id: gitleaks } ]
```

---

## 2. TruffleHog v3

```bash
trufflehog git file://. --results=verified,unknown --json > th.json
trufflehog github --org=myorg --token=$GH_READONLY_TOKEN --results=verified
trufflehog filesystem ./dir --no-verification
trufflehog docker --image registry.example.local/app:candidate
trufflehog s3 --bucket=my-bucket
```

**Verification** = TruffleHog calls the provider's API with the discovered credential to test validity. Implications:
- Generates authentication events at the provider (may alert the provider/owner)
- Only verify **your organization's** secrets with authorization; for third-party data use `--no-verification`
- Verified results are high priority — treat as active compromise exposure

---

## 3. Platform Controls

| Control | Detail |
|---|---|
| GitHub secret scanning + push protection | Block pushes containing supported secret types; custom patterns for internal formats; delegated bypass approvals |
| GitLab secret detection / push rules | Pipeline job + pre-receive checks |
| CI log masking | Mask secrets; never `set -x` around secrets; avoid printing env |
| Images | Multi-stage builds; never `COPY .env`; scan images for secrets (Trivy) |
| Short-lived credentials | OIDC federation (GitHub → AWS/Azure/GCP) eliminates static cloud keys in CI |

---

## 4. Leaked Secret Response

```text
1. Revoke/rotate immediately (provider console/API) — deleting the commit does NOT un-leak it
2. Check provider audit logs for use since the leak time (CloudTrail, Entra sign-ins, GitHub audit log, SaaS logs)
3. Scope: where else is the secret used? (shared credentials)
4. Purge from history: git filter-repo --replace-text secrets.txt (coordinate force-push, invalidate forks/caches; contact platform support for cached views)
5. Add detection rule/custom pattern; root cause (why was it in code?) → vault/OIDC
6. Document as incident if used or public exposure
```

---

## 5. Pitfalls

- Unredacted reports become a new secret store — always `--redact`, restrict artifact access
- High-entropy false positives (hashes, test data) → tune allowlists, don't disable scanning
- Scanning only HEAD misses history
- Secrets in issue trackers, wikis, chat, and CI logs — extend scanning beyond git

---

## Engagement Cheatsheet

```text
pre-commit gitleaks + push protection → CI gitleaks git --redact (PR range) / trufflehog --results=verified,unknown
→ scheduled full-history + org scans → verification only for own secrets (else --no-verification)
→ leak: revoke → provider logs → scope → git filter-repo → rule + vault/OIDC root fix
```

---

## Key References

- github.com/gitleaks/gitleaks (README, config); github.com/trufflesecurity/trufflehog; GitHub secret scanning docs; git-filter-repo
- Related: `defensive-secrets-management`, `defensive-cicd-hardening`, `defensive-tool-sast`, `defensive-tool-safety`
