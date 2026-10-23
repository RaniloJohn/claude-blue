---
name: defensive-cicd-hardening
description: "CI/CD pipeline security for GitHub Actions, GitLab CI, Jenkins, and Azure DevOps: least-privilege GITHUB_TOKEN permissions, pinning actions to full commit SHAs, pull_request_target and workflow_run 'pwn request' risks, script injection via untrusted context expressions, cache poisoning, OIDC federation to cloud instead of stored secrets, environment protections and required reviewers, self-hosted runner isolation (ephemeral runners), branch protection/rulesets, CODEOWNERS, artifact attestation, and detecting malicious workflow changes. Informed by tj-actions/changed-files (CVE-2025-30066) and the Shai-Hulud npm worm campaigns (2025–2026). Use when auditing or securing build pipelines."
---

# CI/CD Hardening

Pipelines hold production credentials and produce the software everyone trusts. Recent incidents show attackers target CI directly: compromised third-party actions (tj-actions/changed-files, 2025), self-replicating npm worms stealing CI tokens (Shai-Hulud, Sept and Nov 2025), the March 2026 Trivy compromise (CVE-2026-33634: malicious Trivy v0.69.4 plus 76 of 77 `trivy-action` tags and all `setup-trivy` tags force-pushed with a credential stealer — a *security scanner* used as the entry point), and 2026 waves that poisoned GitHub Actions caches via pwn requests so that legitimately built packages — with valid provenance — shipped malware.

## Quick Workflow

1. Inventory workflows, runners, secrets, and third-party actions
2. Least-privilege tokens; OIDC instead of long-lived secrets
3. Pin dependencies (actions by SHA, images by digest)
4. Eliminate untrusted-code execution with privileged context
5. Isolate runners; protect environments and branches
6. Monitor workflow/config changes and runner behavior

---

## 1. GitHub Actions Baseline

```yaml
permissions: {}                     # workflow default: nothing
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read                # grant per job only what's needed
      id-token: write               # only if using OIDC
    steps:
      - uses: actions/checkout@<40-char-commit-sha>   # vX.Y.Z (comment for Dependabot)
        with:
          persist-credentials: false
```

Org/repo settings:

```text
[ ] Default workflow permissions: read-only; "Allow GitHub Actions to create and approve PRs" off
[ ] Allowed actions: GitHub-owned + verified creators + explicit allowlist; require SHA pinning (org policy where available)
[ ] Fork PR workflows require approval for outside contributors
[ ] Rulesets: protected default branch, required reviews, required status checks, no force push, signed commits (optional)
[ ] CODEOWNERS for .github/workflows/** requiring security review
[ ] Environments with required reviewers + branch restrictions for deploy jobs
[ ] Secret scanning + push protection on
```

---

## 2. Dangerous Patterns

| Pattern | Risk | Fix |
|---|---|---|
| `pull_request_target` + checkout of PR head + run build | Fork code runs with write token & secrets ("pwn request") | Use `pull_request`; if `_target` needed, never check out/execute PR code |
| `workflow_run` consuming artifacts from fork PR runs | Artifact poisoning | Treat artifacts as untrusted; validate |
| `run: echo "${{ github.event.issue.title }}"` | Script injection from attacker-controlled fields | Pass via `env:` and quote: `env: TITLE: ${{ github.event.issue.title }}` then `"$TITLE"` |
| Shared caches between untrusted (PR) and release workflows | Cache poisoning → malicious release built from trusted workflow | Separate cache keys/scopes for release; don't restore caches in release jobs; build releases clean |
| Third-party actions by tag (`@v4`) | Tag moved to malicious commit | Pin to full SHA; review updates |
| Long-lived cloud keys in secrets | Theft = cloud compromise | OIDC federation with tight subject claims |
| Self-hosted runners on public repos | Fork code runs on your infrastructure | Never; or ephemeral isolated runners only |
| `GITHUB_TOKEN` with `contents: write` everywhere | Repo tampering | Job-scoped minimal permissions |

Untrusted expression sources: `github.event.issue.title/body`, `pull_request.title/body/head.ref/head.label`, `comment.body`, `review.body`, `commits.*.message`, `head_commit.message/author`, `discussion.*`.

---

## 3. OIDC to Cloud

AWS trust policy (restrict to repo + ref/environment):

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:org/app:environment:production"
    }
  }
}
```

Never use wildcard `sub` like `repo:org/*`. Equivalent: Azure federated credentials, GCP Workload Identity Federation with attribute conditions.

---

## 4. Runners

- GitHub-hosted or ephemeral self-hosted (one job per VM/container, destroyed after)
- Self-hosted runner groups restricted to specific repos/workflows
- Egress filtering on runners (Harden-Runner–style monitoring, proxy allowlists)
- No persistent credentials on runner hosts; no Docker socket shared across jobs

---

## 5. Package Publishing

- npm/PyPI/RubyGems/crates/NuGet **trusted publishing** (OIDC) instead of API tokens
- npm: classic tokens revoked (Dec 2025); use short-lived granular tokens or trusted publishing; 2FA (WebAuthn) for maintainers
- Publish only from protected release workflows in protected environments
- Generate provenance/attestations — but note 2026 incidents produced *valid* provenance from poisoned builds: provenance proves where something was built, not that the build was clean. Combine with clean, cache-isolated release builds and review

---

## 6. GitLab / Jenkins / Azure DevOps

| Platform | Key controls |
|---|---|
| GitLab CI | Protected branches/tags; protected + masked variables; `CI_JOB_TOKEN` scope allowlist; runners tagged and restricted; ID tokens for OIDC |
| Jenkins | Patch core/plugins aggressively; no builds on controller; agents isolated; Credentials plugin with folder scoping; script approval; disable CLI over remoting; RBAC (Matrix/Role strategy) |
| Azure DevOps | Pipeline permissions per resource; approvals & checks on environments; workload identity federation for service connections; restrict YAML templates (`extends` required templates) |

---

## 7. Detection

| Signal | Source |
|---|---|
| Workflow file changes outside PR review | Audit log / git history on `.github/workflows` |
| New self-hosted runner registered | Org audit log (`org.register_self_hosted_runner`) |
| Secrets accessed by unusual workflows | Audit log, cloud CloudTrail for OIDC role use from unexpected `sub` |
| Outbound to unknown hosts from runners | Runner egress monitoring |
| Base64/curl\|bash in workflow steps added recently | Diff review / Semgrep rules on workflows |
| Repos named like worm artifacts, unexpected public repos/visibility flips | Org audit log |
| New deploy keys / PATs | Audit log |

Tools: `zizmor` and `actionlint` (static analysis of workflows), OpenSSF Scorecard, StepSecurity Harden-Runner, Legitify/Chain-bench (posture).

```bash
zizmor .github/workflows/
actionlint
```

---

## Engagement Cheatsheet

```text
inventory → permissions:{} + per-job minimal → SHA pins → kill pwn-request & injection patterns
→ separate caches for release → OIDC with exact sub → ephemeral runners → trusted publishing
→ CODEOWNERS on workflows → zizmor/actionlint in CI → audit-log detections
```

---

## Key References

- GitHub: Security hardening for GitHub Actions; OIDC docs; artifact attestations
- CVE-2025-30066 (tj-actions/changed-files); GitHub "Our plan for a more secure npm supply chain" (2025)
- OWASP Top 10 CI/CD Security Risks; OpenSSF Scorecard; zizmor
- Related: `defensive-secrets-management`, `defensive-sbom-slsa`, `defensive-detection-as-code`
