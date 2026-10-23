---
name: defensive-secrets-management
description: "Secrets management and leak response: centralized vaults (HashiCorp Vault/OpenBao, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager), dynamic and short-lived credentials, workload identity instead of static secrets, secret scanning (gitleaks, trufflehog with verification, GitHub secret scanning and push protection, GitLab), scanning history, CI logs, container images and package artifacts, pre-commit hooks, rotation runbooks for leaked AWS/Azure/GCP/GitHub/npm/Slack/database credentials, and detecting use of leaked secrets. Use when designing secrets handling or responding to a leaked credential."
---

# Secrets Management & Leak Response

The best secret is one that doesn't exist (workload identity) or expires in minutes (dynamic credentials). Everything else must be vaulted, scoped, rotated, and scanned for leaks — and when leaked, revoked first, investigated second.

## Quick Workflow

1. Eliminate static secrets where possible (OIDC, managed identities, IAM roles)
2. Vault the rest with access policies and audit logs
3. Inject at runtime; never bake into code/images
4. Scan everything: commits, history, PRs, CI logs, images, packages, tickets/chat
5. On leak: revoke/rotate → assess usage → clean up
6. Measure: secrets age, leaks per month, time-to-revoke

---

## 1. Hierarchy of Options

| Best → worst | Example |
|---|---|
| No secret (federated identity) | GitHub OIDC → AWS role; Azure managed identity; GKE Workload Identity |
| Dynamic, short-lived | Vault database secrets engine (TTL 1 h); STS session creds |
| Vaulted static, auto-rotated | Secrets Manager rotation Lambda; Key Vault rotation policy |
| Vaulted static, manual rotation | Third-party API keys |
| Env var / config file | Acceptable only if injected at runtime from vault and not logged |
| Hardcoded | Never |

---

## 2. Vault Patterns

```bash
# HashiCorp Vault / OpenBao — dynamic DB creds
vault secrets enable database
vault write database/roles/app-ro db_name=prod-pg default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
vault read database/creds/app-ro
```

- Auth via platform identity (Kubernetes auth, AWS IAM auth, OIDC/JWT for CI)
- Policies per app path; deny wildcard
- Audit device enabled → SIEM
- Kubernetes: External Secrets Operator / Secrets Store CSI driver; encrypt K8s Secrets at rest with KMS

---

## 3. Scanning

```bash
gitleaks detect -s . --redact -v                       # working tree + history
gitleaks protect --staged                              # pre-commit
trufflehog git file://. --only-verified                # verifies live credentials
trufflehog github --org=myorg --only-verified
trufflehog docker --image registry/app:latest
trufflehog filesystem ./build-logs/
```

- GitHub secret scanning + push protection (org-wide), custom patterns for internal token formats
- Scan: all branches + full history, CI logs/artifacts, container layers, npm/PyPI packages you publish, wikis, ticket systems, chat exports
- Pre-commit hooks (gitleaks) as first line; server-side push protection as enforcement

---

## 4. Leak Response Runbook

```text
1. Revoke/rotate immediately (don't wait to investigate — scrapers find public secrets within minutes)
2. Identify secret type, scope, permissions, and exposure window (first commit/publish → revocation)
3. Review provider logs for use during window (from unknown IPs/ASNs)
4. Remove from history (git filter-repo / BFG) AND treat as compromised regardless
5. Check for persistence created with the secret (new users, keys, tokens, webhooks)
6. Root cause: how did it get there? Add scanning/pre-commit/push protection
```

| Secret | Revoke | Usage logs |
|---|---|---|
| AWS access key | `aws iam update-access-key --status Inactive`, then delete | CloudTrail by `accessKeyId` |
| Azure SP secret | Remove credential from app registration | `AADServicePrincipalSignInLogs`, `AzureActivity` |
| GCP SA key | `gcloud iam service-accounts keys disable/delete` | Cloud Audit Logs by key/SA |
| GitHub PAT / app key | Revoke in settings / org audit | Org audit log (`token` events) |
| npm token | `npm token revoke` | npm audit/publish history |
| Slack/Discord webhooks/bots | Regenerate | Workspace audit logs |
| Database password | Rotate; kill sessions | DB audit/connection logs |
| TLS private key | Revoke cert, reissue | CT logs for unexpected issuance |
| SSH private key | Remove from `authorized_keys` everywhere | auth.log, bastion logs |

---

## 5. Detection of Leaked-Secret Use

- AWS: GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, `GetCallerIdentity` from new IPs, AccessDenied bursts
- Canary tokens (fake AWS keys, API keys) placed in repos/configs → alert on any use (see `defensive-deception`)
- Monitor public GitHub for org-domain strings and token prefixes

---

## 6. Developer Hygiene

```text
[ ] .gitignore / .dockerignore cover .env, *.pem, *.key, credentials files
[ ] No secrets in CI logs (masking; avoid `set -x` around secrets)
[ ] No secrets in container build args/layers (BuildKit --secret)
[ ] No secrets in client-side code (SPA, mobile)
[ ] Short TTLs; ownership metadata on every secret
```

---

## Engagement Cheatsheet

```text
federate identities → vault + dynamic creds → runtime injection → scan (pre-commit, push protection, history, images, logs)
→ leak: revoke first → usage logs → persistence check → history purge → root cause fix
```

---

## Key References

- OWASP Secrets Management Cheat Sheet
- HashiCorp Vault / OpenBao docs; cloud secret manager docs
- gitleaks, trufflehog, GitHub secret scanning docs
- Related: `defensive-cicd-hardening`, `defensive-cloud-ir`, `defensive-deception`
