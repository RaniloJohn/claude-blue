---
name: defensive-serverless-security
description: "Securing serverless workloads (AWS Lambda, Azure Functions, Google Cloud Run functions/Cloud Functions, Cloud Run) and event-driven architectures: least-privilege execution roles, secrets via secret managers instead of environment variables, input validation for event sources (API Gateway, queues, storage triggers), dependency and layer supply chain, function URL and public invocation exposure, resource policies and cross-account invocation, VPC egress control, timeouts/concurrency for denial-of-wallet, logging and tracing, runtime threats (credential theft from environment, persistence via function code/layers/triggers), detection via CloudTrail/Activity/Audit logs, and IaC checks. Use when building or reviewing serverless applications."
---

# Serverless Security

No servers to patch, but the attack surface moves to **identity (execution roles), event inputs, dependencies, and configuration**. A function role with `*:*` is a domain admin with a URL.

## Quick Workflow

1. Inventory functions, triggers, roles, exposure (function URLs, API Gateway, public triggers)
2. Least-privilege role per function; no wildcard actions/resources
3. Secrets from secret manager at runtime; no plaintext env vars
4. Validate all event inputs; treat every event source as untrusted
5. Scan dependencies/layers/images; pin versions
6. Log invocations and admin changes; detect persistence and credential abuse

---

## 1. Risk → Control

| Risk | Control |
|---|---|
| Over-privileged execution role | One role per function; IAM Access Analyzer policy generation from CloudTrail; deny `iam:*` |
| Secrets in env vars | AWS Secrets Manager/Parameter Store, Azure Key Vault references with managed identity, GCP Secret Manager; encrypt env vars with CMK if unavoidable |
| Injection via events (S3 object names, SQS messages, HTTP bodies) | Schema validation, parameterized queries, avoid shelling out with event data |
| Public invocation | Lambda function URLs with `AuthType: AWS_IAM` (not `NONE`) unless intentionally public; API Gateway authorizers; Azure Functions auth level ≠ anonymous; Cloud Run `--no-allow-unauthenticated` |
| Resource policy abuse | Restrict `lambda:InvokeFunction` principals, `SourceArn`/`SourceAccount` conditions |
| Vulnerable dependencies | SCA in CI (`defensive-tool-container-scanners`), sign images (`defensive-tool-sigstore-cosign`), Lambda code signing |
| Data exfiltration | Place in VPC with egress control/NAT allowlists when handling sensitive data |
| Denial of wallet | Reserved concurrency, timeouts, API throttling, budget alerts |
| Stale runtimes | Track deprecated runtimes (provider deprecation schedules); upgrade |

---

## 2. Threats in Practice

| Technique | Evidence |
|---|---|
| Credential theft from runtime (env contains temporary credentials) | API calls from function role credentials **outside** the function (different IP/user agent) — GuardDuty `InstanceCredentialExfiltration`-style findings for Lambda/ECS (verify coverage) |
| Persistence via backdoored code/layer | `UpdateFunctionCode`, `PublishLayerVersion`, `UpdateFunctionConfiguration` (new layer/env) by unusual principals |
| Persistence via triggers | New EventBridge rules, `CreateEventSourceMapping`, `AddPermission` to external accounts |
| Privilege escalation | `iam:PassRole` + `CreateFunction` with a privileged role (`defensive-detect-privilege-escalation`) |
| Azure | Function app settings changes, deployment slot swaps, new managed identity role assignments |
| GCP | `cloudfunctions.functions.update`/`run.services.update` with new service accounts; `setIamPolicy` making services public |

```sql
-- Athena/CloudTrail: Lambda configuration changes by non-pipeline principals
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'lambda.amazonaws.com'
  AND eventname IN ('UpdateFunctionCode20150331v2','UpdateFunctionConfiguration20150331v2','AddPermission20150331v2','CreateFunctionUrlConfig','PublishLayerVersion20181031')
  AND useridentity.arn NOT LIKE '%deploy-pipeline%'
ORDER BY eventtime DESC;
```

(Lambda CloudTrail event names carry API version suffixes — verify in your logs.)

---

## 3. Logging

CloudWatch Logs + X-Ray (AWS), Application Insights + Activity Log (Azure), Cloud Logging + Cloud Audit Logs (GCP). Structured logs with request IDs; never log secrets or full sensitive payloads. Forward admin events to SIEM.

---

## 4. IaC Guardrails

Checkov/Trivy config rules: no function URL with `AuthType NONE`, no wildcard IAM in function roles, env var encryption, reserved concurrency set, runtime not deprecated, tracing enabled. Enforce in CI; SCP/Azure Policy/Org Policy to block public functions where not allowed.

---

## Engagement Cheatsheet

```text
inventory (functions, triggers, roles, URLs) → per-function least-privilege roles → secrets manager → validate event input → auth on URLs/APIs + resource policy conditions
→ SCA + signing + runtime currency → VPC egress for sensitive → concurrency/timeouts → log + detect code/layer/trigger/permission changes and credential use outside function
```

---

## Key References

- OWASP Serverless Top 10 (archived but useful); AWS Lambda security best practices; Azure Functions security; Cloud Run security docs
- Related: `defensive-aws-security`, `defensive-azure-security`, `defensive-gcp-security`, `defensive-api-security`, `defensive-cspm`
