---
name: defensive-tool-cloud-posture
description: "Cloud and Kubernetes posture assessment tools: Prowler 5.x for AWS, Azure, GCP, Kubernetes, and Microsoft 365 (compliance frameworks, OCSF JSON output, read-only IAM roles such as SecurityAudit and ViewOnlyAccess, multi-account scanning, mutelists), ScoutSuite low-maintenance status, Steampipe SQL over cloud APIs with Powerpipe benchmarks, kube-bench for CIS Kubernetes Benchmark, native services (AWS Security Hub CSPM, Azure Defender for Cloud secure score, GCP Security Command Center), safe credential handling (short-lived, read-only), protecting results, and turning findings into guardrails. Use when assessing cloud or Kubernetes configuration security."
---

# Cloud Posture Tools (Prowler, Steampipe, kube-bench)

Posture scanners enumerate configuration and compare to benchmarks. They need **broad read access** — scope credentials carefully and protect the results (they're a misconfiguration map). Versions observed 2026-10-23: Prowler 5.45.x, Steampipe 2.4.x, kube-bench 0.16.0; ScoutSuite's last PyPI release is 5.14.0 (May 2024) — treat as low-maintenance and prefer actively maintained tools.

## Quick Workflow

1. Create read-only, short-lived credentials (assume-role/OIDC; no long-lived keys)
2. Run scans per account/subscription/project from a controlled runner
3. Map to frameworks (CIS, NIST, PCI, ISO) and severity
4. Triage → fix → convert recurring issues into preventive guardrails (SCP/Policy/Org Policy, IaC checks)
5. Schedule recurring scans; trend findings

---

## 1. Prowler

```bash
pip install prowler
prowler aws --role arn:aws:iam::111122223333:role/ProwlerReadOnly -M json-ocsf html --compliance cis_4.0_aws
prowler aws --organizations-role arn:aws:iam::111122223333:role/ProwlerOrgRead -f ap-southeast-1
prowler azure --az-cli-auth --subscription-ids <sub-id>
prowler gcp --project-ids my-project
prowler kubernetes --kubeconfig-file ~/.kube/config
prowler m365 --az-cli-auth
prowler aws --list-compliance                  # available frameworks (names change between versions)
prowler aws --mutelist-file mutelist.yaml      # documented accepted risks
```

AWS permissions: managed `SecurityAudit` + `ViewOnlyAccess` plus Prowler's documented additional read permissions; trust policy limited to the scanning principal with external ID/conditions. Output OCSF JSON integrates with Security Hub/SIEM.

---

## 2. Steampipe & Powerpipe

```bash
steampipe plugin install aws azure gcp kubernetes
steampipe query "select name, region, bucket_policy_is_public from aws_s3_bucket where bucket_policy_is_public;"
steampipe query "select name, resource_group, network_rule_set ->> 'defaultAction' as default_action from azure_storage_account where network_rule_set ->> 'defaultAction' = 'Allow';"
powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance
powerpipe benchmark run aws_compliance.benchmark.cis_v300 --export cis.json
```

Benchmarks moved from Steampipe "check" to **Powerpipe** — use Powerpipe for compliance runs. Plugin credentials follow standard SDK chains — use read-only profiles.

---

## 3. kube-bench

```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml   # review/pin the manifest first
kubectl logs job/kube-bench
kube-bench run --targets master,node,etcd,policies --json > kube-bench.json
```

Managed clusters (EKS/AKS/GKE) have provider-specific benchmark variants (`--benchmark eks-1.x`); control plane checks may not apply. The job runs with host access — run in a controlled window and remove afterward.

---

## 4. Native Services

| Cloud | Service |
|---|---|
| AWS | Security Hub CSPM (FSBP, CIS), Config rules, IAM Access Analyzer (external & unused access), GuardDuty (threats) |
| Azure | Defender for Cloud (secure score, regulatory compliance), Azure Policy, Entra recommendations |
| GCP | Security Command Center (Security Health Analytics), Policy Analyzer, Recommender |

Use native services for continuous posture; use Prowler/Steampipe for independent verification, multi-cloud views, and custom queries.

---

## 5. Safety

| Risk | Control |
|---|---|
| Over-privileged scanner role | Read-only managed policies; deny data-plane reads (e.g., `s3:GetObject`, Key Vault secrets) unless explicitly required |
| Long-lived keys | OIDC/assume-role; session duration ≤ 1 h |
| Results exposure | Findings reveal exploitable misconfigurations — store encrypted, restrict access |
| Rate limits | Large orgs: throttle regions/services; schedule off-peak |
| Mutelists | Every muted finding has owner, reason, expiry |
| Tool supply chain | Pin versions; install from official PyPI/containers; verify signatures where provided |

---

## 6. From Findings to Guardrails

| Recurring finding | Guardrail |
|---|---|
| Public S3 buckets | S3 Block Public Access at account/org + SCP denying disabling it |
| Unencrypted volumes | Default EBS encryption; Azure Policy deny |
| Public IPs on VMs | Org Policy `compute.vmExternalIpAccess`; Azure Policy deny public IP |
| Root/owner usage | Alerts + SCP/RCP restrictions |
| Old access keys | IAM Identity Center/OIDC; key age alerts |
| IaC drift | Checkov/Trivy config in CI (`defensive-tool-container-scanners`) |

---

## Engagement Cheatsheet

```text
read-only short-lived creds (SecurityAudit+ViewOnly, OIDC) → prowler aws|azure|gcp|kubernetes|m365 -M json-ocsf --compliance
→ steampipe SQL + powerpipe benchmarks → kube-bench (pinned job, remove after) → native CSPM continuous → mutelist w/ expiry
→ recurring issues → SCP/Policy/Org Policy/IaC guardrails → trend
```

---

## Key References

- docs.prowler.com; steampipe.io / powerpipe.io; github.com/aquasecurity/kube-bench; CIS Benchmarks (AWS/Azure/GCP/Kubernetes)
- Related: `defensive-cspm`, `defensive-aws-security`, `defensive-azure-security`, `defensive-gcp-security`, `defensive-k8s-security`
