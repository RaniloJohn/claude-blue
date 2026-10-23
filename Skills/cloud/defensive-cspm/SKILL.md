---
name: defensive-cspm
description: "Cloud Security Posture Management and IaC security: open-source scanners (Prowler for AWS/Azure/GCP/Kubernetes/M365, ScoutSuite, Steampipe/Powerpipe, CloudSploit), native CSPM (AWS Security Hub CSPM, Defender for Cloud, Google SCC), CIS Benchmarks and compliance frameworks, IaC scanning (Checkov, Trivy config, KICS, Terrascan) for Terraform/CloudFormation/Bicep/Kubernetes, policy-as-code (OPA/Conftest, Sentinel), attack path and toxic combination prioritization, drift detection, and remediation workflows. Use when assessing cloud posture, building CSPM pipelines, or prioritizing cloud misconfigurations."
---

# CSPM & IaC Security

Posture management finds misconfigurations before attackers do. The win comes from prioritizing by exploitability (exposure + privilege + sensitive data) and fixing in code so drift does not recur.

## Quick Workflow

1. Run native CSPM + one open-source scanner per cloud
2. Map findings to CIS/framework controls
3. Prioritize by attack paths / toxic combinations
4. Fix in IaC; block regressions with IaC scanning in CI
5. Detect drift between IaC and live state
6. Report trend metrics

---

## 1. Tools

| Tool | Scope | Notes |
|---|---|---|
| Prowler | AWS, Azure, GCP, Kubernetes, M365, GitHub | Hundreds of checks; many compliance frameworks (CIS, NIST 800-53, PCI, ISO 27001, SOC 2…); Prowler App for UI/attack paths |
| ScoutSuite | AWS, Azure, GCP (+ alpha others) | Point-in-time HTML report; slower release cadence — confirm maintenance status before standardizing |
| Steampipe / Powerpipe | SQL over cloud APIs + benchmark mods | Flexible ad-hoc queries |
| AWS Security Hub CSPM | AWS | FSBP, CIS, NIST, PCI standards |
| Defender for Cloud | Azure, AWS, GCP | MCSB; attack paths (Defender CSPM) |
| Google SCC | GCP | Security Health Analytics |
| Checkov / Trivy config / KICS | IaC (Terraform, CloudFormation, Bicep/ARM, K8s, Helm, Dockerfile) | CI gating |
| OPA/Conftest | Custom policy-as-code | Org-specific rules |

```bash
prowler aws --compliance cis_3.0_aws -M html json-ocsf
prowler azure --az-cli-auth
prowler gcp --project-ids my-proj
prowler kubernetes
checkov -d infra/ --framework terraform --compact
trivy config infra/ --severity HIGH,CRITICAL
```

Verify framework IDs with `prowler <provider> --list-compliance`.

---

## 2. High-Impact Misconfigurations

| Category | AWS | Azure | GCP |
|---|---|---|---|
| Public data | S3 public / BPA off | Storage public blob access | Public GCS bucket / allUsers |
| Open admin ports | SG 0.0.0.0/0 :22/:3389 | NSG Any → 22/3389 | Firewall 0.0.0.0/0 → 22/3389 |
| Long-lived creds | IAM user keys > 90 d | SP secrets long expiry | SA keys exist |
| Over-privilege | `*:*` policies, AdminAccess on workloads | Owner on SPs | Basic roles (Owner/Editor) |
| Logging off | CloudTrail not multi-region | Diagnostic settings missing | Data Access logs off |
| Metadata exposure | IMDSv1 allowed | — | Legacy metadata endpoints (deprecated) |
| Encryption | Unencrypted EBS/RDS snapshots shared | Storage without CMK where required | Default keys where CMEK required |
| Root/global admin hygiene | Root keys/MFA | GA without PIM | Org admin breadth |

---

## 3. Prioritization (Toxic Combinations)

Score = exposure × privilege × data sensitivity × exploitability.

| Example combination | Priority |
|---|---|
| Internet-exposed VM + critical CVE (KEV) + instance role with admin | Critical |
| Public bucket containing PII | Critical |
| Lambda with public URL + role that can `iam:PassRole` | High |
| Private VM with medium CVE, no sensitive access | Low |

Use attack path features (Defender CSPM, SCC, Prowler App, Wiz-class tools) or graph tooling (Cartography + Neo4j) to compute reachability.

---

## 4. IaC in CI

```yaml
- name: checkov
  run: |
    pip install checkov
    checkov -d infra/ --framework terraform --soft-fail-on LOW --output sarif --output-file-path results/
- name: conftest
  run: conftest test infra/plan.json -p policy/
```

OPA example — deny public S3 ACL:

```rego
package terraform.s3
deny contains msg if {
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket_acl"
  r.change.after.acl == "public-read"
  msg := sprintf("Public ACL on %s", [r.address])
}
```

(Rego v1 syntax with `contains`/`if`; older OPA requires `import rego.v1` or legacy syntax.)

Scan `terraform plan -out plan.bin && terraform show -json plan.bin > plan.json` for accurate resolved values.

---

## 5. Drift

- Terraform: scheduled `terraform plan -detailed-exitcode` (exit 2 = drift)
- AWS Config / Azure Policy / GCP Asset Inventory change feeds
- Alert on console changes to IaC-managed resources (CloudTrail `userAgent` = console)

---

## 6. Metrics

- Critical/high findings open, by age and owner
- Mean time to remediate by severity
- % resources managed by IaC
- Compliance score trend per framework (secondary to exploitability)

---

## Engagement Cheatsheet

```text
native CSPM + Prowler → toxic-combination prioritization → fix in IaC → Checkov/Trivy/Conftest gates
→ drift detection → owner-based remediation SLAs → trend reporting
```

---

## Key References

- Prowler — https://github.com/prowler-cloud/prowler
- CIS Benchmarks (AWS, Azure, GCP, Kubernetes)
- Checkov, Trivy, KICS, OPA/Conftest docs
- Related: `defensive-aws-security`, `defensive-azure-security`, `defensive-gcp-security`, `defensive-sast-dast`
