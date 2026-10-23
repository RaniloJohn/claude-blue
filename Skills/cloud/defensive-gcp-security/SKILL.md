---
name: defensive-gcp-security
description: "Google Cloud security operations and hardening: resource hierarchy (organization, folders, projects), Organization Policy constraints, IAM least privilege (avoid basic roles), service account security (disable key creation, Workload Identity Federation, impersonation monitoring), Cloud Audit Logs (Admin Activity, Data Access, System Event, Policy Denied) and org-level log sinks, Security Command Center (Event Threat Detection, Container Threat Detection, Security Health Analytics), VPC Service Controls, firewall rules and IAP for SSH/RDP, GKE hardening, and detection queries for IAM abuse, key creation, and exfiltration. Use for GCP reviews, detection engineering, and hardening."
---

# Google Cloud Security

In GCP, service accounts are the primary attack surface: downloaded keys, over-broad roles, and impersonation chains (`iam.serviceAccounts.getAccessToken`) are the common escalation paths.

## Quick Workflow

1. Org hierarchy with folders by environment
2. Organization Policies (deny service account keys, restrict public IPs, domain-restricted sharing)
3. IAM: no basic roles (Owner/Editor/Viewer) for humans/SAs in prod; groups; least privilege
4. Logging: org-level aggregated sink of audit logs; enable Data Access logs for sensitive services
5. Security Command Center: enable detectors; route findings to SIEM
6. Network: no public SSH/RDP; IAP TCP forwarding; VPC Service Controls for data perimeter
7. Detections

---

## 1. Organization Policy Constraints

| Constraint | Purpose |
|---|---|
| `iam.disableServiceAccountKeyCreation` | Stop long-lived SA keys |
| `iam.disableServiceAccountKeyUpload` | Stop external key upload |
| `iam.allowedPolicyMemberDomains` | Domain-restricted sharing (block external identities) |
| `compute.vmExternalIpAccess` | Restrict public IPs |
| `compute.requireOsLogin` | Centralized SSH identity |
| `storage.publicAccessPrevention` | Block public buckets |
| `storage.uniformBucketLevelAccess` | Disable legacy ACLs |
| `compute.restrictLoadBalancerCreationForTypes` | Control internet exposure |
| `gcp.resourceLocations` | Data residency |
| `iam.automaticIamGrantsForDefaultServiceAccounts` | Prevent Editor on default SAs |

(Newer managed constraints use `constraints/...` names under the Org Policy v2 API — verify naming in current docs.)

---

## 2. IAM & Service Accounts

```text
[ ] No basic roles in production; predefined/custom roles only
[ ] Default compute SA not used (or stripped of Editor)
[ ] SA keys disabled; use Workload Identity Federation (external CI/cloud) and attached SAs
[ ] Impersonation permissions (roles/iam.serviceAccountTokenCreator, serviceAccountUser) tightly scoped
[ ] IAM Recommender to remove unused permissions
[ ] Privileged Access Manager / just-in-time grants for admin roles
```

Escalation permissions to watch: `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.actAs` + compute/function create, `iam.serviceAccountKeys.create`, `resourcemanager.projects.setIamPolicy`, `deploymentmanager.deployments.create`, `cloudfunctions.functions.update`, `compute.instances.setMetadata` (startup scripts, SSH keys).

---

## 3. Logging

| Log | Default | Action |
|---|---|---|
| Admin Activity | Always on, free | Sink to SIEM |
| Data Access | Off (except BigQuery) | Enable for IAM, Secret Manager, Cloud Storage (sensitive buckets), KMS |
| System Event | On | Sink |
| Policy Denied | On | Sink (VPC SC / org policy violations) |
| VPC Flow Logs | Off | Enable on subnets |
| Cloud DNS logging | Off | Enable via DNS policy |

```bash
gcloud logging sinks create org-audit-sink \
  bigquery.googleapis.com/projects/sec-logs/datasets/org_audit \
  --organization=<ORG_ID> --include-children \
  --log-filter='logName:"cloudaudit.googleapis.com"'
```

---

## 4. Security Command Center

- Security Health Analytics: misconfigurations (public buckets, open firewall, SA keys)
- Event Threat Detection: anomalous IAM grants, SA key creation/use, malware/crypto-mining DNS, data exfil to external projects (BigQuery)
- Container Threat Detection: runtime on GKE
- Attack path simulation / toxic combinations (Premium/Enterprise tiers)

---

## 5. Detections (Logging query language)

```text
# SA key created
protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"

# IAM policy changes adding members
protoPayload.methodName="SetIamPolicy"
protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"

# Owner granted
protoPayload.methodName="SetIamPolicy"
protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"

# Token generation (impersonation)
protoPayload.methodName="GenerateAccessToken"

# Logging sink deleted/modified (evasion)
protoPayload.methodName=("google.logging.v2.ConfigServiceV2.DeleteSink" OR "google.logging.v2.ConfigServiceV2.UpdateSink")

# Firewall opened to world
protoPayload.methodName:"compute.firewalls.insert" AND protoPayload.request.sourceRanges="0.0.0.0/0"

# Instance metadata change (SSH keys/startup scripts)
protoPayload.methodName="v1.compute.instances.setMetadata"
```

BigQuery over sink:

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.methodName AS method, resource.labels.project_id
FROM `sec-logs.org_audit.cloudaudit_googleapis_com_activity_*`
WHERE protopayload_auditlog.methodName IN ('google.iam.admin.v1.CreateServiceAccountKey','SetIamPolicy')
  AND _TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY))
ORDER BY timestamp DESC;
```

---

## 6. Network & Data

- Firewall: no `0.0.0.0/0` to 22/3389; use IAP TCP forwarding (`35.235.240.0/20` source) for admin
- VPC Service Controls perimeters around sensitive projects (BigQuery, GCS, Secret Manager) to prevent exfil to outside projects
- CMEK for sensitive data; Secret Manager with IAM per secret
- GKE: private clusters, Workload Identity, Binary Authorization, Shielded nodes, network policies

---

## Engagement Cheatsheet

```text
org hierarchy → org policies (no SA keys, domain-restricted sharing, public access prevention)
→ IAM cleanup (no basic roles, impersonation scoped) → org log sink + Data Access logs → SCC detectors
→ IAP + VPC SC → detections (SA keys, SetIamPolicy, GenerateAccessToken, sink changes, firewall)
```

---

## Key References

- Google Cloud security foundations blueprint; CIS Google Cloud Platform Benchmark
- Cloud Audit Logs and Organization Policy constraint references
- Security Command Center docs
- Related: `defensive-cloud-ir`, `defensive-cspm`, `defensive-k8s-security`
