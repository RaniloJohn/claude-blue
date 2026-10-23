---
name: defensive-cloud-ir
description: "Cloud incident response for AWS, Azure, and GCP: leaked access keys, compromised IAM users/roles/service principals/service accounts, instance compromise, S3/Blob/GCS data exposure, cryptomining, logging tampering, and attack-sequence findings (GuardDuty Extended Threat Detection). Covers preserving cloud evidence (CloudTrail, Activity/Entra logs, Cloud Audit Logs, snapshots), credential revocation including AWS role session revocation, isolation security groups, forensic snapshots, scoping attacker-created resources, and recovery. Use when responding to any cloud control-plane or workload compromise."
---

# Cloud Incident Response

Cloud IR is control-plane forensics: who called which API, with which credential, from where. Logs are your disk image — preserve them first, because retention and attacker tampering both erase history.

## Quick Workflow

1. Identify the compromised principal(s) and credential type
2. Preserve logs (export to separate, locked account/project/subscription)
3. Contain the credential (deactivate/revoke), not just the resource
4. Scope every API call by the principal since first malicious use
5. Inventory attacker-created resources and persistence
6. Isolate and snapshot affected workloads
7. Eradicate, rotate, recover; close the exposure path

---

## 1. AWS

### Containment

```bash
# Deactivate leaked key (reversible)
aws iam update-access-key --user-name <u> --access-key-id AKIA... --status Inactive
# Deny everything on the principal
aws iam attach-user-policy --user-name <u> --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
# Revoke active role sessions: console "Revoke active sessions" adds inline AWSRevokeOlderSessions
#   policy denying tokens with aws:TokenIssueTime before now
# Isolate EC2: swap to SG with no inbound/outbound rules (existing tracked connections may persist — also use NACL)
aws ec2 modify-instance-attribute --instance-id i-... --groups sg-isolation
# Preserve
aws ec2 create-snapshot --volume-id vol-... --description "IR-<case> <UTC>"
aws ec2 modify-instance-attribute --instance-id i-... --disable-api-termination
```

### Scoping (CloudTrail)

```sql
SELECT eventtime, eventsource, eventname, awsregion, sourceipaddress, useragent, errorcode,
       requestparameters, responseelements
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIA...'
   OR useridentity.arn LIKE '%<role-session-name>%'
ORDER BY eventtime;
```

Persistence to check: `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `AttachUserPolicy`/`PutUserPolicy`, `CreateRole`/`UpdateAssumeRolePolicy` (external principals), `CreatePolicyVersion` (SetAsDefault), Lambda functions/layers, EC2 user data, SSM documents, IAM Identity Center assignments, new SAML/OIDC providers, cross-account roles, `PutBucketPolicy`/`PutBucketReplication`.

Evasion: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteDetector`, `DisableSecurityHub`, `DeleteFlowLogs`, region hopping to unmonitored regions.

GuardDuty Extended Threat Detection correlates signals into critical **attack sequence** findings (IAM/S3, EKS, EC2, ECS) — triage these first; they include the signal chain.

---

## 2. Azure / Entra

### Containment

```powershell
Revoke-MgUserSignInSession -UserId <id>
Update-MgUser -UserId <id> -AccountEnabled:$false
# Service principal: remove added credentials, disable
Get-MgServicePrincipal -ServicePrincipalId <id> | Select -Expand PasswordCredentials
Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false
# Azure RBAC: remove attacker role assignments
Get-AzRoleAssignment | ? {$_.ObjectId -eq '<attacker-object-id>'} | Remove-AzRoleAssignment
# VM isolation: NSG deny-all; snapshot OS/data disks
```

### Scoping

- `AuditLogs`: role assignments (`Add member to role`), app credential adds, federation changes (`Set domain authentication`), CA policy changes
- `AzureActivity`: `Microsoft.Authorization/roleAssignments/write`, `Microsoft.Compute/virtualMachines/runCommand/action`, `Microsoft.Storage/storageAccounts/listKeys/action`, `Microsoft.KeyVault/vaults/secrets/read` (data plane in Key Vault diagnostics)
- `SigninLogs` + non-interactive + service principal sign-ins for the principal

---

## 3. GCP

```bash
gcloud iam service-accounts keys list --iam-account <sa>@<proj>.iam.gserviceaccount.com
gcloud iam service-accounts keys disable <key-id> --iam-account <sa>@...
gcloud projects get-iam-policy <proj> --format=json > iam-before.json
gcloud compute instances add-tags <vm> --tags=quarantine   # with deny-all firewall rule on tag
gcloud compute disks snapshot <disk> --snapshot-names=ir-<case>
```

Scope with Cloud Audit Logs (Admin Activity always on; Data Access if enabled):

```text
protoPayload.authenticationInfo.principalEmail="<sa>@<proj>.iam.gserviceaccount.com"
protoPayload.methodName:("SetIamPolicy" OR "CreateServiceAccountKey" OR "GenerateAccessToken")
```

---

## 4. Evidence Preservation

| Cloud | Preserve |
|---|---|
| AWS | CloudTrail (incl. data events if enabled), VPC Flow Logs, S3 access logs, GuardDuty findings, Config history, EBS snapshots, memory via SSM if agent present |
| Azure | Entra sign-in/audit, Activity Log, NSG flow logs, Key Vault/Storage diagnostics, disk snapshots |
| GCP | Cloud Audit Logs (export via sink), VPC Flow Logs, disk snapshots |

Copy to a dedicated forensics account/subscription/project with restricted access and object lock/immutability.

---

## 5. Common Scenarios

| Scenario | Key steps |
|---|---|
| Access key in public repo | Deactivate key; CloudTrail by key ID since commit time; look for `GetCallerIdentity` then enumeration; secret scanning on all repos |
| Cryptomining | Instances in unusual regions/types (`RunInstances` with GPU types); billing anomalies; delete after snapshotting one |
| Bucket exposure | `PutBucketPolicy`/ACL changes; S3 access logs or CloudTrail data events for `GetObject` from external IPs |
| SSRF → IMDS credential theft | GuardDuty `InstanceCredentialExfiltration`; enforce IMDSv2; rotate role |
| Federation backdoor (Entra) | Domain auth changed to federated with attacker IdP; revert, rotate token-signing |

---

## 6. Eradication & Recovery

```text
[ ] Remove attacker principals, keys, roles, policies, trust relationships, OAuth apps
[ ] Rotate all secrets the principal could read (Secrets Manager, Key Vault, Parameter Store)
[ ] Rebuild compromised workloads from trusted images
[ ] Enable/repair logging in all regions; org-level trails/sinks
[ ] Close vector: IMDSv2, least privilege, secret scanning, MFA on console, SCP guardrails
```

---

## Engagement Cheatsheet

```text
Identify principal → export logs → deactivate/revoke credential → scope all API calls
→ list attacker-created persistence → snapshot + isolate → eradicate → rotate → guardrails
```

---

## Key References

- AWS Security Incident Response Guide; GuardDuty Extended Threat Detection docs
- Microsoft: Incident response playbooks (Entra, app consent); Azure forensic guidance
- Google Cloud: Data incident response; Cloud Audit Logs
- Related: `defensive-aws-security`, `defensive-azure-security`, `defensive-gcp-security`, `defensive-entra-id`
