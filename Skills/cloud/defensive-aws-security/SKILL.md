---
name: defensive-aws-security
description: "AWS security operations and hardening: organization guardrails (SCPs, RCPs, declarative policies), IAM least privilege and access analysis, root account protection, IAM Identity Center, CloudTrail organization trails and data events, GuardDuty (incl. Extended Threat Detection attack sequences, Runtime Monitoring, S3/EKS/RDS/Lambda protection), Security Hub CSPM, Detective, Config, VPC Flow Logs, Route 53 Resolver query logs, IMDSv2 enforcement, S3 Block Public Access, KMS, Secrets Manager, and CloudTrail detection queries for privilege escalation, persistence, defense evasion, and exfiltration. Use for AWS security reviews, detection engineering, and hardening."
---

# AWS Security

AWS security is identity-first. Most AWS incidents start with a leaked or over-privileged credential, then pivot through IAM. Guardrails at the organization level stop whole classes of mistakes.

## Quick Workflow

1. Organization: separate accounts (security, log archive, workloads); SCP guardrails
2. Logging: org CloudTrail (all regions, validation, KMS), Config, VPC Flow, DNS logs → log archive account
3. Detection: GuardDuty (all regions, all protection plans), Security Hub CSPM
4. Identity: no root use, Identity Center, least privilege, no long-lived keys
5. Data: S3 Block Public Access (account + org), KMS, Secrets Manager
6. Workloads: IMDSv2, SSM instead of SSH, patching, EKS hardening
7. CloudTrail detections → SIEM

---

## 1. Organization Guardrails (SCP examples)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "DenyLeaveOrg", "Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*" },
    { "Sid": "ProtectSecurityServices", "Effect": "Deny",
      "Action": ["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail",
                 "guardduty:DeleteDetector","guardduty:DisassociateFromMasterAccount","guardduty:UpdateDetector",
                 "config:StopConfigurationRecorder","config:DeleteConfigurationRecorder",
                 "securityhub:DisableSecurityHub"],
      "Resource": "*",
      "Condition": { "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdmin" } } },
    { "Sid": "DenyUnapprovedRegions", "Effect": "Deny", "NotAction": ["iam:*","organizations:*","sts:*","support:*","cloudfront:*","route53:*"],
      "Resource": "*", "Condition": { "StringNotEquals": { "aws:RequestedRegion": ["ap-southeast-1","us-east-1"] } } },
    { "Sid": "RequireIMDSv2", "Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": { "StringNotEquals": { "ec2:MetadataHttpTokens": "required" } } }
  ]
}
```

Also consider Resource Control Policies (RCPs) to restrict resource access to your org (data perimeter) and EC2 declarative policies (e.g., IMDS defaults, block public AMI sharing).

---

## 2. Identity

```text
[ ] Root: MFA (hardware/passkey), no access keys, alarm on any root use; centralized root access management for member accounts
[ ] Humans via IAM Identity Center (SSO) with short sessions; no IAM users for people
[ ] Workloads via roles (instance profiles, IRSA/EKS Pod Identity, Lambda roles); no static keys
[ ] IAM Access Analyzer: external access findings, unused access, policy validation
[ ] Permission boundaries for delegated admins
[ ] Credential report: rotate/remove keys > 90 d; remove unused users
```

Privilege-escalation-capable permissions to watch: `iam:PassRole` + compute create, `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy`/`AttachRolePolicy`, `iam:PutUserPolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey` on others, `iam:CreateLoginProfile`/`UpdateLoginProfile`, `lambda:UpdateFunctionCode`, `ssm:SendCommand`, `ec2:ModifyInstanceAttribute` (userData).

---

## 3. Logging & Detection Services

| Service | Configure |
|---|---|
| CloudTrail | Org trail, all regions, log file validation, KMS, S3 with Object Lock in log archive; data events for sensitive S3/Lambda |
| GuardDuty | Delegated admin; all regions; S3, EKS audit + Runtime Monitoring, Malware Protection, RDS, Lambda protection; Extended Threat Detection (on by default) correlates attack sequences |
| Security Hub CSPM | AWS FSBP + CIS standards; aggregation region |
| Config | All resources, conformance packs |
| VPC Flow Logs | All VPCs (at least reject + accept at VPC level) |
| Route 53 Resolver query logs | DNS visibility for C2/exfil |
| Detective | Investigation graphs |
| IAM Access Analyzer | External + unused access |

---

## 4. CloudTrail Detections

| Detection | Events |
|---|---|
| Root activity | `userIdentity.type = Root` (any) |
| Console login without MFA | `ConsoleLogin` with `additionalEventData.MFAUsed = No` |
| Logging tamper | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteFlowLogs`, `DeleteDetector`, `StopConfigurationRecorder` |
| Persistence | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `CreateRole` with external trust, `UpdateAssumeRolePolicy`, `CreateOpenIDConnectProvider`, `CreateSAMLProvider` |
| Privilege escalation | `AttachUserPolicy`/`AttachRolePolicy` with `AdministratorAccess`, `PutUserPolicy`, `CreatePolicyVersion` + `setAsDefault` |
| Recon burst | Many `List*`/`Describe*`/`Get*` + `AccessDenied` from one principal; `GetCallerIdentity` from new IP |
| Data exposure | `PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock`, `PutBucketReplication`, `ModifySnapshotAttribute` (createVolumePermission add), `ModifyDBSnapshotAttribute` |
| Secrets access | `GetSecretValue`, `GetParameter(s)` with `withDecryption`, `Decrypt` spikes |
| Compute abuse | `RunInstances` in unusual regions/types, `CreateFunction` + `AddPermission` public |
| SSM abuse | `SendCommand`, `StartSession` by unusual principals |

```sql
-- Athena: admin policy attached
SELECT eventtime, useridentity.arn, eventname, requestparameters, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('AttachUserPolicy','AttachRolePolicy','AttachGroupPolicy')
  AND requestparameters LIKE '%AdministratorAccess%'
ORDER BY eventtime DESC;
```

```kql
// Sentinel AWSCloudTrail
AWSCloudTrail
| where EventName in ("StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors","DeleteDetector")
| project TimeGenerated, UserIdentityArn, SourceIpAddress, EventName, AWSRegion, RequestParameters
```

---

## 5. Data & Network

- S3 Block Public Access at account and org level; bucket policies require TLS (`aws:SecureTransport`); default encryption (SSE-KMS for sensitive)
- KMS key policies least privilege; CloudTrail on key use
- Secrets Manager rotation; no secrets in user data, env vars in plain text, or AMIs
- Security groups: no 0.0.0.0/0 to 22/3389/DB ports; use SSM Session Manager
- VPC endpoints + endpoint policies for S3/DynamoDB (data perimeter)

---

## 6. Workloads

- IMDSv2 required (hop limit 1 for non-container hosts; 2 where containers need IMDS)
- Inspector for EC2/ECR/Lambda vulnerabilities
- EKS: private API endpoint, audit logging, EKS Pod Identity/IRSA, GuardDuty EKS + Runtime Monitoring

---

## Engagement Cheatsheet

```text
multi-account + SCP guardrails → org CloudTrail/Config/Flow/DNS → GuardDuty all plans + Security Hub
→ Identity Center + roles, no keys → Access Analyzer → S3 BPA + KMS + secrets → IMDSv2 + SSM
→ CloudTrail detections in SIEM
```

---

## Key References

- AWS Security Reference Architecture (SRA); AWS Foundational Security Best Practices
- GuardDuty Extended Threat Detection docs; CIS AWS Foundations Benchmark
- Rhino Security Labs IAM privilege escalation research
- Related: `defensive-cloud-ir`, `defensive-cspm`, `defensive-container-hardening`
