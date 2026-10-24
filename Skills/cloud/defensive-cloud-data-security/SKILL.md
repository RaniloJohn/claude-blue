---
name: defensive-cloud-data-security
description: "Protecting data in AWS, Azure, and GCP: data discovery and classification (Amazon Macie, Microsoft Purview, Google Sensitive Data Protection, DSPM tools), encryption at rest and key management (KMS/Key Vault/Cloud KMS, customer-managed keys, BYOK/HYOK, key policies and rotation), encryption in transit, public exposure prevention (S3 Block Public Access, Azure storage public access disable, GCS public access prevention), data perimeters (AWS SCPs/RCPs with aws:PrincipalOrgID and VPC endpoint policies, Azure Private Endpoints, GCP VPC Service Controls), database security in managed services, snapshot/backup sharing controls, access logging (S3 data events, Storage logs, Data Access logs), and lessons from cloud data breaches. Use when securing cloud-stored data or reviewing data exposure."
---

# Cloud Data Security

Cloud data breaches are mostly **identity and configuration failures**: public buckets, over-broad roles, stolen keys, shared snapshots, and SaaS data platforms without MFA. Layer discovery, prevention, perimeter, and monitoring.

## Quick Workflow

1. Discover and classify sensitive data stores
2. Prevent public exposure at org level
3. Encrypt with appropriate key ownership; lock down key policies
4. Build a data perimeter (only your identities, from your networks, to your resources)
5. Enable data access logging for sensitive stores; alert on anomalies
6. Control copies: snapshots, backups, exports, replication

---

## 1. Discovery & Classification

| Cloud | Service |
|---|---|
| AWS | Amazon Macie (S3 sensitive data discovery, automated discovery) |
| Azure / M365 | Microsoft Purview (data map, classification, sensitivity labels) |
| GCP | Sensitive Data Protection (DLP API, discovery for BigQuery/Cloud Storage) |
| Multi-cloud | DSPM tools (Cyera, Wiz DSPM, Varonis, Sentra, etc.) |

Tag stores with classification (`data_class=restricted`) and owner; drive controls from tags.

---

## 2. Prevent Public Exposure

| Cloud | Control |
|---|---|
| AWS | S3 Block Public Access at **account level** (and org via SCP preventing disablement); default for new buckets is BPA on and ACLs disabled (Object Ownership: bucket owner enforced) |
| Azure | `allowBlobPublicAccess=false` on storage accounts (Azure Policy deny); disable shared key access where possible; private endpoints |
| GCP | Organization Policy `storage.publicAccessPrevention` enforced; `iam.allowedPolicyMemberDomains` (domain-restricted sharing) |

```bash
aws s3control put-public-access-block --account-id 111122223333 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
gcloud resource-manager org-policies enable-enforce storage.publicAccessPrevention --organization=ORG_ID
```

---

## 3. Encryption & Keys

| Topic | Guidance |
|---|---|
| Default encryption | On by default in all three clouds (provider-managed keys) |
| Customer-managed keys (CMK) | For restricted data: separation of duties, revocation capability, key access logs |
| Key policies | Least privilege; separate key admins from key users; deny key deletion except break-glass; enable rotation |
| BYOK / HYOK / external key stores | Regulatory/sovereignty needs (AWS XKS, Azure Managed HSM, GCP Cloud EKM) — weigh availability risk |
| Destruction risk | Attackers with KMS permissions can schedule key deletion/disable keys (ransom) — alert on `ScheduleKeyDeletion`/`DisableKey`, key vault purge; enable purge protection |
| SSE-C abuse | Attackers re-encrypting S3 objects with their own SSE-C keys (2025 campaigns) — restrict `s3:PutObject` with SSE-C via bucket/SCP conditions if unused |

---

## 4. Data Perimeter

| Cloud | Mechanism |
|---|---|
| AWS | SCPs (what your principals can do) + **RCPs** (resource control policies, what any principal can do to your resources) + VPC endpoint policies; conditions `aws:PrincipalOrgID`, `aws:ResourceOrgID`, `aws:SourceVpce`, `aws:SourceIp` |
| Azure | Private Endpoints + disable public network access; Entra Conditional Access for data-plane apps; Azure Policy |
| GCP | VPC Service Controls perimeters around projects/services; access levels (Access Context Manager) |

Example bucket policy deny outside the org:

```json
{
  "Sid": "DenyOutsideOrg",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::restricted-data", "arn:aws:s3:::restricted-data/*"],
  "Condition": { "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "o-abc123" }, "BoolIfExists": { "aws:PrincipalIsAWSService": "false" } }
}
```

---

## 5. Copies & Sharing

- Block public/cross-account sharing of snapshots/AMIs/DB snapshots except to approved accounts (EC2 "block public access for snapshots/AMIs", SCP conditions)
- Azure disk export: restrict `beginGetAccess` (SAS) permissions; short-lived SAS; prefer user delegation SAS
- BigQuery: restrict export to external buckets (VPC-SC); authorized views
- Backups in separate account/subscription with immutability (`defensive-bcp-dr`)

---

## 6. Logging & Detection

Enable for restricted stores: S3 data events (CloudTrail) or S3 server access logs, Azure Storage diagnostic logs (`StorageBlobLogs`), GCP Data Access audit logs (off by default for most services — enable selectively). Detect: mass `GetObject`/download, access from new principals/IPs, policy changes making data public, key policy changes, snapshot sharing (`defensive-detect-exfiltration`, `defensive-detect-collection`).

---

## 7. SaaS Data Platforms

Snowflake/Databricks/BigQuery-style platforms: enforce SSO + MFA (2024 Snowflake customer breaches used stolen credentials without MFA), network policies (IP allowlists), least-privilege roles, monitor login history and large `COPY INTO`/export queries.

---

## Engagement Cheatsheet

```text
discover/classify (Macie/Purview/SDP/DSPM) + tags → org-level public-access prevention → CMK for restricted, tight key policies, purge protection, SSE-C restriction
→ data perimeter (SCP+RCP+VPCE / Private Endpoints / VPC-SC) → control snapshots/exports/SAS → data-access logging + exfil detections → SaaS data platforms SSO+MFA+network policies
```

---

## Key References

- AWS data perimeter whitepaper & RCP docs; Azure Storage security guide; GCP VPC Service Controls & Org Policy docs; Mandiant UNC5537 (Snowflake) report
- Related: `defensive-cspm`, `defensive-aws-security`, `defensive-azure-security`, `defensive-gcp-security`, `defensive-detect-exfiltration`
