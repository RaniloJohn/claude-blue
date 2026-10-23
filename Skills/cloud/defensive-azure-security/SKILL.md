---
name: defensive-azure-security
description: "Azure security operations and hardening: management group and subscription design, Azure Policy guardrails, Azure RBAC least privilege and PIM for resources, Defender for Cloud (CSPM, Defender plans for servers, storage, Key Vault, SQL, containers, App Service, Resource Manager), Activity Log and diagnostic settings to Log Analytics/Sentinel, Key Vault security, Storage account hardening (public access, shared keys, SAS), NSGs and Azure Firewall, Bastion/JIT VM access, managed identities, and detections for role assignment abuse, run command, key listing, and data exfiltration. Use for Azure reviews, detection engineering, and hardening."
---

# Azure Security

Azure control plane = Azure Resource Manager (ARM) governed by Entra ID identities and Azure RBAC. Attackers who gain Owner/Contributor/User Access Administrator at subscription scope can run code on VMs, read secrets, and exfiltrate data.

## Quick Workflow

1. Hierarchy: management groups → subscriptions by environment/risk
2. Azure Policy initiatives (deny/audit/deployIfNotExists)
3. RBAC: no standing Owner; PIM for privileged roles; custom least-privilege roles
4. Logging: Activity Log + resource diagnostic settings → Log Analytics/Sentinel
5. Defender for Cloud: enable relevant plans; fix recommendations by attack path
6. Network: no public management ports; Bastion/JIT; private endpoints
7. Detections in Sentinel

---

## 1. Guardrails (Azure Policy)

| Policy | Effect |
|---|---|
| Storage accounts should disable public blob access | Deny |
| Storage accounts should prevent shared key access | Audit → Deny |
| Key Vault should have purge protection + soft delete | Deny |
| Key Vault should use RBAC permission model | Audit |
| Management ports should be closed on VMs | Audit/Deny via NSG policy |
| Allowed locations | Deny |
| Require diagnostic settings to Log Analytics | DeployIfNotExists |
| Disallow public IPs on NICs (except approved) | Deny |
| Require private endpoints for PaaS | Audit |

Assign at management group scope; use exemptions with expiry instead of disabling.

---

## 2. RBAC & Identity

```text
[ ] No standing Owner/User Access Administrator; PIM eligible with approval
[ ] Avoid Contributor at subscription scope for humans; scope to resource groups
[ ] Managed identities for workloads; no client secrets in code
[ ] Review service principals with Owner/Contributor
[ ] Break-glass access documented and monitored
[ ] Entra roles separate from Azure RBAC — review both
```

High-risk actions: `Microsoft.Authorization/roleAssignments/write`, `Microsoft.Compute/virtualMachines/runCommand/action`, `Microsoft.Compute/virtualMachines/extensions/write`, `Microsoft.Storage/storageAccounts/listKeys/action`, `Microsoft.KeyVault/vaults/accessPolicies/write`, `Microsoft.Web/sites/config/list/action`, `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action`.

---

## 3. Logging

| Source | Destination |
|---|---|
| Activity Log (subscription) | Log Analytics (`AzureActivity`) via diagnostic setting |
| Entra sign-in/audit | Log Analytics (see `defensive-entra-id`) |
| Key Vault `AuditEvent` | Log Analytics (`AzureDiagnostics` or resource-specific tables) |
| Storage (blob/file/queue/table) logs | Log Analytics (`StorageBlobLogs` etc.) |
| NSG/VNet flow logs | Storage + Traffic Analytics (VNet flow logs replace NSG flow logs) |
| AKS audit | Log Analytics |
| Defender for Cloud alerts | Sentinel connector |

---

## 4. Defender for Cloud

- Foundational CSPM free; Defender CSPM adds attack path analysis, cloud security explorer, agentless scanning
- Workload plans: Servers (MDE integration, vulnerability assessment, JIT), Storage (malware scanning, sensitive data threat detection), Key Vault, SQL, Containers, App Service, Resource Manager (control-plane anomalies), DNS (folded into Servers plan in newer versions — verify)
- Prioritize recommendations by attack paths to internet-exposed, high-privilege, or sensitive-data resources

---

## 5. Detections (Sentinel KQL)

```kql
// Role assignment created (esp. Owner/UAA)
AzureActivity
| where OperationNameValue =~ "Microsoft.Authorization/roleAssignments/write" and ActivityStatusValue == "Success"
| extend Props = parse_json(Properties)
| project TimeGenerated, Caller, CallerIpAddress, ResourceId = _ResourceId, Props

// VM Run Command
AzureActivity
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/runCommand/action"
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId

// Storage key listing
AzureActivity
| where OperationNameValue =~ "Microsoft.Storage/storageAccounts/listKeys/action"
| summarize count() by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where count_ > 5

// Key Vault secret reads by unusual identity (resource-specific or AzureDiagnostics)
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
| summarize Secrets = dcount(id_s), Count = count() by identity_claim_upn_s, CallerIPAddress
| where Secrets > 10

// Diagnostic settings deleted (logging evasion)
AzureActivity | where OperationNameValue =~ "Microsoft.Insights/diagnosticSettings/delete"
```

---

## 6. Data & Network

- Storage: disable public access, disable shared key auth (use Entra auth), short-lived user-delegation SAS, private endpoints, immutable storage for backups/logs
- Key Vault: RBAC model, purge protection, private endpoint, firewall
- NSGs: deny inbound from internet to 22/3389/5985/5986; Azure Bastion or JIT
- Azure Firewall / NVA with egress allowlists for servers
- Private endpoints for PaaS; disable public network access where possible

---

## Engagement Cheatsheet

```text
MG hierarchy + Policy guardrails → PIM for RBAC → diagnostic settings everywhere → Defender plans + attack paths
→ storage/KV hardening → Bastion/JIT + private endpoints → Sentinel detections (role assignment, runCommand, listKeys, KV reads, diag deletes)
```

---

## Key References

- Microsoft cloud security benchmark (MCSB); CIS Microsoft Azure Foundations Benchmark
- Defender for Cloud docs; Azure Policy built-in definitions
- Related: `defensive-entra-id`, `defensive-cloud-ir`, `defensive-sentinel`, `defensive-cspm`
