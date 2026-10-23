---
name: defensive-entra-id
description: "Microsoft Entra ID (Azure AD) security operations and hardening: Conditional Access design, phishing-resistant MFA (FIDO2/passkeys, WHfB, CBA), authentication strengths, Privileged Identity Management (PIM), Identity Protection risk policies, Token Protection and Continuous Access Evaluation against token theft/AiTM, workload identity and service principal security, app consent governance, cross-tenant access, Entra Connect/Cloud Sync as Tier 0, break-glass accounts, and detection with SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, and Graph activity logs. Use for Entra hardening reviews, identity detections, and cloud identity incident response."
---

# Microsoft Entra ID Security

Entra ID is the identity control plane for M365 and Azure. Attackers target tokens (AiTM, infostealers), consent (malicious apps), workload identities (service principal secrets), and hybrid sync (Entra Connect). Defend each.

## Quick Workflow

1. Baseline: Secure Score + CISA SCuBA Entra baseline
2. Conditional Access: block legacy auth, phishing-resistant MFA for admins, device compliance
3. Privileged access: PIM, no standing Global Admin, break-glass
4. Token theft defenses: Token Protection, CAE, compliant device
5. App/workload governance: consent restrictions, SP credential hygiene
6. Detection: sign-in anomalies, audit changes, Graph activity

---

## 1. Conditional Access Baseline

| Policy | Scope |
|---|---|
| Block legacy authentication | All users |
| Require phishing-resistant MFA (authentication strength) | All admin roles |
| Require MFA | All users, all cloud apps |
| Require compliant or hybrid-joined device | Sensitive apps / admins |
| Block high sign-in risk; require password change on high user risk | All users (P2) |
| Block device code flow except approved | All users (device code phishing) |
| Restrict access from unmanaged devices to web-only (app-enforced restrictions) | Exchange/SharePoint |
| Token Protection for sign-in sessions | Supported apps/platforms |
| Exclude break-glass accounts (monitored) | All policies |

Use report-only mode first; check sign-in logs `ConditionalAccessStatus` and policy evaluation details.

---

## 2. Privileged Access

- PIM for all directory roles and Azure RBAC owner/contributor at high scopes; approval + MFA on activation; time-bound
- Zero standing Global Administrators except 2 break-glass (FIDO2, excluded from CA, alerted on use)
- Restrict who can create apps, consent, and invite guests
- Separate cloud-only admin accounts (not synced from AD)
- Privileged roles watchlist: Global Admin, Privileged Role Admin, Privileged Authentication Admin, Application Admin, Cloud Application Admin, Exchange Admin, Security Admin, Hybrid Identity Admin, Conditional Access Admin

---

## 3. Token Theft (AiTM, Infostealers)

| Control | Effect |
|---|---|
| Phishing-resistant MFA | Defeats AiTM proxy credential/session capture at sign-in |
| Token Protection (CA session control) | Binds sign-in session tokens to device key — stolen refresh tokens fail elsewhere |
| CAE (strict location enforcement) | Near-real-time revocation on risk/location change for CAE-capable apps |
| Compliant device requirement | Stolen tokens from unmanaged devices less useful |
| Sign-in frequency for sensitive apps | Limits token lifetime value |

Strongest protections (CA, Token Protection, risk-based policies) require premium licensing — document gaps where unlicensed.

---

## 4. Applications & Workload Identities

- User consent: allow only verified publishers + low-risk permissions, or disable with admin consent workflow
- Review apps with high-privilege Graph permissions (`Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`)
- Service principals: certificates over secrets; short expiry; owners limited; monitor credential additions
- Workload identity CA (premium) for SP sign-in locations
- Managed identities preferred over secrets for Azure resources

---

## 5. Hybrid (Entra Connect / Cloud Sync)

- Entra Connect server is **Tier 0** (can sync password hashes, modify cloud objects)
- Protect sync account; monitor `On-Premises Directory Synchronization Service Account` sign-ins from unexpected IPs
- Watch federation changes (`Set domain authentication`, new federated domains) — federation backdoors forge tokens

---

## 6. Detections

```kql
// Admin role assignment outside PIM
AuditLogs
| where OperationName in ("Add member to role","Add eligible member to role") and Result == "success"
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue), Actor = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, Actor, Role, TargetResources

// Credentials added to app/service principal
AuditLogs
| where OperationName has_any ("Add service principal credentials","Update application – Certificates and secrets management")

// Federation change
AuditLogs | where OperationName has_any ("Set domain authentication","Set federation settings on domain")

// Device code flow sign-ins
SigninLogs | where AuthenticationProtocol == "deviceCode" | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName

// Break-glass use
SigninLogs | where UserPrincipalName in ("bg1@contoso.onmicrosoft.com","bg2@contoso.onmicrosoft.com")

// Risky sign-in succeeded
SigninLogs | where RiskLevelDuringSignIn in ("high","medium") and ResultType == "0"
```

Also collect `MicrosoftGraphActivityLogs` (Graph API calls by apps/users) — critical for app-based data access investigations.

Sign-in `ResultType`: `0` success, `50126` invalid creds, `50053` locked, `50074/50076` MFA required, `500121` MFA failed/denied, `53003` blocked by CA, `50158` external security challenge.

---

## 7. Response Actions

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.AccessAsUser.All"
Revoke-MgUserSignInSession -UserId <id>
Update-MgUser -UserId <id> -AccountEnabled:$false
Get-MgUserAuthenticationMethod -UserId <id>          # remove attacker-added methods
Get-MgServicePrincipal -All | ? { $_.PasswordCredentials.Count -gt 0 } | Select DisplayName, AppId
```

---

## Engagement Cheatsheet

```text
SCuBA/Secure Score → CA baseline (legacy auth, phishing-resistant admins, devices, device code)
→ PIM + break-glass → Token Protection + CAE → consent + SP hygiene → Entra Connect Tier 0
→ detections on roles/creds/federation/device code/risk → revocation runbook
```

---

## Key References

- Microsoft Entra documentation: Conditional Access, PIM, Identity Protection, Token Protection, CAE
- CISA SCuBA Microsoft Entra ID baseline
- ERNW White Paper 80 "Token Theft in Microsoft Entra ID" (2026)
- Related: `defensive-bec-response`, `defensive-sentinel`, `defensive-cloud-ir`
