---
name: defensive-bec-response
description: "Business Email Compromise and Microsoft 365 / Google Workspace account takeover response: AiTM phishing and token theft, malicious inbox rules (delete, move to RSS/Archive, forward), external forwarding, OAuth consent phishing, MFA method registration by attacker, MailItemsAccessed scoping, Unified Audit Log and Sentinel/Defender hunting, session and token revocation, payment fraud recall, and post-incident hardening (phishing-resistant MFA, token protection, CA policies). Use when a mailbox or cloud identity is suspected compromised or a fraudulent payment request is reported."
---

# BEC & M365 Account Takeover Response

Modern BEC is identity compromise: adversary-in-the-middle (AiTM) proxies steal session cookies, bypassing non-phishing-resistant MFA. Password reset alone does not evict a token-holding attacker.

## Quick Workflow

1. Confirm compromise signals (sign-in anomalies, inbox rules, MFA changes)
2. Contain: revoke sessions, reset password, remove attacker MFA methods, block sign-in if needed
3. Remove persistence: inbox rules, forwarding, OAuth grants, app passwords, delegates
4. Scope: what mail/files were accessed, who else was targeted, which payments affected
5. Notify finance/bank fast if funds moved (recall windows are short)
6. Harden

---

## 1. Compromise Indicators

| Indicator | Source |
|---|---|
| Sign-in from new ASN/country, hosting provider IP | `SigninLogs`, Identity Protection |
| Same session ID used from two IPs/countries | `SigninLogs`/`AADNonInteractiveUserSignInLogs` `SessionId` |
| New MFA method registered | `AuditLogs` "User registered security info" |
| Inbox rule: delete/move/forward with finance keywords | `OfficeActivity` `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules` |
| External forwarding (`ForwardingSmtpAddress`) | `Set-Mailbox` in UAL |
| OAuth consent to unknown app | `AuditLogs` "Consent to application" |
| Bulk `MailItemsAccessed` | UAL (license-dependent) |
| Outbound phishing from the mailbox | `EmailEvents` |

---

## 2. Hunting Queries (Sentinel / Defender XDR)

```kql
// Session token reuse across IPs (AiTM indicator)
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d) and ResultType == "0"
| summarize IPs = make_set(IPAddress), Countries = make_set(tostring(LocationDetails.countryOrRegion)) by SessionId, UserPrincipalName
| where array_length(IPs) > 1 and array_length(Countries) > 1

// Suspicious inbox rules
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where Parameters has_any ("DeleteMessage","MoveToFolder","RSS","Archive","Conversation History","ForwardTo","RedirectTo")
| where Parameters has_any ("invoice","payment","wire","bank","ACH","remittance") or Parameters has_any ("RSS Feeds","RSS Subscriptions")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters

// MFA method added
AuditLogs
| where OperationName has_any ("User registered security info","User registered all required security info","Update user") and Result == "success"
| where tostring(TargetResources) has "StrongAuthentication"
```

PowerShell (Exchange Online):

```powershell
Connect-ExchangeOnline
Get-InboxRule -Mailbox user@contoso.com | fl Name,Enabled,From,SubjectContainsWords,MoveToFolder,DeleteMessage,ForwardTo,RedirectTo
Get-Mailbox user@contoso.com | fl ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
Get-MailboxPermission user@contoso.com | ? {$_.User -notlike "NT AUTHORITY*"}
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds user@contoso.com -ResultSize 5000
```

---

## 3. Containment Order

```text
1. Revoke sessions:      Revoke-MgUserSignInSession -UserId <id>   (CAE-aware apps respond near real time)
2. Reset password (strong, out-of-band delivery)
3. Remove attacker MFA methods; require re-registration with phishing-resistant method
4. Block sign-in temporarily if attacker still active
5. Remove inbox rules, forwarding, delegates, app passwords
6. Review/remove OAuth grants: Get-MgUserOauth2PermissionGrant; remove app/SP if malicious
7. Block attacker IPs/ASNs via Conditional Access named locations (temporary)
8. Purge phishing sent internally (Defender Threat Explorer / compliance search purge)
```

Refresh tokens are invalidated by revocation; already-issued access tokens may live until expiry (typically ~60–90 min) for non-CAE apps.

---

## 4. Scoping

- Mail accessed: `MailItemsAccessed` (bind/sync), `SearchQueryInitiated` where available
- Files accessed: SharePoint/OneDrive `FileAccessed`, `FileDownloaded`
- Messages sent: `EmailEvents` from compromised mailbox; replies to vendors/finance
- Other victims: same phishing URL/sender in `EmailEvents`/`EmailUrlInfo`; same attacker IPs in sign-ins across tenant
- Financial impact: invoices modified, bank details changed, payments approved

---

## 5. Payment Fraud

- Contact bank immediately for recall; time-critical
- Report to law enforcement (e.g., FBI IC3 in US; PNP-ACG / NBI-CCD in the Philippines)
- Verify vendor bank-change requests by phone using known-good numbers

---

## 6. Hardening

```text
[ ] Phishing-resistant MFA (FIDO2/passkeys, Windows Hello for Business, CBA) for all, admins first
[ ] Conditional Access: require compliant/hybrid-joined device for sensitive apps
[ ] Token Protection (device-bound sign-in session tokens) where supported
[ ] Continuous Access Evaluation (strict location enforcement)
[ ] Block legacy authentication
[ ] Disable automatic external forwarding (outbound spam policy) except approved
[ ] User consent restricted to verified publishers + admin consent workflow
[ ] Alert on inbox rules, MFA registration, OAuth consent, session anomalies
[ ] Finance process: dual control for bank detail changes
```

---

## Engagement Cheatsheet

```text
Revoke sessions → reset pw → kill attacker MFA → remove rules/forwarding/OAuth
→ scope mail/files/sent → bank recall → CA + phishing-resistant MFA + token protection
```

---

## Key References

- Microsoft: Token theft playbook; AiTM phishing investigation guidance; CAE and Token Protection docs
- CISA SCuBA M365 secure configuration baselines
- Related: `defensive-entra-id`, `defensive-phishing-triage`, `defensive-sentinel`
