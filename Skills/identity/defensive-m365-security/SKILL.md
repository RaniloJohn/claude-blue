---
name: defensive-m365-security
description: "Microsoft 365 tenant security: CISA SCuBA baselines and ScubaGear assessments (BOD 25-01 for federal agencies, free for anyone), Maester continuous testing, Exchange Online hardening (Defender for Office 365 Standard/Strict preset policies, SPF/DKIM/DMARC, outbound auto-forwarding control, SMTP AUTH Basic authentication default-off at end of December 2026), Purview Audit (Standard 180-day retention, Premium 1-year for key workloads, MailItemsAccessed), SharePoint/OneDrive external sharing, Teams external access, app consent and OAuth governance, Conditional Access baselines, Secure Score, and detection queries for BEC and data theft. Use when hardening, assessing, or monitoring a Microsoft 365 tenant."
---

# Microsoft 365 Security

Most M365 breaches are identity-driven (phishing, token theft, consent phishing) followed by mailbox abuse (rules, forwarding) and data theft from SharePoint/OneDrive. Baseline the tenant, assess continuously, and log everything.

## Quick Workflow

1. Assess against CISA SCuBA baselines (ScubaGear) and Secure Score
2. Identity first: Conditional Access, phishing-resistant MFA for admins, block legacy auth (`defensive-entra-id`)
3. Exchange: presets, email auth, forwarding control, SMTP AUTH plan
4. Collaboration: sharing, guest access, Teams external access
5. Apps: consent policies, OAuth app review
6. Audit and detect: retention, MailItemsAccessed, SIEM detections
7. Re-assess continuously (Maester / scheduled ScubaGear)

---

## 1. Baselines & Assessment

| Tool | Notes |
|---|---|
| CISA SCuBA baselines | "Shall" items mandatory for US federal agencies under **BOD 25-01** (inventory Feb 21, 2025; tooling Apr 25, 2025; implementation Jun 20, 2025); usable by anyone |
| ScubaGear (PowerShell + OPA) | Assesses Entra ID, Defender, Exchange Online, Teams, SharePoint, Power Platform, Power BI; v1.8.0 (2026) moved SharePoint/Power Platform collection to REST — update runbooks/permissions |
| Maester | Open-source Pester-based continuous testing (PowerShell 7.4+); `Install-Module -Name Maester -Scope CurrentUser`; a 3.0 preview has breaking changes — pin versions in automation |
| Microsoft Secure Score | Prioritized recommendations; track trend |

```powershell
Install-Module -Name ScubaGear -Scope CurrentUser
Initialize-SCuBA                           # installs dependencies (OPA etc.)
Invoke-SCuBA -ProductNames aad,defender,exo,sharepoint,teams -OutPath .\scuba-report
```

---

## 2. Exchange Online

| Control | Recommendation |
|---|---|
| Defender for Office 365 presets | **Standard** for most users, **Strict** for priority accounts; Built-in protection stays on for everyone else; don't edit the threat policies underlying presets |
| Precedence | Strict > Standard > evaluation policies > custom > built-in/defaults |
| Email authentication | SPF, DKIM signing for custom domains, DMARC toward `p=reject` (`defensive-email-auth`) |
| Outbound forwarding | Anti-spam outbound policy: automatic forwarding **Off** (exceptions via specific policy) |
| External sender tagging | Enable external tagging |
| SMTP AUTH Basic authentication | Updated timeline (Jan 2026): **turned off by default for existing tenants at end of December 2026** (admins can re-enable temporarily); new tenants won't have it; final removal date expected in 2H 2027. Move printers/apps to OAuth 2.0, Graph `sendMail`, or connectors now |
| Mailbox auditing | On by default; verify not bypassed |

```powershell
Get-EOPProtectionPolicyRule -Identity "Standard Preset Security Policy" | Format-Table Name,State
Enable-EOPProtectionPolicyRule -Identity "Standard Preset Security Policy"
Enable-ATPProtectionPolicyRule -Identity "Standard Preset Security Policy"
Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled
Get-CASMailbox -ResultSize Unlimited | Where-Object SmtpClientAuthenticationDisabled -eq $false | Select PrimarySmtpAddress
```

---

## 3. SharePoint, OneDrive, Teams

- External sharing: "New and existing guests" or stricter; disable "Anyone" links or set short expiry + view-only
- Default link type: specific people; OneDrive sharing no more permissive than SharePoint
- Guest access reviews; guest expiration
- Teams: restrict external access to allowed domains; block unmanaged Teams accounts if not needed (phishing via Teams chats)
- Sensitivity labels + DLP for confidential content (`defensive-detect-exfiltration`)

---

## 4. Apps & Consent

- User consent: allow only verified publishers with low-risk permissions, or admin consent workflow only
- Review enterprise apps with high-privilege Graph permissions (`Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`) and unknown publishers
- Remove unused apps and stale secrets/certificates on app registrations

---

## 5. Audit

| Tier | Retention |
|---|---|
| Purview Audit (Standard) | On by default; **180 days** for records since Oct 17, 2023 |
| Purview Audit (Premium) | Default **1 year** for Exchange, SharePoint, OneDrive, Entra records (others 180 days); custom policies up to 1 year; 3–10 years with the 10-Year Audit Log Retention add-on |

Retention policies are not retroactive — export to SIEM/data lake for longer history. `MailItemsAccessed` is key for scoping mailbox data access (verify availability for your licensing tier).

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations New-InboxRule,Set-InboxRule,Set-Mailbox -ResultSize 5000
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations MailItemsAccessed -UserIds user@contoso.com -ResultSize 5000
```

---

## 6. Detections

```kql
// Inbox rules forwarding/deleting/moving to obscure folders
CloudAppEvents
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| extend p = tostring(RawEventData.Parameters)
| where p has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo","DeleteMessage","RSS Feeds","Conversation History")
| project Timestamp, AccountDisplayName, IPAddress, ActionType, p
```

```kql
// Mass SharePoint/OneDrive downloads with scripting user agents
OfficeActivity
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| where UserAgent has_any ("PowerShell","python","curl","Go-http-client")
| summarize Files = dcount(OfficeObjectId) by UserId, ClientIP, UserAgent, bin(TimeGenerated, 1h)
| where Files > 50
```

Plus: consent to apps with high-privilege permissions, new external forwarding, sign-ins from hosting ASNs followed by mailbox access, Teams messages from new external tenants with links/attachments.

---

## Engagement Cheatsheet

```text
ScubaGear/Maester/Secure Score baseline → identity CA + phishing-resistant admins + no legacy auth → EXO presets (Standard/Strict), SPF/DKIM/DMARC, auto-forward off,
SMTP AUTH migration before end-Dec 2026 → sharing/guest/Teams external restrictions → consent policy + app review → audit retention (180d std / 1y premium) + SIEM export
→ detections (inbox rules, scripted mass downloads, consent, forwarding) → continuous re-assessment
```

---

## Key References

- CISA BOD 25-01 and SCuBA M365 baselines; github.com/cisagov/ScubaGear; github.com/maester365/maester
- Microsoft Learn: Defender for Office 365 preset security policies; Purview audit retention; Exchange Online Basic auth deprecation; Exchange team blog SMTP AUTH timeline (Jan 2026)
- Related: `defensive-entra-id`, `defensive-bec-response`, `defensive-email-auth`, `defensive-defender-xdr`, `defensive-detect-exfiltration`
