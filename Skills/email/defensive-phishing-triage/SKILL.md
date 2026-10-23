---
name: defensive-phishing-triage
description: "Phishing email triage and response for SOC analysts: user-reported phish workflow, header analysis (Received chain, Return-Path, Reply-To, Authentication-Results, ARC), URL analysis (redirect chains, AiTM phishing kits like Evilginx/Tycoon-style, QR code phishing, CAPTCHA-gated pages, legitimate-service abuse), attachment triage, sandboxing with data-sharing caution, determining clicks/credential entry/execution, tenant-wide search and purge (Defender Threat Explorer, compliance search, Google Workspace investigation tool), blocking, user notification, and metrics. Use when handling reported or detected phishing."
---

# Phishing Triage

Every phishing case has three questions: **is it malicious, who received it, and did anyone interact?** Answer them in that order, then contain at tenant scale.

## Quick Workflow

1. Get the original message (.eml/.msg with headers), not a forward
2. Analyze headers, sender, URLs, attachments
3. Verdict + confidence
4. Scope: all recipients of same campaign
5. Interaction check: clicks, credential entry, downloads, executions
6. Contain: purge, block, reset/revoke affected users
7. Notify users; record metrics; feed detections

---

## 1. Header Analysis

| Header | Check |
|---|---|
| `From` | Display name vs address; lookalike domain (homoglyphs, extra letters, new TLD) |
| `Reply-To` | Differs from From → common in BEC |
| `Return-Path` | Envelope sender domain (SPF evaluated here) |
| `Received` | Read bottom-up; first external hop = true origin; check IPs/hosts |
| `Authentication-Results` | spf / dkim / dmarc results and alignment |
| `ARC-*` | Forwarding chain authentication |
| `Message-ID` | Domain consistency with sender platform |
| `X-MS-Exchange-Organization-SCL`, `X-Forefront-Antispam-Report` | M365 filtering verdicts |

Lookalike detection: compare to your domains with edit distance; check domain registration age (WHOIS/RDAP).

---

## 2. URL Analysis

```text
1. Extract all URLs (body, HTML hrefs, buttons, QR codes, attachments)
2. Defang in notes
3. Expand redirects (safe tooling, no credentials): urlscan.io (private scan), sandboxed browser
4. Identify landing page type: credential harvest, AiTM proxy, malware download, callback phishing
5. Check domain age, hosting, TLS cert issuance (CT logs)
```

| Technique | Indicators |
|---|---|
| AiTM phishing (Evilginx, PhaaS kits) | Page proxies real Microsoft/Google login; session cookie theft; Entra sign-in from kit IP right after user sign-in |
| QR code phishing (quishing) | Image-only body with QR; decode QR (`zbarimg`) — URL bypasses link scanners |
| CAPTCHA/Turnstile gating | Blocks automated scanners; analyze in interactive sandbox |
| Legit service abuse | SharePoint/OneDrive/Google Docs/Dropbox/DocuSign/Canva/Notion pages hosting phishing links |
| Open redirects | Trusted domain redirecting (`google.com/url?q=`, ad trackers) |
| HTML/SVG attachments | Local phishing forms or smuggling (see `defensive-maldoc-analysis`) |
| Callback phishing (TOAD) | No link; phone number to "cancel subscription" → remote access tool |

```bash
zbarimg qr.png                                   # decode QR
```

Do not visit attacker URLs from corporate IPs or logged-in browsers; use isolated sandbox/VPN egress. Public scans (urlscan public) expose the URL — choose private visibility for sensitive cases.

---

## 3. Scope & Interaction (Microsoft 365)

```kql
// Recipients of campaign
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain =~ "evil-lookalike.example" or Subject has "Invoice #4471"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, DeliveryLocation, NetworkMessageId

// Clicks
UrlClickEvents
| where Timestamp > ago(7d) and Url has "evil-lookalike"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough

// Sign-ins after click (possible credential entry / AiTM)
SigninLogs
| where TimeGenerated > ago(7d) and UserPrincipalName in~ ("user1@contoso.com","user2@contoso.com")
| where IPAddress !in ("<corp egress IPs>")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType

// Downloads/execution
DeviceFileEvents | where FileOriginUrl has "evil-lookalike"
```

Google Workspace: Security investigation tool (Gmail log events), Admin console message search.

---

## 4. Containment

| Action | Tool |
|---|---|
| Purge from mailboxes | Defender Threat Explorer → Take action (soft delete); or `New-ComplianceSearch` + `New-ComplianceSearchAction -Purge -PurgeType SoftDelete` |
| Block sender/domain/URL | Tenant Allow/Block List; transport rule; secure email gateway |
| Block URL/domain on endpoints & proxy | EDR network indicators, DNS RPZ, proxy |
| Users who entered creds | Revoke sessions, reset password, review MFA methods and inbox rules (see `defensive-bec-response`) |
| Users who executed payload | Isolate host → malware IR |

```powershell
New-ComplianceSearch -Name "Phish-2026-114" -ExchangeLocation All `
  -ContentMatchQuery 'subject:"Invoice #4471" AND from:billing@evil-lookalike.example'
Start-ComplianceSearch -Identity "Phish-2026-114"
New-ComplianceSearchAction -SearchName "Phish-2026-114" -Purge -PurgeType SoftDelete
```

---

## 5. Verdict Notes

```text
Verdict: Malicious credential phish (AiTM) — Confidence High
Sender: billing@evil-lookalike[.]example (domain registered 2026-10-20), SPF pass for attacker domain, DMARC none
Lure: invoice → hxxps://login-portal[.]evil-lookalike[.]example/... (Microsoft login proxy)
Recipients: 37 | Clicked: 4 | Sign-ins from kit IP: 1 (j.doe)
Actions: purged 37, blocked domain/URL, revoked j.doe sessions + reset + MFA review
Detections: new rule for sign-in from kit ASN after UrlClickEvents
```

---

## 6. Metrics

- Report-to-triage time; triage-to-purge time
- Reporting rate (users who report) vs click rate
- % of reported mail that is malicious (tune awareness)
- Repeat clickers (targeted training)

---

## Engagement Cheatsheet

```text
original .eml → headers (Received/Return-Path/Reply-To/auth) → URLs (expand safely, QR decode) → attachments
→ verdict → campaign scope → clicks/sign-ins/downloads → purge + block + revoke → notify → detections
```

---

## Key References

- Microsoft Defender for Office 365: Threat Explorer, AIR, Tenant Allow/Block List
- Microsoft: AiTM phishing detection guidance
- urlscan.io, PhishTool, CyberChef
- Related: `defensive-bec-response`, `defensive-email-auth`, `defensive-maldoc-analysis`
