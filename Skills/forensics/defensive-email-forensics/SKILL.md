---
name: defensive-email-forensics
description: "Email forensics and message-level investigation: header analysis (Received chain, Return-Path, Message-ID, Authentication-Results, ARC, DKIM-Signature, X-headers from Exchange Online and Google), SPF/DKIM/DMARC verdict interpretation, spoofing vs lookalike vs compromised-account sending, MIME structure and attachment extraction, EML/MSG/PST/OST/MBOX handling, Microsoft 365 message trace, Threat Explorer, Purview content search and audit (MailItemsAccessed, Send, inbox rules), Google Workspace email log search, BEC evidence (forwarding rules, OAuth apps, impossible travel), tools (eml parsers, msgconvert, readpst, libpff, MXToolbox-style header analyzers), and timeline reconstruction. Use when analyzing suspicious emails or reconstructing email-based incidents."
---

# Email Forensics

Answer three questions: **Who really sent it? What did it carry? What happened after delivery?** Headers answer the first, MIME the second, platform logs the third.

## Quick Workflow

1. Obtain the original message (EML/MSG with full headers), not a forward
2. Read the Received chain bottom-up; check authentication results
3. Classify: spoofed, lookalike domain, compromised legitimate account, or legitimate
4. Extract and analyze URLs/attachments safely
5. Use platform logs to scope recipients, clicks, replies, rules, and mailbox access

---

## 1. Header Analysis

| Header | What it tells you |
|---|---|
| `Received:` (read bottom → top) | Path of servers; first external hop = true origin MTA (others can be forged above your boundary, not below it) |
| `Return-Path` / envelope from | Bounce address used for SPF |
| `From:` | Displayed sender (what users see) — DMARC alignment target |
| `Reply-To:` | Where replies go (BEC often differs from From) |
| `Message-ID` | Generating system clues; trace key |
| `Authentication-Results` | SPF, DKIM, DMARC verdicts as evaluated by receiving system |
| `ARC-*` | Authentication chain through forwarders/lists |
| `DKIM-Signature` | `d=` signing domain, `s=` selector |
| Microsoft `X-MS-Exchange-Organization-AuthAs`, `X-Forefront-Antispam-Report` (`SCL`, `SFV`, `CIP`), `X-MS-Exchange-CrossTenant-*` | Internal vs external, spam verdict, connecting IP, tenant IDs |
| Google `X-Gm-Message-State`, `ARC-Authentication-Results` | Gmail processing |

```bash
python3 -c "import email,sys; m=email.message_from_file(open('msg.eml')); [print(k,':',v) for k,v in m.items()]"
grep -iE '^(Received|Authentication-Results|Return-Path|From|Reply-To|Message-ID|DKIM-Signature):' msg.eml
```

---

## 2. Classify the Sender

| Pattern | Indicators |
|---|---|
| Direct spoof of your domain | DMARC fail; origin IP not your MTAs (fix: DMARC `p=reject`, `defensive-email-auth`) |
| Lookalike domain | Auth passes for attacker domain (`rnicrosoft.com`, extra TLD); domain age days/weeks |
| Display-name spoof | From name "CEO Name" with external address |
| Compromised vendor/partner | Auth passes for real domain; unusual reply-to, new bank details, thread hijacking |
| Internal compromised account | `AuthAs: Internal`; sign-in anomalies for sender; inbox rules |
| Legitimate bulk/marketing | Auth passes, list headers, consistent history |

---

## 3. Content & Attachments

```bash
ripmime -i msg.eml -d ./parts          # or: munpack, python email module
msgconvert message.msg                 # MSG → EML (libemail-outlook-message-perl)
readpst -r -o ./pst_out mailbox.pst    # PST/OST export (libpst)
oleid attachment.doc ; olevba attachment.doc     # maldocs → defensive-maldoc-analysis
pdfid attachment.pdf
```

URLs: extract, defang, check redirect chains in a sandbox/URL scanner without clicking from analyst workstation; check for QR codes in images (quishing) and HTML attachments (smuggling).

---

## 4. Platform Logs

| Platform | Source | Use |
|---|---|---|
| Microsoft 365 | Message trace (`Get-MessageTraceV2` in Exchange Online PowerShell; legacy cmdlets retired — verify) | Delivery path, recipients |
| | Defender Threat Explorer / `EmailEvents`, `UrlClickEvents`, `EmailPostDeliveryEvents` | Recipients, clicks, ZAP actions |
| | Purview Audit: `MailItemsAccessed`, `Send`, `New-InboxRule`, `Set-Mailbox` forwarding, `Add-MailboxPermission` | BEC actions, data access |
| | Content search + purge (`New-ComplianceSearchAction -Purge`) | Remove from all mailboxes |
| Google Workspace | Email Log Search; Admin audit; Gmail log events in BigQuery/Security Center | Delivery, actions, investigation tool |

```kql
EmailEvents | where NetworkMessageId == "<id>" | project Timestamp, SenderFromAddress, RecipientEmailAddress, DeliveryAction, DeliveryLocation, ThreatTypes
UrlClickEvents | where NetworkMessageId == "<id>" | project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough
```

---

## 5. BEC Reconstruction

Timeline: credential phish → sign-in from attacker IP/ASN → MFA method added or session token replay → inbox rule (move/delete keywords "invoice", "payment") → mailbox search/`MailItemsAccessed` → fraudulent emails sent (thread hijack) → payment change request. Evidence from Entra sign-ins, UAL, message trace. See `defensive-bec-response`.

---

## Engagement Cheatsheet

```text
original EML/MSG → Received bottom-up + Authentication-Results/ARC → classify (spoof/lookalike/compromised/legit)
→ extract MIME parts safely (ripmime/msgconvert/readpst/olevba/pdfid) → URLs/QR/HTML smuggling
→ message trace + EmailEvents/UrlClickEvents + UAL (MailItemsAccessed, rules, forwarding) → scope + purge → BEC timeline
```

---

## Key References

- RFC 5322 (message format), RFC 5321 (SMTP), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 8617 (ARC), DMARCbis RFC 9989
- Microsoft Defender for Office 365 & Purview Audit docs; Google Workspace Email Log Search
- Related: `defensive-phishing-triage`, `defensive-email-auth`, `defensive-bec-response`, `defensive-maldoc-analysis`, `defensive-entra-id`
