---
name: defensive-google-workspace-security
description: "Google Workspace security hardening and monitoring: Google's security checklist (2-Step Verification for all, security keys for admins and high-value users, Advanced Protection), mandatory 2SV enforcement for admin accounts and its timelines, SSO and post-SSO verification, third-party OAuth app access control and allowlisting, Context-Aware Access with Endpoint Verification, Gmail protections (SPF/DKIM/DMARC, attachment and link safety, auto-forwarding restrictions), Drive sharing and DLP, alert center and security center, audit log retention (6 months; Vault indefinite) and lag times, BigQuery export for longer retention, CISA SCuBA ScubaGoggles assessments, and incident response actions. Use when securing or investigating a Google Workspace domain."
---

# Google Workspace Security

Workspace security hinges on **strong admin and user authentication**, **OAuth app governance**, **sharing controls**, and **log export** (native retention is only six months).

## Quick Workflow

1. Enforce 2SV for all users; security keys/passkeys for admins and high-value users
2. Minimize super admins; use delegated admin roles
3. Restrict third-party OAuth apps (allowlist)
4. Context-Aware Access for sensitive apps; Endpoint Verification
5. Gmail and Drive protections; DLP
6. Export logs to BigQuery/SIEM; monitor alert center
7. Assess with ScubaGoggles and Google's security checklist

---

## 1. Authentication

| Control | Detail |
|---|---|
| 2SV | Enforce for all organizational units; prefer security keys/passkeys; disallow SMS where possible |
| Admin 2SV (Google-enforced) | Google is rolling out mandatory 2SV for all admin accounts (announced Dec 2023, gradual): super admins ~90 days' notice, other admins ~60 days; unenrolled admins lose mobile app access after 15 days and web access after 30 days; no opt-out except removing admin rights; service accounts exempt but impersonated admins need 2SV |
| SSO admins | Must still have 2SV on the Google account; **Post-SSO verification** setting controls whether 2SV prompts appear after SSO; direct Google sign-ins always require 2SV |
| Advanced Protection Program | For executives, admins, high-risk users |
| Password Alert | Detects password reuse on non-Google sites (Chrome) |

---

## 2. Admin Hygiene

Few super admins (2–4), break-glass super admin with security keys stored securely, delegated custom roles for daily tasks, separate admin accounts from daily email accounts, alert on admin role changes.

---

## 3. OAuth / Third-Party Apps

- Security → API controls → App access control: restrict unconfigured third-party apps; **allowlist** trusted apps; block high-risk scopes (Gmail, Drive full access) for unverified apps
- Block "less secure apps" / basic auth access
- Review Token (OAuth) audit logs — note they lag by a couple of hours
- 2025–2026 campaigns abused OAuth grants after SSO phishing (e.g., suspicious Workspace OAuth grants for unfamiliar apps) — alert on new grants with broad scopes

---

## 4. Context-Aware Access

- Requires Endpoint Verification and supported editions (Enterprise Standard/Plus, Frontline Standard/Plus, Education Standard/Plus, Enterprise Essentials Plus, Cloud Identity Premium)
- Access levels: IP subnets, location, device policy (encryption, screen lock, company-owned), OS version; advanced mode with CEL
- Access levels are shared with Google Cloud (Access Context Manager) — changes take effect immediately and can lock users out; test with a pilot OU

---

## 5. Gmail & Drive

| Area | Controls |
|---|---|
| Gmail | SPF/DKIM/DMARC; enhanced pre-delivery scanning; attachment protection (encrypted attachments, scripts); link and external image protection; spoofing protections; disable IMAP/POP if unused; restrict **automatic forwarding** |
| Drive | External sharing limited to allowlisted domains or with warnings; default link sharing restricted; shared drive policies; disable Takeout for sensitive OUs / during investigations |
| DLP | Rules for Drive, Gmail, Chat (e.g., national ID numbers, credit cards, custom detectors) |
| Chrome | Safe Browsing always on; managed browser policies (`defensive-browser-forensics`) |

---

## 6. Logging & Retention

| Logs | Retention | Lag |
|---|---|---|
| Admin, Login, Drive, Gmail, Token (OAuth) log events | **6 months** | Most minutes; Login tens of minutes; Token a couple of hours |
| Security/highlight reports | 6 months | 1–3 days |
| Vault log events | Indefinite | — |

Retention cannot be changed → export to **BigQuery** (Workspace log export, edition-dependent) or SIEM for longer history and correlation. Alert center alerts follow log lag times.

---

## 7. Assessment

- Google security checklists (small, medium/large businesses) on knowledge.workspace.google.com (Admin help moved from support.google.com/a)
- CISA SCuBA Google Workspace baselines + **ScubaGoggles** (Python/OPA; `pip install scubagoggles`, see repo docs)
- Security center / security health page (edition-dependent)

---

## 8. Incident Response Actions

Suspend user / reset password and sign-in cookies, revoke OAuth tokens and app-specific passwords, remove recovery info changed by attacker, review and remove Gmail filters/forwarding and delegation, wipe/lock mobile devices via endpoint management, search Gmail logs and use the security investigation tool (edition-dependent) to delete phishing messages domain-wide.

---

## Engagement Cheatsheet

```text
2SV all + security keys for admins/high-value (Google admin 2SV enforcement timelines) → few super admins + delegated roles → OAuth allowlist + block less secure apps
→ Context-Aware Access (Endpoint Verification, pilot OU — shared with GCP) → Gmail/Drive/DLP controls, auto-forward off → export logs (6-month native) to BigQuery/SIEM
→ ScubaGoggles + checklist → IR: reset cookies, revoke tokens, remove filters/forwarding
```

---

## Key References

- knowledge.workspace.google.com: 2SV enforcement for admins, data retention and lag times, security checklists, Context-Aware Access
- CISA SCuBA Google Workspace baselines; github.com/cisagov/ScubaGoggles
- Related: `defensive-phishing-resistant-mfa`, `defensive-saas-security`, `defensive-email-auth`, `defensive-detect-exfiltration`, `defensive-browser-forensics`
