---
name: defensive-saas-security
description: "SaaS security posture and incident defense: SaaS inventory and shadow IT, SSPM, SSO/SCIM enforcement, OAuth and connected-app governance, API and bulk-export restrictions, IP/network allowlists, event monitoring, and lessons from major SaaS attack campaigns — Salesloft Drift OAuth token theft against Salesforce (UNC6395, Aug 2025), ShinyHunters-linked vishing of Salesforce Data Loader authorizations (UNC6040/UNC6240) and 2026 SSO-relay and attacker-MFA-enrollment campaigns, and the 2024 Snowflake customer credential campaign (UNC5537) with Snowflake's MFA and password-deprecation phases (Phase 3 Aug–Oct 2026). Includes hunting queries and response steps. Use when securing SaaS platforms or responding to SaaS data theft."
---

# SaaS Security

Attackers increasingly skip endpoints and go straight to SaaS data: stolen OAuth tokens from third-party integrations, vishing users into authorizing malicious apps, relaying SSO logins, and credential stuffing accounts without MFA. None of the major 2024–2025 campaigns required a SaaS platform vulnerability.

## Quick Workflow

1. Inventory SaaS apps and integrations (CASB/SWG discovery, IdP app catalog, OAuth grants)
2. Enforce SSO + phishing-resistant MFA; SCIM for lifecycle; disable local logins
3. Govern OAuth/connected apps (allowlist, least scope, IP restrictions)
4. Restrict API access and bulk export to those who need it
5. Monitor SaaS audit/event logs in SIEM; hunt for mass export
6. Prepare SaaS IR (token revocation, secret rotation)

---

## 1. Posture Controls

| Control | Detail |
|---|---|
| SSO + MFA | All SaaS via IdP; block password/local login where possible; phishing-resistant for admins |
| SCIM | Automatic deprovisioning |
| OAuth/connected apps | Allowlist; minimal scopes (avoid "full"); review third-party integrations regularly; IP restrictions on connected apps |
| API access | Remove "API Enabled"-style permissions from broad profiles; grant via specific permission sets |
| Bulk export | Restrict export/report/data loader permissions |
| Network restrictions | Login IP ranges / network policies; block commercial VPNs/Tor for privileged access where feasible |
| Session timeouts | Shorter sessions for sensitive SaaS |
| Logging | Event Monitoring / audit logs exported (may require add-on licensing, e.g., Salesforce Shield) |
| SSPM | Continuous misconfiguration detection across SaaS (AppOmni, Obsidian, Adaptive Shield/CrowdStrike, Valence, etc.) |

---

## 2. Campaign Lessons

### Salesloft Drift → Salesforce (UNC6395, Aug 8–18, 2025)

- Stolen Drift OAuth access/refresh tokens used against customer Salesforce instances; tokens revoked Aug 20, 2025; Drift Email also affected a small number of Google Workspace accounts
- Actor ran `SELECT COUNT()` then bulk exports (User, Case, Account, Opportunity), searched exported data for **secrets** (AWS `AKIA` keys, Snowflake tokens, passwords), deleted query jobs (logs remained)
- IOC user agents included `Salesforce-Multi-Org-Fetcher/1.0`, `Salesforce-CLI/1.0`, `python-requests/2.32.4`, `Python/3.11 aiohttp/3.12.15`; Tor exits
- Response: revoke/rotate all integration tokens, review Event Monitoring incl. `UniqueQuery`, scan SaaS data for secrets (TruffleHog), enforce connected-app IP restrictions, least-privilege scopes

### Vishing → Malicious Connected App (UNC6040, reported June 2025)

- Callers posing as IT support led employees to authorize a modified Salesforce Data Loader ("connection code"), then exported data; extortion later by UNC6240 claiming ShinyHunters
- Mitigate: restrict who can authorize/manage connected apps, allowlist apps, restrict API/bulk export, IP restrictions, Shield Transaction Security policies, help-desk impersonation training

### SSO Relay + Attacker MFA Enrollment (2026 reporting)

- Live vishing + real-time phishing of Okta/Entra/Google SSO on lookalike domains (e.g., `<company>sso.com`), coached MFA approval, then **enrolling attacker MFA devices** and pivoting to Salesforce, SharePoint, DocuSign, Slack, Atlassian, Dropbox
- Detect: new MFA enrollment + logins from commercial VPN/residential proxies + bulk downloads; deletion of MFA-enrollment notification emails; PowerShell user agents on SharePoint downloads

### Snowflake Customers (UNC5537, 2024)

- ~165 organizations notified; ≥ 79.7% of accounts used had credentials previously exposed by infostealers (some unrotated since 2020); no MFA, no network allowlists
- Exfil pattern: `CREATE TEMPORARY STAGE` → `COPY INTO @stage FROM (SELECT ...)` → `GET`
- Snowflake MFA/password deprecation (per docs; dates per account, notified individually): Phase 1 Sep 2025–Jan 2026 (MFA for Snowsight password sign-in), Phase 2 May–Jul 2026 (new users need MFA; no new `LEGACY_SERVICE` users), **Phase 3 Aug–Oct 2026** (all human password sign-ins need MFA; passwords blocked for `LEGACY_SERVICE`, which migrates to `TYPE=SERVICE`) — migrate integrations to key-pair/OAuth/workload identity

---

## 3. Hunting

| Platform | Hunt |
|---|---|
| Salesforce | Event Monitoring: API/bulk query volume per user, `UniqueQuery` with `COUNT()` across objects, new connected apps, logins from Tor/VPN, unusual client IDs/user agents |
| Snowflake | `LOGIN_HISTORY` (client types, IPs, password vs key-pair), `QUERY_HISTORY` for `CREATE TEMPORARY STAGE`, `COPY INTO @`, `GET`, large `SELECT *` (verify view/column names for your account) |
| Microsoft 365 | Scripted mass downloads, consent grants (`defensive-m365-security`) |
| Google Workspace | Token log new OAuth grants, Drive mass downloads (`defensive-google-workspace-security`) |
| IdP | New MFA enrollment followed by first-time SaaS access and exports (`defensive-threat-hunting`) |

---

## 4. SaaS Incident Response

1. Revoke sessions and **OAuth tokens (incl. refresh tokens)** for affected users/integrations
2. Disable or remove malicious connected apps; rotate integration credentials
3. Search exported data for secrets → rotate those secrets in every downstream system (cloud keys, database tokens)
4. Preserve logs (export before retention expires)
5. Assess data exposure for notification (`defensive-incident-response`)
6. Harden: allowlists, scopes, IP restrictions, MFA, monitoring

---

## Engagement Cheatsheet

```text
inventory apps + integrations → SSO + phishing-resistant MFA + SCIM, no local logins → OAuth allowlist, least scope, IP-restricted connected apps
→ restrict API/bulk export → SaaS logs to SIEM (Event Monitoring/Shield) + SSPM → hunt mass export, COUNT() recon, new apps, VPN/Tor logins, MFA enroll→export
→ IR: revoke tokens (incl. refresh), rotate secrets found in exported data, preserve logs → Snowflake Phase 3: kill password service users
```

---

## Key References

- Google Threat Intelligence Group: Salesloft Drift data theft (Aug 2025), UNC6040 vishing (June 2025), UNC5537 Snowflake (June 2024)
- Snowflake docs: MFA rollout / password deprecation phases; Salesforce security guidance for connected apps
- Related: `defensive-okta-security`, `defensive-m365-security`, `defensive-google-workspace-security`, `defensive-cloud-data-security`, `defensive-tool-secret-scanners`
