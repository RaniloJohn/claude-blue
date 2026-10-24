---
name: defensive-okta-security
description: "Securing and monitoring Okta Workforce Identity: admin hardening (phishing-resistant MFA for admins, admin session binding to network, least-privilege custom admin roles, super admin minimization), authentication policies and FastPass, ThreatInsight and network zones, help-desk reset protections, OAuth/API token governance, System Log monitoring with verified eventType names (app.oauth2.*, credential.register, device.*, policy changes), lessons from Okta's 2023 support-system breach (HAR files with session tokens), patching on-prem/agent components (Access Gateway, RADIUS agent, Credential Provider, Hyperdrive, Privileged Access client) given frequent 2026 advisories, and detection of ShinyHunters-style SSO abuse. Use when hardening or investigating an Okta tenant."
---

# Okta Security

Okta is the front door to every SaaS app it federates — compromise of an Okta admin or a user session cascades across the business. Harden admin access, enforce phishing-resistant authentication, govern tokens, and stream the System Log to your SIEM.

## Quick Workflow

1. Lock down admins: few super admins, custom roles, phishing-resistant MFA, session binding
2. Authentication policies: phishing-resistant (FastPass/FIDO2) for sensitive apps; block weak factors
3. Protect enrollment/recovery and help desk flows
4. Govern API tokens, OAuth apps, and integrations
5. Stream System Log to SIEM; deploy detections (§5)
6. Patch on-prem/agent components

---

## 1. Admin Hardening

| Control | Detail |
|---|---|
| Super admins | Minimal (2–3 named + break-glass); use custom admin roles with resource sets for daily work |
| Admin MFA | Phishing-resistant (FIDO2 / FastPass with strong binding) via admin console app sign-on policy |
| Session binding | Re-authenticate admin sessions when network/ASN changes (Okta's post-2023 control; check current setting under Security → General) |
| Session lifetime | Short admin session lifetime; idle timeout |
| Admin from managed devices | Device assurance policies |
| Notifications | Alert on admin role assignment, new API tokens, policy changes |

---

## 2. Authentication & Policies

- Global session policy + app authentication policies: require phishing-resistant factor for admin console, email, VPN/ZTNA, finance and HR apps
- Disable SMS/voice where possible; restrict email as a factor
- ThreatInsight in "log and enforce" for credential-stuffing/password-spray protection; network zones (block anonymizers/Tor where business allows)
- Device assurance (OS version, disk encryption, EDR) for sensitive apps
- FastPass: phishing resistance only with strong binding (loopback/Apple Credential SSO extension); weak enrollment paths remain a gap — require strong factors for enrollment

---

## 3. Recovery & Help Desk

Help-desk-driven MFA resets are the main 2023–2026 abuse path (Scattered Spider, ShinyHunters clusters vishing users/help desks, then enrolling their own MFA). Require verified identity (callback to number on file, manager approval, ID verification for admins), disallow help-desk resets for admins without a second approver, and alert on factor reset + new enrollment.

---

## 4. Tokens, Apps, Integrations

- API tokens: inherit creator's permissions — create under least-privilege service admins, network-restricted, rotated; prefer OAuth service apps with scoped grants
- OAuth app governance: review `app.oauth2.client.privilege.grant` and admin consent events; remove unused integrations
- Third-party integrations (SIEM, HR, provisioning) are high-value — monitor their token usage
- **Don't upload unsanitized HAR files** to any vendor support case — Okta's 2023 support-system breach exposed HAR files containing live session tokens used to hijack customer sessions (5 customers affected; root cause: a service account credential saved in an employee's personal Google profile on a managed laptop)

---

## 5. System Log Monitoring

Stream via Okta Log Streaming (e.g., to Splunk/AWS EventBridge) or the System Log API (`GET /api/v1/logs?filter=eventType eq "<type>"`). Verified eventType examples:

| eventType | Use |
|---|---|
| `app.oauth2.token.detect_reuse`, `app.oauth2.as.token.detect_reuse` | Refresh token reuse (theft) |
| `app.oauth2.token.grant` (+ `.access_token`, `.refresh_token`) | Token issuance baselines |
| `app.oauth2.client.privilege.grant` / `.revoke` | Admin roles granted to OAuth clients |
| `app.oauth2.admin.consent.grant` | Admin consent to OAuth scopes |
| `app.oauth2.client.read_client_secret` | Client secret viewed |
| `credential.register` / `credential.revoke` | Credential lifecycle |
| `application.policy.sign_on.update`, `.rule.create`, `.rule.delete` | App sign-on policy tampering |
| `device.platform_sso.enrollment.create`, `device.lifecycle.*` | Device enrollment changes |

Also monitor (names per Okta event-type catalog): user MFA factor enrollment/reset, admin privilege grants, session start from new ASN/country, ThreatInsight detections, policy and network zone changes.

```spl
index=okta sourcetype=OktaIM2:log eventType IN ("app.oauth2.token.detect_reuse","app.oauth2.as.token.detect_reuse","app.oauth2.client.privilege.grant","application.policy.sign_on.rule.delete")
| table _time eventType actor.alternateId client.ipAddress outcome.result target{}.displayName
```

Detection ideas from 2025–2026 SSO-abuse campaigns: factor enrollment shortly after a help-desk interaction, sign-ins from commercial VPN/residential proxies, deletion of "Security method enrolled" notification emails, then bulk downloads in downstream SaaS (SharePoint, Salesforce, DocuSign).

---

## 6. Patch On-Prem / Agent Components

Okta's 2026 advisories are mostly for components **running in your network**: Okta Access Gateway (multiple CVEs Sept–Oct 2026), RADIUS Agent, Credential Provider for Windows, Okta Verify for Windows, Hyperdrive agent, Okta Privileged Access client, AD/LDAP agents, Auth0 SDKs. Inventory them and patch per trust.okta.com/security-advisories.

---

## Engagement Cheatsheet

```text
admins: few super admins, custom roles, phishing-resistant MFA, network-bound sessions → policies: FastPass(strong binding)/FIDO2 for sensitive apps, ThreatInsight enforce, device assurance
→ verified help-desk resets + alert on new factor → API tokens/OAuth governance, sanitize HARs → System Log streaming + detections (token reuse, privilege grants, policy deletes, enroll→bulk download)
→ patch OAG/RADIUS/Credential Provider/agents
```

---

## Key References

- Okta security root-cause report for the 2023 support system incident (sec.okta.com); Okta security advisories (trust.okta.com); Okta event types reference (developer.okta.com)
- Related: `defensive-phishing-resistant-mfa`, `defensive-threat-hunting`, `defensive-saas-security`, `defensive-security-awareness`
