---
name: defensive-phishing-resistant-mfa
description: "Phishing-resistant MFA strategy and rollout: what qualifies (FIDO2/WebAuthn passkeys, platform authenticators like Windows Hello for Business, PKI smart cards/CBA) and what does not (SMS, voice, OTP, push even with number matching), NIST SP 800-63-4 (final July 31, 2025) AAL2/AAL3 requirements and synced vs device-bound passkeys, Microsoft Entra authentication strengths and passkey profiles, Microsoft mandatory MFA for Azure phases, Okta FastPass binding caveats, AiTM/Evilginx relay attacks, secure registration and recovery (Temporary Access Pass, help-desk verification), token theft after sign-in, rollout sequencing, and monitoring. Use when planning or auditing MFA strength."
---

# Phishing-Resistant MFA

Adversary-in-the-middle phishing kits relay passwords, OTPs, and push approvals in real time — any MFA a user can be tricked into typing or approving is phishable. Phishing-resistant methods bind authentication to the **real site origin** or a **client-authenticated TLS channel**.

## Quick Workflow

1. Classify current methods (§1)
2. Prioritize: admins, help desk, email/SSO, remote access, finance, executives (CISA ordering)
3. Deploy FIDO2/passkeys, Windows Hello for Business, or CBA; enforce with policy (authentication strengths)
4. Secure registration and recovery — the new weakest link
5. Protect sessions after sign-in (token theft); monitor

---

## 1. What Counts

| Method | Phishing-resistant? |
|---|---|
| FIDO2 security keys / passkeys (WebAuthn) | **Yes** — verifier-name (origin) binding |
| Windows Hello for Business / platform credentials | **Yes** |
| PKI smart card / PIV/CAC / Entra certificate-based auth (CBA) | **Yes** — channel binding |
| Okta FastPass | Yes **when** strong binding paths are used (loopback server / Apple Credential SSO extension) and policy requires phishing resistance |
| Push with number matching | **No** (resists push bombing only — CISA) |
| TOTP/HOTP apps or tokens | No |
| SMS / voice | No (also SIM-swap) |
| Email codes | No |

---

## 2. NIST SP 800-63-4 (final, July 31, 2025)

| Level | Requirement |
|---|---|
| AAL2 | Verifiers **must offer at least one phishing-resistant option**; federal agencies must require phishing-resistant authentication for staff/contractors/partners |
| AAL3 | Phishing resistance **plus** cryptographic authenticator with a **non-exportable** private key |
| Synced passkeys | Allowed at AAL1/AAL2 (exportable keys); **not** permitted at AAL3 |

SP 800-63-4 supersedes 800-63-3 (2020) — update policy citations to 63B-4.

---

## 3. Microsoft Entra

| Feature | Notes |
|---|---|
| Authentication strengths (Entra ID P1) | Built-in: Multifactor, Passwordless MFA, **Phishing-resistant MFA** (FIDO2, Windows Hello for Business/platform credential, CBA multifactor). Use in Conditional Access grant; can't combine "Require MFA" and "Require authentication strength" in one policy |
| Passkeys (FIDO2) | Device-bound (security keys, Microsoft Authenticator) vs synced (iCloud Keychain, Google Password Manager, 1Password, Bitwarden). **Synced passkeys don't support attestation**; without enforced attestation Entra can't guarantee whether a passkey is synced or device-bound (AAGUID allowlists become guidance only) |
| Passkey profiles | Opt-in (can't revert), up to 3 profiles incl. Default; attestation enforced only at registration |
| Mandatory MFA for Azure (public cloud) | Phase 1 (Azure portal, Entra and Intune admin centers) from Oct 2024; M365 admin center Feb 2025; Phase 2 (Azure CLI, PowerShell, mobile app, IaC, REST control plane — create/update/delete) from Oct 1, 2025; postponement of Phase 2 allowed only until July 1, 2026 — now expected to be enforced. Applies to all users incl. break-glass and guests; workload identities generally out of scope; ROPC flows incompatible |
| Temporary Access Pass | Time-limited bootstrap for passkey registration / recovery |

Conditional Access baseline: admins → phishing-resistant strength; all users → phishing-resistant for high-risk apps (email, VPN/ZTNA, finance), MFA strength elsewhere during transition; block legacy auth; block device code flow except approved scenarios.

---

## 4. Registration & Recovery (where attackers go next)

- Attackers now vish help desks or phish users to **enroll their own MFA device** (2025–2026 ShinyHunters-linked campaigns) — require phishing-resistant MFA (or in-person/verified identity) to register new methods
- Help-desk resets: callback to number on file, manager approval, video verification with ID for privileged users; never accept caller-supplied numbers
- Alert on new authenticator registration followed by risky activity (mass downloads, mailbox rules, OAuth grants)
- Issue ≥ 2 keys per admin (primary + backup); define lost-key procedure with TAP

```kql
AuditLogs
| where OperationName in ("User registered security info","Admin registered security info","User registered all required security info")
| extend UPN = tostring(TargetResources[0].userPrincipalName), IP = tostring(InitiatedBy.user.ipAddress)
| join kind=inner (SigninLogs | where RiskLevelDuringSignIn in ("medium","high") | project UserPrincipalName, RiskTime = TimeGenerated) on $left.UPN == $right.UserPrincipalName
| where abs(datetime_diff('hour', TimeGenerated, RiskTime)) < 24
```

---

## 5. After Sign-In: Session Theft

Phishing-resistant MFA stops credential relay, not **token/cookie theft** by infostealers on the endpoint. Pair with: EDR, Entra token protection / Continuous Access Evaluation, short session lifetimes for sensitive apps, compliant-device requirements, and revoking sessions on infostealer detection (`defensive-threat-hunting`).

---

## 6. Rollout Plan

| Phase | Scope |
|---|---|
| 1 | Global/privileged admins, break-glass (FIDO2 keys), help desk staff |
| 2 | IT, finance, executives and assistants, developers with prod access |
| 3 | All employees for email/SSO/remote access (passkeys in Authenticator or platform, WHfB) |
| 4 | Remove SMS/voice; restrict OTP/push to exception groups with expiry |
| 5 | Partners/guests (cross-tenant trust for MFA) and customers (passkeys) |

Metrics: % users with a phishing-resistant method registered, % sign-ins satisfied with phishing-resistant strength, admin coverage (target 100%), number of exceptions.

---

## Engagement Cheatsheet

```text
classify methods (FIDO2/passkeys/WHfB/CBA = yes; push/OTP/SMS = no) → NIST 800-63-4 (AAL2 must offer; AAL3 non-exportable, no synced)
→ Entra auth strengths + passkey profiles (attestation for device-bound) + mandatory Azure MFA → secure registration/recovery (TAP, verified help desk, alert new methods)
→ token theft defenses → phased rollout → remove SMS/voice → metrics
```

---

## Key References

- NIST SP 800-63-4 / 63B-4 (July 31, 2025); CISA "Implementing Phishing-Resistant MFA" fact sheet
- Microsoft Learn: authentication strengths, passkeys (FIDO2), mandatory MFA for Azure; Okta FastPass documentation
- Related: `defensive-entra-id`, `defensive-pam`, `defensive-okta-security`, `defensive-threat-hunting`, `defensive-security-awareness`
