---
name: defensive-pam
description: "Privileged access management: privileged account inventory, tiering and PAWs, vaulting and credential rotation (CyberArk, BeyondTrust, Delinea and others), just-in-time access with Microsoft Entra PIM (eligible vs active, approval, MFA on activation, access reviews, PIM for Groups), session recording and brokering, Windows LAPS (native since April 2023, Entra or AD backup, encryption, DSRM backup; legacy LAPS deprecated and legacy emulation stores cleartext), service accounts (gMSA vs Windows Server 2025 dMSA and the BadSuccessor technique, CVE-2025-53779), break-glass/emergency access accounts per Microsoft guidance, detection of privileged activity, and PAM program metrics. Use when designing or reviewing privileged access controls."
---

# Privileged Access Management (PAM)

Privileged credentials turn a single compromise into a full breach. PAM reduces **how many** privileged identities exist, **how long** privilege lasts, **where** it can be used, and **how visible** its use is.

## Quick Workflow

1. Inventory privileged identities: humans, service accounts, local admins, cloud roles, SaaS admins, secrets in pipelines
2. Remove standing privilege: JIT (PIM/PAM), separate admin accounts, tiering + PAWs
3. Vault and rotate: local admin (Windows LAPS), shared/service credentials (PAM vault), secrets (vault)
4. Broker and record privileged sessions
5. Monitor privileged activity; review access quarterly

---

## 1. Inventory

| Type | Sources |
|---|---|
| AD privileged groups | Domain/Enterprise/Schema Admins, Administrators, Account/Server/Backup/Print Operators, DnsAdmins, GPO creators, AD CS admins, Entra Connect accounts |
| Entra/cloud roles | Global Admin, Privileged Role Admin, Exchange/SharePoint admins; AWS admin roles; GCP Owner/Editor |
| Local admins | Endpoint/servers (should be LAPS-managed only) |
| Service accounts | SPNs, scheduled tasks, IIS app pools, SQL services |
| Infrastructure | Hypervisors (ESXi/vCenter), backup consoles, network devices, firewalls |
| SaaS admins | Okta, Salesforce, GitHub org owners, CI/CD admins |
| Machine secrets | API keys, tokens in pipelines (`defensive-secrets-management`) |

Attack-path tools (BloodHound CE, `defensive-tool-ad-assessment`) reveal hidden privilege via ACLs and delegation.

---

## 2. Just-in-Time with Entra PIM

| Setting | Recommendation |
|---|---|
| Assignment type | **Eligible** for admin roles; permanent active only for break-glass |
| Activation | MFA (authentication strength: phishing-resistant), justification, ticket number, approval for Tier 0 roles |
| Duration | 1–4 h for highly privileged roles |
| Notifications | Alert security team on Global Admin / Privileged Role Admin activation |
| Access reviews | Quarterly for privileged roles and PIM for Groups |
| Scope | Entra roles, Azure resource roles, PIM for Groups (which can govern app/SaaS access) |

Licensing: Entra ID P2 / ID Governance (confirm current SKU on Microsoft licensing pages).

---

## 3. Vaulting, Brokering, Recording

Commercial PAM platforms (CyberArk — now part of Palo Alto Networks since early 2026 and still sold as a platform; BeyondTrust; Delinea; others) and open-source/lighter options (HashiCorp Vault for secrets, Teleport/Boundary for session brokering) provide:

- Credential vaulting with automatic rotation after checkout
- Session brokering (admins never see the password), recording, keystroke logging
- Approval workflows and break-glass checkout
- Discovery of privileged accounts across systems

Harden the PAM platform itself as Tier 0 (MFA, isolated network, monitored, patched, backed up).

---

## 4. Windows LAPS

| Fact | Detail |
|---|---|
| Availability | Built into Windows since the April 11, 2023 updates (Windows 10/11, Server 2019/2022); native in Windows 11 23H2+ and Server 2025 |
| Storage | Entra ID **or** AD (not both for hybrid-joined devices); AD supports password **encryption** and **history**; DSRM password backup on DCs |
| Legacy LAPS (MSI) | Deprecated for Windows 11 23H2+ (newer OSes block installing it); **legacy emulation mode stores passwords in cleartext in AD** — migrate to native mode with encryption |
| Automatic account management | Windows 11 24H2+ / Server 2025+ |
| Windows 10 | End of support Oct 14, 2025 — LAPS on Windows 10 only meaningful with ESU |

```powershell
Update-LapsADSchema                                        # once per forest
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"
Get-LapsADPassword -Identity WS-042 -AsPlainText           # authorized retrieval (audited)
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=corp,DC=local"   # who can read passwords
```

Policy: password length ≥ 15–20, complexity, rotation ≤ 30 days, post-authentication reset (rotate after use), encryption enabled, readers limited to a dedicated group.

---

## 5. Service Accounts

| Type | Notes |
|---|---|
| Standard user accounts as services | Avoid; if unavoidable: long random passwords (25+), vaulted, AES-only, no interactive logon, monitored, no SPN on privileged accounts (Kerberoasting) |
| gMSA | Automatic password rotation; but password is retrievable by authorized principals and not machine-bound |
| dMSA (Windows Server 2025) | New type that supersedes a legacy service account; secrets bound to machine identity (pair with Credential Guard); migration via `Start-ADServiceAccountMigration`/`Complete-ADServiceAccountMigration`; cannot migrate MSA/gMSA → dMSA; unconstrained delegation stops working after migration |

**BadSuccessor (dMSA abuse):** reported by Akamai (published May 21, 2025). Any domain with ≥ 1 Windows Server 2025 DC is exposed if non-admins can create dMSAs (`Create msDS-DelegatedManagedServiceAccount` or `Create all child objects` on any OU) or write to an existing dMSA — Akamai found such rights in 91% of surveyed environments. Microsoft fixed a key part as **CVE-2025-53779** (August 12, 2025), but Akamai notes the technique remains relevant in some scenarios. Actions:
- Patch DCs; audit and remove OU create-child rights for non-admins
- Enable directory service object-change auditing; alert on **5137** (dMSA object created), **5136** (`msDS-ManagedAccountPrecededByLink` modified), **Directory Service 2946** (TGT with dMSA key package issued)

---

## 6. Break-Glass Accounts (Microsoft guidance)

- ≥ 2 cloud-only `*.onmicrosoft.com` accounts with Global Administrator, **active permanent** in PIM
- Phishing-resistant method (FIDO2 passkey or CBA) **different** from regular admins' method; credentials split and stored securely
- Excluded from blocking Conditional Access policies (but still MFA — Microsoft mandatory MFA applies to them)
- **Alert on every sign-in** (Log Analytics alert, threshold > 0, highest severity)
- Validate usability at least every 90 days

```kql
SigninLogs
| where UserPrincipalName in~ ("breakglass1@contoso.onmicrosoft.com","breakglass2@contoso.onmicrosoft.com")
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName, ConditionalAccessStatus
```

---

## 7. Monitoring

PIM activations outside change windows; additions to privileged groups (4728/4732/4756; Entra "Add member to role"); LAPS password reads (event 4662 on the LAPS attribute or Windows LAPS audit events); vault checkouts without tickets; privileged sign-ins from non-PAW devices; service accounts logging on interactively (4624 type 2/10).

---

## 8. Metrics

Standing privileged accounts (target: break-glass only), % privileged roles eligible-only, % admin sign-ins from PAWs, % local admin passwords LAPS-managed, service accounts vaulted/rotated, access review completion.

---

## Engagement Cheatsheet

```text
inventory (AD groups, cloud/SaaS roles, local admins, service accounts, infra, secrets) → JIT via PIM (eligible, phishing-resistant MFA, approval, short duration)
→ vault + broker + record → Windows LAPS native w/ encryption (kill legacy emulation) → gMSA/dMSA + BadSuccessor fix (patch, OU rights, 5136/5137/2946)
→ 2 break-glass (FIDO2/CBA, alert every sign-in, test 90d) → monitor + quarterly reviews
```

---

## Key References

- Microsoft Learn: Windows LAPS overview; Entra PIM; Emergency access accounts; dMSA overview
- Akamai "BadSuccessor" research (May 2025, updated Aug 2025); CVE-2025-53779
- Related: `defensive-ad-hardening`, `defensive-entra-id`, `defensive-phishing-resistant-mfa`, `defensive-tool-ad-assessment`, `defensive-secrets-management`
