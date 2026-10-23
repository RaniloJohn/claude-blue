---
name: defensive-ad-hardening
description: "Active Directory and AD CS hardening: Enterprise Access Model tiering, PAWs, Tier 0 asset inventory (DCs, ADCS, ADFS, Entra Connect, backup, hypervisors), Protected Users, privileged group minimization, AdminSDHolder, ACL attack path reduction (BloodHound, PingCastle, Purple Knight), unconstrained/constrained/RBCD delegation cleanup, ms-DS-MachineAccountQuota, Kerberos AES-only after 2026 RC4 removal, gMSA, krbtgt rotation, LAPS, GPO permissions, trust SID filtering, and AD CS ESC1–ESC16 remediation with strong certificate mapping (KB5014754 full enforcement). Use for AD security assessments and post-compromise hardening."
---

# Active Directory Hardening

AD compromise is graph traversal: the attacker walks from any user to Tier 0 through sessions, ACLs, delegation, and certificates. Hardening = removing edges and protecting the nodes at the top.

## Quick Workflow

1. Inventory Tier 0 (everything that can control a DC)
2. Run attack-path and posture tools (BloodHound CE, PingCastle, Purple Knight, Locksmith)
3. Shrink privileged groups; enforce tiering and PAWs
4. Fix delegation, ACLs, AD CS templates
5. Enforce Kerberos/NTLM hardening
6. Monitor changes to all of the above

---

## 1. Tier 0 Inventory

Domain controllers; AD CS servers and CA keys; ADFS; Entra Connect / Cloud Sync servers; PAM/PIM systems; backup servers with DC backups; virtualization hosts running DCs; GPO-editing accounts; accounts with DCSync rights; MDI/EDR consoles with remote execution over DCs; SCCM if it manages DCs.

Treat compromise of any as domain compromise.

---

## 2. Tiering & Admin Model

| Tier | Assets | Rule |
|---|---|---|
| 0 | Identity control plane | Admin only from Tier 0 PAWs |
| 1 | Servers/apps | Tier 1 admins never log on to Tier 2 |
| 2 | Workstations/users | Helpdesk scoped; LAPS for local admin |

Enforce with GPO "Deny log on" rights (locally, via RDP, as batch/service) per tier; Authentication Policies and Silos for Tier 0 accounts.

---

## 3. Privileged Groups

- Minimize: Enterprise Admins, Domain Admins, Schema Admins (empty by default), Administrators, Account/Server/Backup/Print Operators, DnsAdmins, Group Policy Creator Owners, Cert Publishers
- Add privileged users to **Protected Users** (no NTLM, no delegation, no RC4/DES, 4 h TGT, no cached creds)
- Mark sensitive accounts "Account is sensitive and cannot be delegated"
- Review AdminSDHolder ACL and `adminCount=1` orphans
- Break-glass accounts: monitored, vaulted, tested

---

## 4. Attack Path Reduction

| Edge | Fix |
|---|---|
| GenericAll / GenericWrite / WriteDacl / WriteOwner on privileged objects | Remove non-admin ACEs |
| Sessions of DAs on workstations | Tiering; Restricted Admin/Remote Credential Guard |
| Unconstrained delegation (non-DC) | Remove; use constrained/RBCD where needed |
| Constrained delegation with protocol transition to sensitive SPNs | Review necessity |
| RBCD via writable `msDS-AllowedToActOnBehalfOfOtherIdentity` | Remove write access; set `ms-DS-MachineAccountQuota = 0` |
| `msDS-KeyCredentialLink` writable (shadow credentials) | Restrict write; monitor 5136 |
| GPO edit rights on GPOs linked to Tier 0 OUs | Restrict to Tier 0 |
| DCSync rights for non-DCs | Remove (`Replicating Directory Changes All`) |
| Kerberoastable privileged service accounts | gMSA; AES-only; 25+ char passwords; remove SPNs from user accounts where possible |
| AS-REP roastable accounts | Enable preauth (`DONT_REQ_PREAUTH` off) |

Tools: BloodHound CE (attack paths), PingCastle (health score), Purple Knight (IOEs), ADeleg (delegation), Locksmith (AD CS).

---

## 5. Kerberos & NTLM

- RC4 removal: Microsoft's CVE-2026-20833 rollout (KB5073381) made AES-SHA1 the default KDC encryption (April 2026) and removed the rollback (July 2026). Remaining RC4 use requires explicit `msDS-SupportedEncryptionTypes` — find and fix those accounts; reset passwords so AES keys exist
- krbtgt: rotate twice (interval ≥ max ticket lifetime + replication) on schedule (e.g., every 180 days) and after compromise; use Microsoft's `New-KrbtgtKeys.ps1`
- NTLM: audit (NTLM/Operational), restrict incoming/outgoing on DCs, disable NTLMv1 (BlockNTLMv1SSO enforced by default from Oct 2026); plan for NTLM-disabled-by-default in next Windows Server release
- LDAP signing + channel binding required; SMB signing required on DCs
- Disable Print Spooler on DCs (coercion)
- EPA on AD CS web enrollment / ADFS (relay)

---

## 6. AD CS (ESC1–ESC16)

| ESC | Misconfiguration | Remediation |
|---|---|---|
| ESC1 | Template: enrollee supplies subject + client-auth EKU + low-priv enroll + no approval | Remove `ENROLLEE_SUPPLIES_SUBJECT` or require manager approval; restrict enrollment |
| ESC2 | Any Purpose / no EKU template | Restrict EKUs and enrollment |
| ESC3 | Enrollment Agent template broadly enrollable | Restrict; enrollment agent restrictions on CA |
| ESC4 | Write rights on template object | Fix template ACLs |
| ESC5 | Write rights on PKI objects (CA computer, containers) | Treat as Tier 0; fix ACLs |
| ESC6 | CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`; restart CA |
| ESC7 | ManageCA / ManageCertificates to low-priv | Restrict CA permissions |
| ESC8 | NTLM relay to HTTP web enrollment | Disable web enrollment or require HTTPS + EPA; disable NTLM |
| ESC9 | Template `CT_FLAG_NO_SECURITY_EXTENSION` | Remove flag |
| ESC10 | Weak certificate mapping (registry) | Strong mapping enforced (KB5014754 full enforcement, compatibility mode removed Sept 2025) — verify no legacy overrides |
| ESC11 | RPC enrollment without packet privacy (`IF_ENFORCEENCRYPTICERTREQUEST` off) | Enable flag |
| ESC12 | CA private key on accessible hardware/HSM shell | Protect CA host and key |
| ESC13 | Issuance policy OID linked to privileged group | Remove OID group links or restrict enrollment |
| ESC14 | Weak explicit mappings in `altSecurityIdentities` | Use strong mapping formats; restrict write |
| ESC15 (EKUwu, CVE-2024-49019) | Schema v1 templates accept injected application policies | Patch (Nov 2024); duplicate v1 templates to v2; restrict enrollment |
| ESC16 | CA-wide removal of SID security extension | Remove `1.3.6.1.4.1.311.25.2` from CA `DisableExtensionList` |

```powershell
Install-Module Locksmith; Invoke-Locksmith -Mode 4       # identify + generate fixes
certipy find -u auditor@corp.local -p '<pw>' -dc-ip <dc> -vulnerable -stdout   # read-only audit
```

Enable CA auditing (`certutil -setreg CA\AuditFilter 127`) → 4886/4887/4899/4900.

---

## 7. Other Controls

- Windows LAPS for all local admin accounts (incl. DSRM where supported)
- gMSA for services; remove plaintext service passwords from GPP/scripts (`Get-GPPPassword` audit)
- Trusts: SID filtering on external/forest trusts; selective authentication
- Remove legacy: SMBv1, LM hashes (`NoLMHash`), reversible encryption
- Backup: offline/immutable DC backups; tested forest recovery plan
- Entra Connect server = Tier 0; restrict sync account permissions

---

## Engagement Cheatsheet

```text
Tier 0 inventory → BloodHound/PingCastle/Locksmith → shrink priv groups + Protected Users
→ tiering deny-logon GPOs → delegation/ACL/MAQ fixes → AD CS ESC fixes → AES-only, NTLM restrict,
LDAP/SMB signing → krbtgt rotation → monitor changes
```

---

## Key References

- Microsoft Enterprise Access Model; Securing privileged access
- SpecterOps "Certified Pre-Owned" (ESC1–8) and follow-up research (ESC9–16)
- Microsoft KB5014754 (strong certificate mapping); KB5073381 (Kerberos RC4)
- PingCastle, BloodHound CE, Locksmith (TrimarcJake)
- Related: `defensive-ad-detection`, `defensive-windows-hardening`, `defensive-incident-response`
