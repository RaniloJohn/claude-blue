---
name: defensive-tool-ad-assessment
description: "Active Directory and Entra security assessment tools used defensively: BloodHound Community Edition 9.x (Docker deployment, initial admin credential handling, localhost binding, SharpHound 2.17 and AzureHound 3.1 collectors, OpenHound, Privilege Zones, Findings, attack path remediation, protecting collected data), PingCastle 4.x health check scoring and licensing, Semperis Purple Knight, Locksmith for AD CS misconfigurations, Defender for Identity posture, coordinating collections with the SOC (they trigger reconnaissance alerts), and turning findings into a remediation roadmap. Use when assessing AD/Entra attack paths or running AD security audits."
---

# AD Assessment Tools (BloodHound CE, PingCastle, Purple Knight, Locksmith)

Attackers map your AD in minutes; defenders should map it first and cut the paths. These tools are **dual-use** — collections look like attacker reconnaissance and the output is a privilege-escalation map. Versions observed 2026-10-23: BloodHound 9.8.0, SharpHound 2.17.0, AzureHound 3.1.1, PingCastle 4.0.x.

## Quick Workflow

1. Get approval; notify SOC with collection host, account, and time window
2. Collect from a controlled admin host (PAW/jump), store output encrypted
3. Analyze: Tier 0 definition, attack paths to Tier 0, high-risk findings
4. Remediate in waves (quick wins → structural fixes like tiering)
5. Re-collect monthly; track scores and path counts over time
6. Delete raw collection files after import

---

## 1. BloodHound CE

```bash
# Deployment (Docker, official CLI)
./bloodhound-cli install          # prints initial admin password — change at first login, store in vault
# Default UI on localhost; keep it bound to 127.0.0.1 or behind SSO/VPN — never internet-exposed
```

| Practice | Detail |
|---|---|
| Credentials | Change initial admin password; create named accounts; MFA where supported |
| Exposure | Localhost or restricted management network; TLS (v8.9.1+ dropped SHA-1 cipher suites when serving HTTPS directly) |
| Data | Graph = full map of privilege paths → Tier 0 sensitivity; encrypt disk; restrict access |
| Collectors | SharpHound 2.17.0 (`SharpHound.exe -c All,GPOLocalGroup --zipfilename corp.zip`), AzureHound 3.1.x (Entra/Azure), OpenHound (GitHub, Jamf, Okta); keep collectors current (BloodHound Enterprise will reject uploads from older AzureHound/OpenHound from Nov 2026) |
| Features | Privilege Zones (GA since 8.9.0) to define Tier 0/high-value assets, Findings table (GA 9.8.0), Protection Score (9.8.0), OpenGraph extensions |

Defensive queries/analysis:
- Shortest paths from Domain Users / Authenticated Users to Tier 0
- Kerberoastable users with paths to Tier 0
- Computers with unconstrained delegation
- Users with DCSync rights (non-DC)
- AD CS templates and CAs exploitable (ESC paths)
- Entra: paths from users/service principals to Global Admin, app owners with privileged roles

Remediate choke points: one ACL or group membership often removes thousands of paths.

---

## 2. PingCastle

```powershell
.\PingCastle.exe --healthcheck --server corp.local              # HTML + XML report, risk score
.\PingCastle.exe --healthcheck --server corp.local --level Full
```

Report areas: Stale Objects, Privileged Accounts, Trusts, Anomalies — each with points; lower is better. Track score monthly. Licensing (Netwrix): verify terms — free basic use within your own organization; auditing others/commercial use requires a license.

---

## 3. Purple Knight & Locksmith

| Tool | Use |
|---|---|
| Purple Knight (Semperis) | Free AD/Entra/Okta indicator-of-exposure assessment with category scores |
| Locksmith | PowerShell AD CS misconfiguration finder (ESC1–ESC8-class issues, auditing gaps) with fix guidance: `Invoke-Locksmith -Mode 1` (findings) / mode with remediation scripts — review scripts before running |
| Defender for Identity | Continuous identity posture assessments (unconstrained delegation, weak ciphers, clear-text LDAP, dormant admins) |

---

## 4. Coordination & Safety

- SharpHound session/local-admin collection hits many hosts over SMB/RPC and LDAP — expect MDI/EDR recon alerts; pre-register the collection
- Use a dedicated, monitored assessment account (read-only domain user is sufficient for most collection)
- Never run collectors from a domain controller or a user workstation
- Store zip/JSON outputs encrypted; delete after import; don't email reports
- Any remediation script from these tools: review, test in lab, change ticket

---

## 5. Remediation Roadmap (typical)

| Wave | Items |
|---|---|
| Quick wins (weeks) | Remove stale admins, fix dangerous ACLs on Tier 0 objects, disable unconstrained delegation on non-DCs, fix AD CS ESC1/ESC8, LAPS everywhere, remove SPNs from privileged users |
| Medium (months) | Tiered admin model with PAWs, gMSA for services, Protected Users for admins, LDAP signing/channel binding, NTLM restrictions, RC4 removal |
| Structural | Clean Tier 0 boundary (backup, EDR, sync servers), forest recovery plan (`defensive-ad-forest-recovery`) |

---

## Engagement Cheatsheet

```text
approval + SOC notice → collect from PAW with read-only account (SharpHound 2.17/AzureHound 3.1/OpenHound) → BloodHound CE on localhost, admin pw changed
→ Privilege Zones = Tier 0 → choke-point paths & Findings → PingCastle/Purple Knight scores → Locksmith for AD CS → encrypt + delete raw data → monthly re-collect
```

---

## Key References

- bloodhound.specterops.io (release notes, install, Privilege Zones); PingCastle (pingcastle.com / Netwrix); Semperis Purple Knight; Locksmith (GitHub: jakehildreth/Locksmith)
- Related: `defensive-ad-hardening`, `defensive-ad-detection`, `defensive-entra-id`
