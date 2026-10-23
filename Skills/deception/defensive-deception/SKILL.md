---
name: defensive-deception
description: "Deception engineering for high-fidelity detection: honeytokens (fake credentials, AWS/API canary keys, honey documents, DNS and URL canaries, database honey records), Canarytokens, honey accounts and SPNs in Active Directory, honey AD CS templates, decoy shares and files, honeypots (OpenCanary, T-Pot, Cowrie, Dionaea, Conpot), placement strategy along attack paths, alert routing, MITRE ENGAGE planning, legal/ethical considerations, and avoiding self-inflicted false positives. Use when designing deception or adding near-zero-false-positive tripwires."
---

# Deception

Deception produces alerts that legitimate users never trigger. Place believable decoys on the paths attackers take — credential stores, AD, file shares, cloud configs — and route every touch to on-call.

## Quick Workflow

1. Model likely attack paths (recon → creds → lateral → data)
2. Choose decoys per stage
3. Make them believable but unused
4. Ensure every interaction is logged and alerted
5. Document decoys so admins/scanners don't trip them
6. Review and rotate periodically

---

## 1. Decoy Types by Attack Stage

| Stage | Decoy | Alert source |
|---|---|---|
| Recon (network) | OpenCanary services (SMB, RDP, SSH, HTTP, MSSQL) on unused IPs | Any connection |
| Recon (AD) | Honey users/groups with attractive names; honey computer objects | Any auth (4624/4625/4768/4769) |
| Credential access | Fake creds in LSASS (`runas /netonly` decoy session), in scripts, browser stores, `~/.aws/credentials`, `.env` | Use of creds anywhere (AD logs, cloud trail) |
| Kerberoasting | Honey SPN on user account (strong password) | 4769 for that SPN |
| AS-REP roasting | Account with preauth disabled, never used | 4768 for it |
| AD CS abuse | Honey template appearing ESC1-vulnerable, enrollment audited | 4886/4887 on template |
| Lateral movement | Decoy RDP/SMB hosts named like servers (`FS-FINANCE02`) | Any logon/connection |
| Collection | Honey documents (`passwords.xlsx`, `Q4-salaries.docx`) with beacon tokens | Document open callback |
| Cloud | Canary AWS keys, fake Azure SP secrets, decoy S3 bucket names | CloudTrail use / access logs |
| Exfil | Honey DB rows/emails (unique addresses) | Use in phishing/spam, external sightings |
| Web apps | Hidden admin endpoints, fake API keys in JS | WAF/app logs hits |

---

## 2. Canarytokens

Canarytokens (Thinkst; free hosted or self-hosted) types include: web bug URL, DNS, AWS API key, Azure login certificate, MS Word/Excel/PDF documents, Windows folder (`desktop.ini`), cloned website, SQL Server, QR code, credit card, Kubeconfig, WireGuard config, sensitive command (Windows), and more.

Placement examples:
- AWS key in a repo's old commit / config file on a jump host
- Word doc in `\\fileserver\Finance\Archive\`
- Kubeconfig on a developer laptop image
- DNS token as hostname in a fake inventory spreadsheet

---

## 3. Honeypots

| Tool | Purpose |
|---|---|
| OpenCanary | Lightweight multi-service internal honeypot; low interaction; syslog/webhook alerts |
| T-Pot | Multi-honeypot platform (internet-facing research) with ELK |
| Cowrie | SSH/Telnet medium-interaction (captures commands, downloads) |
| Dionaea | Malware capture (SMB, HTTP, FTP…) |
| Conpot | ICS/SCADA protocols (Modbus, S7, BACnet) |

OpenCanary config snippet:

```json
{
  "device.node_id": "fs-finance02",
  "smb.enabled": true,
  "rdp.enabled": true,
  "ssh.enabled": true,
  "ssh.port": 22,
  "logger": {
    "class": "PyLogger",
    "kwargs": { "handlers": { "syslog-unix": { "class": "logging.handlers.SysLogHandler", "address": ["10.10.1.30", 514] } } }
  }
}
```

Internal honeypots: never expose to internet; isolate so compromise can't pivot.

---

## 4. AD Honey Accounts

```powershell
New-ADUser -Name "svc_backup_legacy" -SamAccountName "svc_backup_legacy" -AccountPassword (Read-Host -AsSecureString) -Enabled $true -Description "Legacy backup service - do not delete"
Set-ADUser svc_backup_legacy -ServicePrincipalNames @{Add="MSSQLSvc/sql-legacy01.corp.local:1433"}
# Optional AS-REP decoy:
Set-ADAccountControl -Identity svc_backup_legacy -DoesNotRequirePreAuth $true
```

Use a long random password (it should never be cracked). Alert on any 4768/4769/4624/4625 referencing the account.

---

## 5. Operational Rules

```text
[ ] Every decoy in an inventory (owner, location, alert route)
[ ] Exclude decoys from vulnerability scanners / allowlist scanner IPs in alert logic (or let scanners alert and suppress by source)
[ ] Alerts go to on-call, severity High by default
[ ] Decoys look real (naming conventions, timestamps, content) but contain no real data
[ ] Periodic validation that alerts still fire
[ ] Legal review for internet-facing honeypots and data captured
```

---

## 6. Planning (MITRE ENGAGE)

ENGAGE structures adversary engagement: goals (expose, affect, elicit), approaches (collection, detection, prevention, direction, disruption, reassurance, motivation). For most SOCs, focus on **Expose → Detect** with low-interaction decoys.

---

## Engagement Cheatsheet

```text
attack paths → decoy per stage (honey SPN, AS-REP, fake creds, canary docs/keys, OpenCanary hosts)
→ logging + on-call alert → inventory + scanner exclusions → test → rotate
```

---

## Key References

- Thinkst Canarytokens — https://canarytokens.org ; OpenCanary
- MITRE ENGAGE — https://engage.mitre.org ; D3FEND Deceive tactic
- T-Pot (Deutsche Telekom Security), Cowrie
- Related: `defensive-ad-detection`, `defensive-secrets-management`
