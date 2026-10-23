---
name: defensive-ad-detection
description: "Detecting Active Directory attacks with DC event logs, Microsoft Defender for Identity, and network telemetry: Kerberoasting, AS-REP roasting, password spraying, DCSync, DCShadow, golden/silver/diamond/sapphire tickets, pass-the-hash/ticket, overpass-the-hash, NTLM relay and coercion (PetitPotam, PrinterBug, DFSCoerce), shadow credentials, RBCD abuse, AD CS abuse (ESC1/ESC8 certificate requests, template changes), GPO abuse, AdminSDHolder and privileged group changes, BloodHound/LDAP reconnaissance, and honey accounts/honeytokens. Use when writing AD detections or investigating domain compromise."
---

# Active Directory Attack Detection

Most AD attacks leave traces on domain controllers — if DC auditing is configured. Collect 4662, 4768/4769/4771/4776, 5136, 4728/4732/4756, 4886/4887, and LDAP diagnostics from every DC.

## Quick Workflow

1. Verify DC audit policy and collection from **all** DCs
2. Deploy the detection set below (Sigma/SPL/KQL)
3. Deploy deception: honey SPN account, honey admin, AS-REP honey
4. Correlate with Defender for Identity (MDI) alerts if licensed
5. Tune for service accounts, scanners, and admin tooling

---

## 1. Detection Matrix

| Attack | ATT&CK | Primary signal |
|---|---|---|
| Kerberoasting | T1558.003 | 4769 RC4 (0x17), many SPNs per requester, non-`$` service |
| AS-REP roasting | T1558.004 | 4768 `PreAuthType=0` |
| Password spray | T1110.003 | 4771 0x18 / 4625 / 4776 failures across many users from one source |
| DCSync | T1003.006 | 4662 with replication GUIDs by non-DC; DRSUAPI traffic from non-DC IP |
| DCShadow | T1207 | New server object / SPN `GC/...` on non-DC computer (5136/5137); rogue DC registration |
| Golden ticket | T1558.001 | TGS without prior TGT on any DC; abnormal lifetimes; nonexistent users |
| Diamond/Sapphire ticket | T1558.001 | Modified legit TGT — PAC anomalies; MDI "suspicious Kerberos" |
| Silver ticket | T1558.002 | Service logons with no 4769 |
| Pass-the-hash | T1550.002 | 4624 type 3 NTLM spread; type 9 `seclogo` on source |
| Overpass-the-hash | T1550.002 | 4768 RC4 from user normally using AES |
| NTLM relay | T1557.001 | Machine account NTLM auth from IP not matching the machine |
| Coercion (PetitPotam/PrinterBug/DFSCoerce) | T1187 | 5145 to `lsarpc`/`efsrpc`/`spoolss`/`netdfs` pipes on DCs from workstations, followed by DC→attacker NTLM |
| Shadow credentials | T1556 | 5136 on `msDS-KeyCredentialLink`; 4768 PKINIT for that account |
| RBCD abuse | T1134 | 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity`; 4741 new computer account |
| AD CS ESC1 | T1649 | 4887 with SAN ≠ requester; certificate for privileged UPN requested by low-priv user |
| AD CS ESC8 | T1649 | 4886/4887 from web enrollment via NTLM for DC machine accounts |
| Template change | T1649 | 4899/4900 template updates; 5136 on `pKICertificateTemplate` |
| GPO abuse | T1484.001 | 5136 on `groupPolicyContainer` / `gPCFileSysPath`; SYSVOL file changes |
| Priv group change | T1098 | 4728/4732/4756 for privileged groups |
| AdminSDHolder | T1098 | 5136 on `CN=AdminSDHolder` |
| SID History injection | T1134.005 | 4765/4766 |
| LDAP recon (BloodHound-like) | T1087.002 | High-volume LDAP queries from workstation; DS event 1644 (expensive queries, needs field engineering logging) |

---

## 2. Queries

Kerberoasting (Splunk):

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as spns values(Service_Name) as services by Account_Name Client_Address
| where spns >= 3
```

AS-REP roastable request (KQL, SecurityEvent):

```kql
SecurityEvent
| where EventID == 4768
| extend PreAuth = extract(@"PreAuthType"">([^<]+)<", 1, EventData)
| where PreAuth == "0"
| project TimeGenerated, Computer, TargetUserName, IpAddress
```

DCSync (Sigma):

```yaml
title: DCSync By Non-DC Account
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_dc:
    SubjectUserName|endswith: '$'      # refine with explicit DC account list
  condition: selection and not filter_dc
level: critical
tags: [attack.credential-access, attack.t1003.006]
```

Refine `filter_dc` with an explicit list of DC machine accounts — any computer account ending `$` is too broad.

Shadow credentials / RBCD (KQL):

```kql
SecurityEvent
| where EventID == 5136
| extend Attr = extract(@"AttributeLDAPDisplayName"">([^<]+)<", 1, EventData)
| where Attr in ("msDS-KeyCredentialLink","msDS-AllowedToActOnBehalfOfOtherIdentity")
| project TimeGenerated, Computer, SubjectUserName, Attr, EventData
```

Privileged group change (Splunk):

```spl
index=wineventlog EventCode IN (4728,4732,4756)
  TargetUserName IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins","Account Operators","Backup Operators","DnsAdmins")
| table _time host SubjectUserName MemberName TargetUserName
```

---

## 3. Kerberos After RC4 Removal

With KDC defaults AES-only since 2026 (CVE-2026-20833 enforcement), any 0x17 ticket indicates an account explicitly configured for RC4 or an attempted downgrade. Inventory RC4-enabled accounts (`msDS-SupportedEncryptionTypes` includes 0x4) and alert on RC4 requests for all others. KDCSVC events 201–209 identify RC4 usage during transition.

---

## 4. Deception

| Decoy | Detection |
|---|---|
| Honey SPN user (attractive name, strong password, no use) | Any 4769 for its SPN = Kerberoasting |
| AS-REP honey account (`DONT_REQ_PREAUTH`) | Any 4768 for it |
| Honey admin (in fake admin-looking group, never used) | Any 4624/4625/4768 |
| Honey AD CS template (looks ESC1-vulnerable, enroll audited) | 4886/4887 on that template |
| Fake credentials in LSASS (honeytokens via scheduled task with `runas /netonly`) | Use of those creds anywhere |

---

## 5. Defender for Identity (MDI)

Sensors on DCs, AD CS, ADFS, Entra Connect. Key alert families: reconnaissance (LDAP, SAMR, DNS), credential access (Kerberoasting, AS-REP, DCSync, honeytoken), lateral movement (PtH, PtT, overpass, NTLM relay), domain dominance (golden ticket, DCShadow, skeleton key, malicious replication). Hunt in `IdentityLogonEvents`, `IdentityDirectoryEvents`, `IdentityQueryEvents`.

---

## 6. Tuning Notes

- Vulnerability scanners and backup software generate 4662/LDAP noise — allowlist by account + source IP
- Azure AD Connect sync account legitimately has replication rights — explicitly allowlist and monitor its logons
- Password spray thresholds: count distinct users per source per 10–30 min

---

## Engagement Cheatsheet

```text
DC audit + collection from all DCs → Kerberos (4768/4769/4771) → DCSync (4662) →
5136 attribute watches (KeyCredentialLink, RBCD, AdminSDHolder, GPO) → priv groups → AD CS (4886/4887/4899)
→ coercion pipes (5145) → honey accounts → MDI correlation
```

---

## Key References

- Microsoft: Audit Directory Service Changes; MDI security alert guide
- SpecterOps AD CS research; Sean Metcalf (adsecurity.org) detection notes
- Microsoft KB5073381 (Kerberos RC4)
- Related: `defensive-ad-hardening`, `defensive-windows-event-logs`, `defensive-deception`
