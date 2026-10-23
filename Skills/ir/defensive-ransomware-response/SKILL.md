---
name: defensive-ransomware-response
description: "Ransomware incident response and preparedness: precursor detection (initial access brokers, RMM abuse, AD recon, credential dumping, backup deletion, security tool disabling), early-warning indicators (vssadmin/wbadmin/bcdedit, mass file renames, ransom note creation, ESXi encryption), immediate containment and segment isolation, backup protection, encryption scope assessment, data-theft/double-extortion assessment, recovery sequencing (identity first), decryptor checks, legal/regulatory and payment considerations, and hardening to prevent recurrence. Use during an active ransomware event, tabletop, or readiness review."
---

# Ransomware Response

Ransomware is the last stage of an intrusion that started days or weeks earlier. Response must stop encryption, protect backups and identity, determine data theft, and rebuild trust in the environment.

## Quick Workflow

1. Stop spread: isolate affected segments, disable compromised accounts, block lateral paths
2. Protect backups and identity infrastructure (DCs, backup servers, hypervisors)
3. Preserve evidence (memory from encrypting hosts if feasible, logs, ransom notes, samples)
4. Scope encryption and data theft
5. Decide recovery path (restore / rebuild / decryptor)
6. Recover identity first, then core services, then business apps
7. Harden and monitor for re-entry

---

## 1. Precursors (hunt these before encryption)

| Stage | Signals |
|---|---|
| Initial access | VPN/edge appliance exploitation (KEV), valid creds without MFA, phishing loaders |
| Remote tools | New RMM (AnyDesk, ScreenConnect, Atera, Splashtop) installs; RMM from unusual parents |
| Recon | AdFind, SharpHound/BloodHound, `nltest /domain_trusts`, `net group "domain admins"`, network scanners (Advanced IP Scanner, SoftPerfect) |
| Credential access | LSASS dumps, NTDS extraction, Kerberoasting |
| Lateral movement | PsExec, WMI, RDP spikes, GPO edits deploying scripts |
| Exfil | Rclone, MEGAsync, WinSCP, `curl`/`rclone` to cloud storage, large egress |
| Defense evasion | Defender disabled/exclusions, EDR uninstall attempts, BYOVD drivers |
| Pre-encryption | Backup deletion, VSS deletion, ESXi SSH enabled |

---

## 2. Imminent-Encryption Indicators

```text
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
wbadmin delete catalog -quiet
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures
wevtutil cl Security / System
```

- Mass file modifications/renames with new extension; high-entropy writes
- Ransom note files (`README*.txt`, `*.hta`) created across many directories
- ESXi: `esxcli vm process kill`, `vim-cmd vmsvc/power.off`, encryption of `.vmdk`, SSH enabled unexpectedly
- Group Policy changes deploying scheduled tasks/scripts domain-wide

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("delete shadows","shadowcopy delete","delete catalog","recoveryenabled no")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

---

## 3. Immediate Containment (first hour)

| Action | Notes |
|---|---|
| Isolate affected hosts/segments | EDR isolation; switch/VLAN; don't power off encrypting hosts unless no other option (memory may hold keys) |
| Disconnect backups | Take backup repositories offline / immutable mode; rotate backup admin creds |
| Block lateral protocols | SMB/RDP/WinRM between workstations; restrict admin paths |
| Disable compromised accounts | Especially domain admins and service accounts used by actor |
| Block C2 / exfil destinations | Firewall/proxy/DNS |
| Protect hypervisors | Disable SSH on ESXi, isolate management networks |
| Suspend scheduled tasks/GPOs deploying the payload | Edit/unlink malicious GPO |
| Out-of-band comms | Assume email/Teams may be monitored |

---

## 4. Scope Assessment

| Question | Evidence |
|---|---|
| Which systems encrypted? | Ransom notes, file extensions, EDR alerts |
| Which accounts used? | 4624/4672 on affected hosts, GPO change logs |
| Patient zero & initial access | Earliest malicious activity |
| Data stolen? | Egress volume, rclone/MEGA logs, cloud storage logs, leak site monitoring |
| Backups intact? | Verify immutability, last good restore point, backup server compromise |
| Identity integrity | DC compromise? krbtgt? ADCS? Entra Connect? |

---

## 5. Recovery Sequencing

1. Clean, isolated recovery environment
2. Identity: restore/rebuild DCs (AD forest recovery if Tier 0 compromised); reset krbtgt twice; reset all privileged accounts; rotate service accounts; review ADCS
3. Security tooling: EDR, logging, SIEM working before broad restore
4. Core infrastructure: DNS, DHCP, file services
5. Business-critical apps by priority
6. Scan restored data and hosts before reconnecting
7. Monitor for re-entry ≥30 days

Decryptors: check No More Ransom (nomoreransom.org) and vendor resources for the identified family before considering any other option.

---

## 6. Decisions Requiring Legal/Executive Input

- Ransom payment (sanctions screening — e.g. OFAC; legality varies; insurance terms)
- Law enforcement engagement
- Regulatory notifications (GDPR 72 h, NIS2 24/72 h, SEC 8-K Item 1.05, sector regulators, PH NPC 72 h)
- Customer/partner notification on data theft

SOC/IR provides facts and timelines; does not negotiate unless designated.

---

## 7. Hardening After

```text
[ ] MFA on all remote access and admin interfaces; phishing-resistant for admins
[ ] Patch/mitigate edge appliances (KEV-driven, exposure-first)
[ ] Tiered admin model; LAPS; remove local admin
[ ] Immutable/offline backups; tested restores; separate backup credentials
[ ] Block RMM tools not approved; application control
[ ] EDR tamper protection; ASR rules
[ ] Disable SMBv1; restrict SMB/RDP east-west
[ ] Detections for every precursor observed
```

---

## Engagement Cheatsheet

```text
Isolate segments → protect backups + DCs + hypervisors → disable actor accounts
→ preserve → scope encryption + exfil → identity-first recovery → monitor → harden
```

---

## Key References

- CISA #StopRansomware Guide (CISA/MS-ISAC)
- No More Ransom — https://www.nomoreransom.org
- Microsoft: Active Directory Forest Recovery Guide
- Related: `defensive-incident-response`, `defensive-ad-hardening`, `defensive-hunt-windows`
