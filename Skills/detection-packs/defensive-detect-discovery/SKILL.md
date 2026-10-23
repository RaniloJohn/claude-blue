---
name: defensive-detect-discovery
description: "Detection pack for MITRE ATT&CK Discovery (TA0007): account, group, and domain trust discovery (net, nltest, dsquery, AdFind, BloodHound/SharpHound collection, LDAP recon), system and network configuration discovery (whoami, ipconfig, systeminfo, arp, route), remote system discovery and internal port/network scanning, permission groups, software and security software discovery, process and service enumeration, file and share discovery, cloud infrastructure and service discovery (AWS/Azure/GCP enumeration APIs), container and Kubernetes discovery, and Linux/macOS recon commands. Burst and sequence detections, honeytokens, FPs. Use when building discovery detections."
---

# Detection Pack — Discovery (TA0007)

Single discovery commands are noise; **bursts** of them from one process tree, one account, or one host are signal. Detect clusters, rare tools, and touches on honey objects.

## Quick Workflow

1. Collect process creation, LDAP queries (1644 / MDI / EDR LDAP telemetry), firewall/NDR internal connections, cloud API logs
2. Build burst detection: N distinct recon commands in T minutes per host/user/parent
3. Detect high-fidelity tooling (AdFind, SharpHound, network scanners)
4. Plant honeytokens (honey users, honey SPNs, honey shares) — any touch alerts

---

## 1. Recon Command Burst

```spl
index=sysmon EventCode=1
  process_name IN ("whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe","arp.exe","route.exe","netstat.exe","quser.exe","qwinsta.exe","tasklist.exe","sc.exe","dsquery.exe","nslookup.exe","klist.exe","cmdkey.exe","wmic.exe","hostname.exe","setspn.exe")
| bin _time span=10m
| stats dc(process_name) as distinct values(CommandLine) as cmds by host user ParentImage _time
| where distinct >= 5
```

```kql
DeviceProcessEvents
| where FileName in~ ("whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe","arp.exe","netstat.exe","quser.exe","tasklist.exe","dsquery.exe","nslookup.exe","klist.exe","setspn.exe")
| summarize Distinct = dcount(FileName), Cmds = make_set(ProcessCommandLine, 20) by DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where Distinct >= 5
```

High-signal individual commands:

| Command | Why |
|---|---|
| `nltest /domain_trusts`, `/dclist:` | Trust/DC mapping |
| `net group "domain admins" /domain`, `"enterprise admins"` | Privileged group enumeration |
| `whoami /all` or `/priv` from service accounts or web server processes | Post-exploitation |
| `setspn -T * -Q */*` | SPN enumeration (pre-Kerberoast) |
| `dsquery * -filter`, `Get-ADUser -Filter *` from workstations | Bulk directory reads |

---

## 2. AD Reconnaissance Tooling

| Tool | Signal |
|---|---|
| AdFind | `OriginalFileName=AdFind.exe`; args `-f objectcategory=`, `-gcb`, `trustdmp` |
| SharpHound/BloodHound | LDAP burst (thousands of queries), SMB session enumeration (`NetSessionEnum`/`NetWkstaUserEnum`) to many hosts, ZIP of JSON files written |
| PowerView | 4104 `Get-DomainUser`, `Get-NetComputer`, `Find-LocalAdminAccess`, `Invoke-ShareFinder` |
| ldapsearch / ldapdomaindump / NetExec | LDAP from Linux hosts or non-domain machines |

Domain controller LDAP visibility: enable **Field Engineering diagnostic logging** (`15 Field Engineering = 5`) + thresholds to get 1644 expensive/inefficient queries, or use Defender for Identity / EDR LDAP events.

```kql
IdentityQueryEvents
| where QueryType == "LdapSearch" or ActionType has "LDAP"
| summarize Queries = count(), Targets = dcount(QueryTarget) by DeviceName, AccountName, bin(Timestamp, 15m)
| where Queries > 500
```

---

## 3. Network Discovery (T1046, T1018)

| Signal | Source |
|---|---|
| One host connecting to many internal IPs on same port (horizontal scan) | Zeek `conn.log`, firewall, NetFlow |
| One host hitting many ports on one target (vertical scan) | Same |
| Many `REJ`/`S0` connection states | Zeek |
| ICMP sweeps | Firewall / NDR |
| SMB to every host (share enumeration) | Zeek `smb_mapping.log`, 5140 on servers |
| Scanner binaries (`nmap`, `masscan`, `Advanced IP Scanner`, `SoftPerfect netscan`, `Angry IP`) | Process creation, software inventory |

```spl
index=zeek sourcetype=zeek_conn local_orig=T local_resp=T
| bin _time span=5m
| stats dc(id.resp_h) as targets dc(id.resp_p) as ports count(eval(conn_state IN ("S0","REJ","RSTOS0"))) as failed by id.orig_h _time
| where targets > 50 OR ports > 100
```

---

## 4. Security Software & System Discovery

- `tasklist /svc`, `Get-Process` filtered on EDR names; `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct`; registry reads of `HKLM\SOFTWARE\Microsoft\Windows Defender`
- `fltmc` (filter driver listing), `sc query` for EDR service names
- Linux: `ps aux | grep -i falcon`, `systemctl list-units | grep -i` for agents; `cat /etc/os-release`, `uname -a`, `id`, `sudo -l`, `cat /etc/passwd`, `find / -perm -4000`
- macOS: `system_profiler`, `sw_vers`, `dscl . list /Users`, `security list-keychains`

---

## 5. Cloud & Kubernetes Discovery (T1580, T1526, T1613)

| Platform | Signal |
|---|---|
| AWS | Burst of `List*`/`Describe*`/`Get*` across services by one principal; `GetCallerIdentity` from new IP; `ListBuckets` + `GetBucketAcl`; errors `AccessDenied` spikes (enumeration with limited perms) |
| Azure | ARM `read` burst; Graph `users`/`groups`/`servicePrincipals` enumeration (AzureHound, ROADtools) from unusual clients |
| GCP | `*.list` bursts; `testIamPermissions` sweeps |
| Kubernetes | `get/list` on `secrets`, `pods`, `nodes`, `clusterroles` from service accounts; `SelfSubjectAccessReview`/`SelfSubjectRulesReview` (`kubectl auth can-i --list`) |

```sql
-- Athena over CloudTrail: enumeration burst
SELECT useridentity.arn, sourceipaddress, count(DISTINCT eventname) AS apis, count(*) AS calls,
       sum(CASE WHEN errorcode = 'AccessDenied' THEN 1 ELSE 0 END) AS denied
FROM cloudtrail_logs
WHERE eventtime > date_format(current_timestamp - interval '1' hour, '%Y-%m-%dT%H:%i:%sZ')
  AND (eventname LIKE 'List%' OR eventname LIKE 'Describe%' OR eventname LIKE 'Get%')
GROUP BY 1, 2
HAVING count(DISTINCT eventname) > 30 OR sum(CASE WHEN errorcode = 'AccessDenied' THEN 1 ELSE 0 END) > 20;
```

---

## 6. Honeytokens

| Token | Alert on |
|---|---|
| Honey user (realistic name, never used) | Any 4624/4625/4768/4771 or LDAP read of its attributes (SACL) |
| Honey SPN | 4769 for that SPN (Kerberoasting) |
| Honey admin in Domain Admins (disabled logon) | Enumeration via SACL read audit 4662 |
| Honey share / file (`passwords.xlsx`) | 5145 access, file open |
| Fake AWS key (canarytoken) | Any API use |

See `defensive-deception`.

---

## 7. False Positives

IT admin scripts, inventory agents (SCCM, Lansweeper), vulnerability scanners (Nessus/Qualys/Rapid7 — maintain scanner IP list), monitoring systems, CSPM tools doing cloud API enumeration, developers running `kubectl`. Allowlist by source host/account + schedule, never by command alone.

---

## Engagement Cheatsheet

```text
burst (≥5 recon cmds/10m per tree) → AdFind/SharpHound/PowerView → DC LDAP volume → internal scan (dc targets/ports, S0/REJ)
→ security-software discovery → cloud API enumeration + AccessDenied spikes → K8s can-i → honeytokens → allowlist scanners by source
```

---

## Key References

- MITRE ATT&CK TA0007; Microsoft Defender for Identity reconnaissance alerts
- Related: `defensive-detect-credential-access`, `defensive-ad-detection`, `defensive-deception`, `defensive-zeek`, `defensive-threat-hunting`
