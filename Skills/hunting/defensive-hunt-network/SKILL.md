---
name: defensive-hunt-network
description: "Network threat hunting for command-and-control, exfiltration, and lateral movement using Zeek, Suricata EVE, NetFlow/IPFIX, proxy, DNS resolver, and firewall logs. Covers beacon detection (interval, jitter, coefficient of variation, RITA), long connections, DNS tunneling and DGA (label length, entropy, NXDOMAIN rate, TXT volume), rare destinations/ASNs, newly registered domains, TLS fingerprinting (JA4/JA4S, JA3), self-signed and short-lived certificates, data volume asymmetry, cloud storage exfil, internal scanning, SMB/RDP/WinRM east-west anomalies, and DoH/proxy evasion."
---

# Network Hunting

Adversaries must communicate. Hunt the shape of communication — regularity, rarity, volume, and protocol misuse — rather than chasing IP reputation.

## Quick Workflow

1. Confirm visibility: egress sensor, DNS resolver logs, proxy, flow
2. Baseline top talkers, top destinations, normal ports per segment
3. Run beacon, long-connection, DNS, TLS, and volume hunts
4. Map each outlier to a host and process (EDR join)
5. Validate and escalate

---

## 1. Beaconing

Signals: many connections, regular interval, low jitter, similar byte sizes, long duration of activity.

```text
CV (coefficient of variation) = stdev(interval) / mean(interval)
CV < 0.1 with > 50 connections in 24 h → strong beacon candidate
```

```spl
index=zeek sourcetype=zeek_conn
| sort 0 _time | streamstats current=f last(_time) as prev by id.orig_h id.resp_h
| eval d=_time-prev | where isnotnull(d)
| stats count avg(d) as mean stdev(d) as sd avg(orig_bytes) as avg_out stdev(orig_bytes) as sd_out by id.orig_h id.resp_h id.resp_p
| eval cv=sd/mean, size_cv=sd_out/avg_out
| where count>50 AND cv<0.15 AND size_cv<0.2
| sort cv
```

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName, Key = strcat(DeviceName, "|", RemoteIP)
| sort by Key asc, Timestamp asc
| extend PrevKey = prev(Key), PrevTs = prev(Timestamp)
| where Key == PrevKey
| extend Delta = datetime_diff('second', Timestamp, PrevTs)
| summarize Count = count(), Mean = avg(Delta), SD = stdev(Delta) by DeviceName, RemoteIP, InitiatingProcessFileName
| extend CV = SD / Mean
| where Count > 50 and CV < 0.15
| sort by CV asc
```

Tools: **RITA** (Active Countermeasures) scores beacons, long connections, DNS tunneling from Zeek logs. Exclude known update/telemetry endpoints (Windows Update, AV, EDR, NTP).

---

## 2. Long Connections

```bash
zeek-cut id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes < conn.log \
  | awk '$5 > 14400' | sort -k5 -nr | head -50
```

Expect: VPN, RDP gateways, streaming, SSH admin sessions. Unexpected: workstation → rare IP on 443 for 8 h.

---

## 3. DNS

| Signal | Threshold idea |
|---|---|
| Label length | Longest label > 40 chars |
| Query entropy | Shannon entropy > 3.5 on subdomain |
| Unique subdomains per parent | > 200/day from one client |
| TXT / NULL volume | Unusual TXT per host |
| NXDOMAIN rate | > 50% for a host → DGA |
| Newly registered domains | < 30 days old |
| Direct-to-internet DNS | Hosts bypassing internal resolver (udp/53 to non-resolver) |
| DoH | TLS to known DoH endpoints from non-browser processes |

```bash
zeek-cut query qtype_name rcode_name id.orig_h < dns.log | awk '{split($1,a,"."); if (length(a[1])>40) print}' | head
zeek-cut id.orig_h query < dns.log | awk -F'\t' '{n=split($2,p,"."); if(n>=2) print $1, p[n-1]"."p[n]}' | sort | uniq -c | sort -nr | head
```

```kql
DnsEvents   // or ASimDnsActivityLogs / _Im_Dns
| where TimeGenerated > ago(1d)
| extend Sub = tostring(split(Name, ".")[0])
| where strlen(Sub) > 40
| summarize Q=count(), Uniq=dcount(Name) by ClientIP, Parent=strcat_array(array_slice(split(Name,"."),-2,-1),".")
| where Uniq > 100
```

---

## 4. TLS / Certificates

| Signal | Source |
|---|---|
| Self-signed / untrusted chain | Zeek `ssl.log validation_status`, `x509.log` |
| Cert validity < 30 days or default subjects (`CN=localhost`, empty O) | `x509.log` |
| Rare JA4 client fingerprint per process | Zeek JA4 package, Suricata `ja4.hash`, EDR |
| JA4S/JA4X matching known C2 frameworks | FoxIO JA4+ references (license-dependent) |
| No SNI on TLS to public IP | `ssl.log server_name` empty |
| SNI ≠ HTTP Host (domain fronting) | Proxy TLS inspection |

```bash
zeek-cut id.orig_h id.resp_h server_name validation_status < ssl.log | grep -i "self signed" | sort | uniq -c | sort -nr
```

---

## 5. Volume & Exfil

- Outbound/inbound byte ratio > 10 for a host-destination pair
- Uploads to cloud storage/file sharing (mega, transfer.sh, anonfiles clones, personal Drive/Dropbox) from servers
- Off-hours large uploads
- Rclone / MEGAcmd user agents; `rclone` process network events
- Compression tools before egress (7z, rar, `Compress-Archive`)

```spl
index=proxy action=allowed
| stats sum(bytes_out) as out sum(bytes_in) as in by src dest_host
| eval ratio=out/(in+1) | where out > 500000000 AND ratio > 10
```

---

## 6. Rare Destinations

```spl
index=firewall action=allowed dest_zone=external earliest=-30d
| stats dc(src) as clients count by dest_ip dest_asn
| where clients=1
```

Enrich: ASN (hosting/VPS vs ISP), domain age, geolocation vs business footprint.

---

## 7. East-West

| Behavior | Signal |
|---|---|
| Internal scanning | One source → many dest IPs or ports; Zeek `conn_state` S0/REJ bursts |
| SMB admin shares | Zeek `smb_files.log` ADMIN$/C$ writes; workstation → workstation SMB |
| RDP chaining | Workstation → workstation 3389 |
| WinRM | 5985/5986 from non-admin hosts |
| Kerberos anomalies | Zeek `kerberos.log` RC4 (`cipher rc4-hmac`) requests, AS-REQ without preauth |
| NTLM | Zeek `ntlm.log`; NTLM where Kerberos expected |
| LDAP enumeration | High-volume LDAP queries from workstation (BloodHound-like) |

```bash
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | awk '$4=="S0"||$4=="REJ"' | awk '{print $1}' | sort | uniq -c | sort -nr | head
```

---

## 8. Process Attribution

Network-only findings need a process. Join on host + time + 5-tuple using EDR network events (`DeviceNetworkEvents`, Sysmon 3, Elastic `network` events). Community ID enables joins across Zeek, Suricata, and supporting EDRs.

---

## Engagement Cheatsheet

```text
Baseline → beacons (CV) → long conns → DNS (length/entropy/NXDOMAIN) → TLS (self-signed/JA4/no SNI)
→ volume ratio → rare dest/ASN → east-west scans/SMB/RDP → attribute to process → validate
```

---

## Key References

- RITA — https://github.com/activecm/rita
- JA4+ — https://github.com/FoxIO-LLC/ja4
- Zeek log reference — https://docs.zeek.org
- Related: `defensive-zeek`, `defensive-pcap-analysis`, `defensive-firewall-analysis`, `defensive-threat-hunting`
