---
name: defensive-netflow-ndr
description: "Flow-based monitoring and network detection and response: NetFlow v5/v9, IPFIX, sFlow, J-Flow, cloud flow logs (AWS VPC Flow Logs, Azure VNet flow logs, GCP VPC Flow Logs), flow exporter configuration on Cisco and Huawei (NetStream), collectors (nfdump, SiLK, ntopng, pmacct, GoFlow2, ElastiFlow), flow analytics for scanning, beaconing, exfiltration, lateral movement and DDoS, NDR platforms (Zeek/Corelight, Vectra, ExtraHop, Darktrace, Cisco Secure Network Analytics), Community ID correlation, and baselining. Use when setting up flow monitoring, hunting with flow data, or evaluating NDR."
---

# NetFlow & NDR

Flow records (who talked to whom, when, how much, which ports) are cheap to collect everywhere and retain for months — ideal for scoping incidents and finding lateral movement and exfiltration even when payloads are encrypted.

## Quick Workflow

1. Enable flow export at routers, firewalls, core switches, and cloud VPCs
2. Collect centrally (nfdump/SiLK/ElastiFlow/SIEM) with ≥ 90 days retention
3. Enrich with asset inventory, GeoIP/ASN, threat intel
4. Run analytics (§4) and feed alerts to SIEM; pivot into PCAP/Zeek where available

---

## 1. Formats

| Format | Notes |
|---|---|
| NetFlow v5 | Fixed fields, IPv4 only — legacy |
| NetFlow v9 | Template-based, IPv6, extensible |
| IPFIX (RFC 7011) | IETF standard based on v9; variable-length fields |
| sFlow | Packet sampling + counters (common on switches); sampled — not every flow |
| Huawei NetStream | NetFlow v5/v9/IPFIX-compatible export |
| Cloud flow logs | AWS VPC Flow Logs (v2–v5 fields), Azure VNet flow logs (NSG flow logs retiring Sept 2027 — migrate), GCP VPC Flow Logs |

Sampling trades accuracy for load: 1:1 for security on edge/DC where possible; sampled data under-detects low-volume C2.

---

## 2. Exporter Configuration

### Cisco IOS-XE (Flexible NetFlow)

```text
flow record SEC-REC
 match ipv4 source address
 match ipv4 destination address
 match transport source-port
 match transport destination-port
 match ipv4 protocol
 match interface input
 collect counter bytes long
 collect counter packets long
 collect timestamp absolute first
 collect timestamp absolute last
 collect transport tcp flags
flow exporter SEC-EXP
 destination 10.20.0.50
 source Loopback0
 transport udp 2055
 export-protocol ipfix
flow monitor SEC-MON
 record SEC-REC
 exporter SEC-EXP
 cache timeout active 60
interface GigabitEthernet0/0/1
 ip flow monitor SEC-MON input
 ip flow monitor SEC-MON output
```

### Huawei VRP (NetStream)

```text
ip netstream export version 9
ip netstream export source 10.0.0.1
ip netstream export host 10.20.0.50 2055
ip netstream timeout active 1
interface GigabitEthernet0/0/1
 ip netstream inbound
 ip netstream outbound
```

(Commands vary by platform/VRP version — verify against the device's NetStream guide.)

### AWS

```bash
aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-0abc --traffic-type ALL \
  --log-destination-type s3 --log-destination arn:aws:s3:::org-flowlogs \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${pkt-srcaddr} ${pkt-dstaddr} ${tcp-flags} ${flow-direction}'
```

---

## 3. Collectors & Queries

```bash
nfcapd -w -D -l /var/flows -p 2055                                  # collect
nfdump -R /var/flows -s dstip/bytes -n 20 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8'   # top external destinations by bytes
nfdump -R /var/flows -A srcip,dstport -s record/flows 'dst port in [445 3389 5985]' -n 50     # admin protocol fan-out
nfdump -R /var/flows 'proto tcp and flags S and not flags A' -s srcip/flows -n 20             # SYN scanners
```

SiLK: `rwfilter --start-date=2026/10/22 --proto=6 --dport=445 --pass=stdout | rwuniq --fields=sip --values=distinct:dip --threshold-distinct:dip=50`

---

## 4. Analytics

| Use case | Flow logic |
|---|---|
| Horizontal scan | One src → many dst on same port, many incomplete (SYN-only) flows |
| Lateral movement | Workstation → workstation on 445/135/3389/5985 |
| Beaconing | Same src/dst/port, regular intervals, similar byte counts |
| Exfiltration | Bytes out ≫ bytes in to a rare external destination; long durations |
| Data hoarding | Internal host receiving large volumes from many file servers |
| DDoS | Packet rate spikes, many sources → one destination, SYN/UDP floods |
| Tunneling | Long-lived flows on 53/123/ICMP with high byte counts |
| New services | First-seen listening port on a server |
| Cloud | `REJECT` spikes (scanning), traffic to IMDS from containers, egress from DB subnets |

---

## 5. NDR Platforms

| Platform | Strength |
|---|---|
| Zeek / Corelight | Rich protocol logs, open format, scriptable |
| Vectra AI | Attack-behavior models, identity/Entra coverage |
| ExtraHop RevealX | Wire-data analytics, decryption support |
| Darktrace | Unsupervised anomaly detection |
| Cisco Secure Network Analytics (Stealthwatch) | Flow-based analytics at scale |
| Security Onion | Open-source NSM stack (Zeek, Suricata incl. PCAP in 3.x) |

Evaluate on: protocol coverage (SMB/Kerberos/LDAP/DCE-RPC parsers), east-west visibility, encrypted traffic analytics, SIEM/EDR integration, retention, and whether detections are explainable.

**Community ID** (hash of 5-tuple) links Zeek, Suricata, EDR, and firewall records for the same flow — enable everywhere.

---

## Engagement Cheatsheet

```text
export IPFIX/v9/NetStream/cloud flow logs (1:1 where possible) → central collector ≥90d → enrich (assets, ASN, intel)
→ analytics: scans, ws↔ws admin ports, beacons, bytes-out ratio, long flows, REJECT spikes → Community ID pivot to Zeek/PCAP/EDR
```

---

## Key References

- RFC 7011 (IPFIX); nfdump; CERT NetSA SiLK; ElastiFlow; Community ID spec
- Related: `defensive-zeek`, `defensive-hunt-network`, `defensive-detect-exfiltration`, `defensive-ddos`, `defensive-network-forensics`
