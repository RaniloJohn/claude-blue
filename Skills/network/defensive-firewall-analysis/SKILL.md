---
name: defensive-firewall-analysis
description: "Firewall, router, and flow log analysis plus rule-base review: Palo Alto PAN-OS (traffic/threat/URL/GlobalProtect logs, App-ID, security policy), Fortinet FortiGate (traffic/utm/event logs, policy IDs), Cisco Secure Firewall ASA/FTD syslog message IDs, pfSense/OPNsense filterlog, NetFlow/IPFIX with nfdump, VPN logs, and detection use cases (C2 egress, port scans, brute force against VPN, data exfil, policy bypass, denied-then-allowed). Also rule-base hygiene: any-any rules, shadowed/redundant rules, unused rules by hit count, risky services, and change monitoring. Use when investigating with firewall/flow data or auditing firewall policy."
---

# Firewall & Flow Analysis

Firewalls see every allowed and denied flow at a boundary. They are the backstop when endpoint telemetry is missing — and the policy itself is attack surface.

## Quick Workflow

1. Confirm what is logged (allow + deny, session start/end, NAT)
2. Normalize fields (src, dst, ports, app, action, rule, bytes, user)
3. Run detection queries (egress, scans, VPN brute force, exfil)
4. Pivot to endpoint/identity for attribution
5. Review the rule base on a schedule

---

## 1. Platform Log Reference

| Platform | Log types | Key fields |
|---|---|---|
| Palo Alto PAN-OS | TRAFFIC, THREAT, URL, WILDFIRE, DATA, GLOBALPROTECT, SYSTEM, CONFIG, USERID, DECRYPTION | `src, dst, sport, dport, app, action, rule, from/to zone, bytes_sent/received, session_end_reason, threat_id, category, srcuser` |
| Fortinet FortiGate | `type=traffic` (forward/local), `type=utm` (ips, av, webfilter, app-ctrl, dns), `type=event` (vpn, system, user) | `srcip, dstip, dstport, service, action, policyid, app, sentbyte, rcvdbyte, user` |
| Cisco ASA / FTD | Syslog message IDs | `%ASA-6-302013/302014` TCP built/teardown, `%ASA-6-302015/302016` UDP, `%ASA-4-106023` ACL deny, `%ASA-6-106100` ACL hit, `%ASA-6-113004/113005` AAA success/failure, `%ASA-6-722022/722051` AnyConnect session, `%ASA-4-733100` threat detection; FTD Connection Events via FMC/eStreamer |
| pfSense / OPNsense | `filterlog` CSV | rule number, interface, action (pass/block), direction, proto, src, dst, ports |
| NetFlow/IPFIX | Flow records | 5-tuple, bytes, packets, start/end, TCP flags, AS |

---

## 2. Detection Use Cases

| Use case | Logic |
|---|---|
| Egress to rare destinations | Allowed outbound to dst/ASN seen by ≤1 internal host in 30 d |
| Server-initiated egress | Servers (DMZ/DB) initiating outbound internet sessions |
| Non-standard egress ports | Allowed outbound on ports outside 80/443/53/123 from workstations |
| Port scan (internal) | One src → many dst ports or IPs with deny/reset |
| VPN brute force / spray | Many failed VPN auths (GlobalProtect, Fortinet SSL-VPN `event vpn`, ASA 113005) by user/IP |
| Successful VPN from new country/ASN | VPN login geo anomaly |
| Exfil volume | Bytes out per src→dst above baseline; uploads to file-sharing categories |
| Deny → allow flip | Same src/dst/port denied then allowed after a config change |
| Threat log hits followed by allowed session | IPS alert but session continued (alert-only policy) |
| Tor / anonymizers | Connections to Tor exit lists / App-ID `tor` |
| DNS bypass | Outbound udp/53 or tcp/853 not to approved resolvers |

```spl
index=pan sourcetype=pan:traffic action=allowed dest_zone=untrust
| stats dc(src_ip) as clients sum(bytes_out) as out by dest_ip app
| where clients=1 AND out > 50000000
```

```spl
index=fortinet type=event subtype=vpn action=ssl-login-fail
| stats count dc(user) as users by srcip | where count > 20 OR users > 10
```

---

## 3. NetFlow with nfdump

```bash
nfdump -R /var/cache/nfdump -t 2026/10/22.00:00:00-2026/10/23.00:00:00 -s dstip/bytes -n 20 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8'
nfdump -R /var/cache/nfdump -s srcip/flows -n 20 'flags S and not flags A'        # SYN-only (scanning)
nfdump -R /var/cache/nfdump -A srcip,dstip -O bytes -n 20 'dst port 443'          # aggregated pairs
```

Flow has no payload — corroborate with proxy/Zeek/EDR.

---

## 4. Rule-Base Review

| Issue | How to find | Fix |
|---|---|---|
| Any-any / overly broad | Rules with `any` source/destination/service | Narrow to required |
| Shadowed rules | Rule fully covered by an earlier rule | Remove or reorder |
| Redundant | Duplicate coverage | Consolidate |
| Unused | Zero hit count over 90 d | Disable → remove |
| Risky services inbound | RDP/SMB/Telnet/SNMPv1/2 from internet | Remove; VPN/ZTNA |
| No logging | Rules without log at session end | Enable logging |
| Expired temporary rules | Rules with past-due tickets | Remove |
| Missing egress filtering | Outbound any from servers | Default-deny egress with allowlists |

Tools: vendor policy optimizers (PAN-OS Policy Optimizer, FortiManager), Tufin/AlgoSec/FireMon, `capirca`/`aerleon` for policy-as-code.

```text
# PAN-OS CLI: hit counts
show rule-hit-count vsys vsys-name vsys1 rule-base security rules all
# Cisco ASA
show access-list | include hitcnt=0
```

---

## 5. Change Monitoring

- PAN-OS CONFIG logs; FortiGate `type=event subtype=system` config change; ASA `%ASA-5-111008` (command executed), `%ASA-5-111010`
- Alert on: new any-any, new inbound NAT, logging disabled, admin login from new source, config changes outside windows

---

## 6. Management Plane

- Management interfaces never exposed to the internet; restrict to admin subnets/jump hosts
- MFA for admin; separate admin accounts; RBAC
- Patch edge devices urgently (firewalls/VPNs are top KEV targets); subscribe to vendor PSIRT
- Export logs off-box; configuration backups with integrity checks

---

## Engagement Cheatsheet

```text
logging coverage → normalize → egress/scan/VPN/exfil/deny→allow detections → attribute via EDR/IdP
→ rule review (any-any, shadowed, unused, risky) → change monitoring → mgmt plane hardening
```

---

## Key References

- Palo Alto PAN-OS syslog field descriptions; Fortinet log reference; Cisco ASA Syslog Messages guide
- nfdump — https://github.com/phaag/nfdump
- CIS Benchmarks for Palo Alto, Fortinet, Cisco firewalls
- Related: `defensive-network-segmentation`, `defensive-hunt-network`, `defensive-network-device-hardening`
