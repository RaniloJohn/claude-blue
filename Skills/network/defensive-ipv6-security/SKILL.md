---
name: defensive-ipv6-security
description: "IPv6 security for dual-stack and IPv6-only networks: rogue Router Advertisements and RA Guard (RFC 6105), DHCPv6 Guard and mitm6/WPAD/NTLM relay attacks, Neighbor Discovery spoofing and ND inspection/SAVI/device-tracking, IPv6 source guard, ICMPv6 filtering per RFC 4890, extension header and fragmentation risks, tunneling (Teredo, 6to4, ISATAP) blocking, firewall policy parity between IPv4 and IPv6, SLAAC privacy addresses and logging/attribution, Windows IPv6 preference settings, Cisco IOS-XE and Huawei VRP first-hop security configs, and IPv6 visibility in SIEM/NDR. Use when securing or assessing IPv6, or defending against mitm6-style attacks."
---

# IPv6 Security

Most enterprise networks run IPv6 whether they planned to or not: Windows, macOS, and Linux enable it by default and prefer it. Unmanaged IPv6 = an unmonitored second network that attackers can take over with one rogue router advertisement or DHCPv6 reply.

## Quick Workflow

1. Decide: manage IPv6 properly (preferred) or deliberately suppress it per segment
2. Enable first-hop security on access switches: RA Guard, DHCPv6 Guard, ND inspection/source guard
3. Ensure firewall policy parity for IPv6 (same zones and rules)
4. Block legacy tunneling; filter ICMPv6 correctly
5. Log IPv6 neighbor/DHCPv6 bindings for attribution

---

## 1. Attacks

| Attack | Mechanism | Impact |
|---|---|---|
| Rogue RA | Attacker sends Router Advertisements | Becomes default gateway (MITM) or DoS |
| mitm6 (DHCPv6 spoofing) | Replies to Windows DHCPv6 solicitations with attacker DNS server | DNS takeover → WPAD → NTLM relay to LDAP/AD CS (with ntlmrelayx) |
| ND spoofing | Fake Neighbor Advertisements | MITM (ARP spoofing equivalent) |
| RA flooding | Thousands of RAs with random prefixes | Host CPU exhaustion |
| Extension header abuse | Long header chains, fragmentation | IDS/firewall evasion |
| Tunnels (Teredo/6to4/ISATAP) | IPv6 over IPv4 | Bypass IPv4-only controls |
| Policy gaps | IPv4 rules but IPv6 allow-any | Direct exposure |

---

## 2. First-Hop Security — Cisco IOS-XE

```text
ipv6 nd raguard policy HOSTS
 device-role host
ipv6 nd raguard policy ROUTERS
 device-role router
ipv6 dhcp guard policy CLIENTS
 device-role client
ipv6 dhcp guard policy SERVERS
 device-role server
device-tracking policy DT-HOSTS
 security-level guard
 tracking enable
!
interface range GigabitEthernet1/0/1 - 46
 ipv6 nd raguard attach-policy HOSTS
 ipv6 dhcp guard attach-policy CLIENTS
 device-tracking attach-policy DT-HOSTS
interface GigabitEthernet1/0/48
 description uplink-to-router
 ipv6 nd raguard attach-policy ROUTERS
 ipv6 dhcp guard attach-policy SERVERS
```

Verify: `show ipv6 nd raguard policy`, `show device-tracking database`. IPv6 source guard (`ipv6 source-guard attach-policy`) blocks traffic from unbound addresses (platform-dependent).

---

## 3. First-Hop Security — Huawei VRP

```text
dhcp enable
dhcp snooping enable ipv6
nd snooping enable
interface GigabitEthernet0/0/1
 description access-port
 nd raguard role host
interface GigabitEthernet0/0/24
 description uplink
 nd raguard role router
 dhcp snooping trusted
 nd snooping trusted
```

Verify: `display nd snooping user-bind all`, `display dhcpv6 snooping user-bind all`. (Exact commands vary by S-series model and VRP version — verify.)

---

## 4. Host Controls

| OS | Control |
|---|---|
| Windows | Don't disable IPv6 entirely (Microsoft unsupported; breaks components). To blunt mitm6 where IPv6 isn't deployed: prefer IPv4 (`DisabledComponents = 0x20`) and block inbound DHCPv6 (UDP 546) and RA via Windows Firewall GPO; disable WPAD; enforce LDAP signing + channel binding and EPA on AD CS web enrollment |
| Linux | `net.ipv6.conf.all.accept_ra=0` on servers with static config; `accept_redirects=0` |
| macOS | Managed via profiles; same network-side protections apply |

Windows Firewall GPO rules (inbound block): "Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPV6-In)", "Core Networking - Router Advertisement (ICMPv6-In)" — only where IPv6 is not used.

---

## 5. Firewall & Filtering

- Every IPv4 zone rule needs its IPv6 equivalent; default deny for IPv6 on all firewalls
- ICMPv6 (RFC 4890): allow essential types (1 Destination Unreachable, 2 Packet Too Big, 3 Time Exceeded, 4 Parameter Problem, echo as policy allows; ND types 133–137 link-local only) — never block Packet Too Big (breaks PMTUD)
- Drop Routing Header type 0 (RFC 5095), excessive extension headers, and atomic/overlapping fragments
- Block tunneling: IPv4 protocol 41 (6in4/6to4/ISATAP), UDP 3544 (Teredo) at the edge; disable Teredo/ISATAP on Windows via GPO
- Block ISATAP and WPAD names in DNS global query block list (Windows DNS defaults)

---

## 6. Visibility & Attribution

- SLAAC privacy/temporary addresses change frequently — log ND/DHCPv6 bindings (switch device-tracking, DHCPv6 server logs, router neighbor tables) to map IPv6 → MAC → host over time
- Ensure SIEM parsers, Zeek, Suricata, NetFlow v9/IPFIX, and EDR all capture IPv6 fields
- Threat intel and blocklists must include IPv6 indicators

---

## 7. Detections

| Signal | Source |
|---|---|
| RA from non-router port | RA Guard violation logs, Zeek `icmp`, NDR |
| DHCPv6 ADVERTISE/REPLY from non-server | DHCPv6 Guard logs, Zeek `dhcp` |
| Windows clients with unexpected IPv6 DNS servers | EDR/inventory (`Get-DnsClientServerAddress`) |
| WPAD requests followed by NTLM auth to workstation IP | Proxy/NDR + 4624 |
| LDAP/AD CS NTLM auth from workstation IPs | 4624 NTLM to DCs/CA from non-server sources |
| Protocol 41 / UDP 3544 egress | Firewall |

---

## Engagement Cheatsheet

```text
decide manage vs suppress → RA Guard + DHCPv6 Guard + device-tracking/ND snooping on access ports (Cisco/Huawei)
→ Windows: prefer IPv4 0x20 + block DHCPv6/RA in firewall if unused, kill WPAD, LDAP signing/channel binding, EPA
→ IPv6 firewall parity + RFC 4890 ICMPv6 + drop RH0 + block proto 41/UDP 3544 → log bindings → detect rogue RA/DHCPv6
```

---

## Key References

- RFC 6105 (RA Guard), RFC 4890 (ICMPv6 filtering), RFC 5095 (RH0 deprecation), RFC 7113 (RA Guard implementation advice), RFC 8200 (IPv6)
- NSA "IPv6 Security Guidance" (2023); Fox-IT mitm6 research
- Related: `defensive-l2-security`, `defensive-ad-hardening`, `defensive-network-device-hardening`
