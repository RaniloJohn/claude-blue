---
name: defensive-network-security-architecture
description: "End-to-end network security architecture: security zones and trust levels, perimeter/DMZ/internal/management/OT zones, north-south vs east-west controls, campus/branch/data center/cloud designs, hub-and-spoke and transit, out-of-band management, egress architecture (proxy, DNS, NAT), placement of NGFW, IPS, NDR sensors, WAF, load balancers, ZTNA connectors, NAC, network visibility architecture (TAPs, SPAN, packet brokers, flow), resilience (redundant paths, HA pairs), NIST SP 800-215 and SP 800-41, and a network security review checklist. Use when designing or assessing an organization's network security, drawing zone diagrams, or placing security controls."
---

# Network Security Architecture

The network is both an attack path and the best sensor in the environment. Design it so that **every zone crossing is controlled and observed**, management is separated from data, and egress is deliberate.

## Quick Workflow

1. Inventory sites, segments, flows, and internet/cloud/partner connections
2. Define zones and trust levels (§1) and the allowed flow matrix
3. Place enforcement (firewalls, ACLs, ZTNA, NAC) at zone boundaries
4. Place visibility (TAP/SPAN, NDR, flow, DNS logs) at chokepoints
5. Separate management; harden devices (`defensive-network-device-hardening`)
6. Review with the checklist (§6)

---

## 1. Zones

| Zone | Contents | Default policy |
|---|---|---|
| Internet / untrusted | Everything outside | Deny inbound except published services |
| Edge / DMZ | Reverse proxies, WAF, mail relays, VPN/ZTNA gateways, public DNS | Inbound from internet to specific ports; **no initiation to internal** except via defined proxies |
| Internal user | Workstations, Wi-Fi clients | Outbound via proxy/DNS filters; no inbound from other user segments |
| Server / data center | App servers, databases | Only required app ports from defined sources |
| Restricted / crown jewels | Payment (CDE), HR, research data | Strictly allowlisted flows, enhanced monitoring |
| Identity / Tier 0 | DCs, PKI, IdP connectors, PAM | Only required auth protocols from clients; admin only from PAW |
| Management (OOB) | Device mgmt interfaces, iLO/iDRAC/IPMI, hypervisor mgmt, backup | Reachable only from jump hosts/PAWs |
| Guest / IoT | Visitor Wi-Fi, printers, cameras, building systems | Internet-only or tightly scoped; no internal |
| OT / ICS | Purdue levels 0–3 | Via IT/OT DMZ (level 3.5) only |
| Cloud VPC/VNet | Workloads | Same zone model, enforced with SG/NSG/firewall |
| Partner / third party | Extranet, vendor access | Per-partner segment, ZTNA, time-bound |

---

## 2. North-South vs East-West

| Direction | Controls |
|---|---|
| North-south (in/out of org) | Edge NGFW, DDoS protection, WAF, email gateway, secure web gateway/proxy, protective DNS, egress filtering |
| East-west (internal) | Internal segmentation firewalls, VLAN ACLs, host firewalls, micro-segmentation agents, SGT/TrustSec, cloud SG/NSG, NDR |

Most ransomware damage is east-west — budget for internal segmentation and visibility, not only the edge.

---

## 3. Reference Designs

| Environment | Pattern |
|---|---|
| Campus | Access (802.1X/NAC, DHCP snooping, DAI) → distribution (VLAN ACLs/VRFs) → core → internal firewall to DC; guest VRF to internet only |
| Branch | SD-WAN edge with local internet breakout via SSE/SWG; local segmentation; no direct DC access without policy |
| Data center | Zones per application tier, firewall or micro-segmentation between tiers, separate storage and management networks |
| Cloud | Hub-and-spoke / transit gateway with central inspection (AWS Network Firewall, Azure Firewall, Cloud NGFW), private endpoints for PaaS, no public IPs on workloads by default |
| Remote users | ZTNA/SSE per-app access; legacy VPN only with MFA + posture + split-tunnel policy decision |
| OT | IEC 62443 zones & conduits, IT/OT DMZ, unidirectional gateways for high-consequence sites |

---

## 4. Egress Architecture

- All web egress via proxy/SWG (explicit or transparent) with category filtering and logging
- DNS only via internal resolvers → protective DNS; block outbound 53/853 and unsanctioned DoH elsewhere
- Servers: default-deny internet; allowlist update/vendor domains
- SMTP egress only from mail servers
- Block outbound SMB (445), RDP (3389), and NetBIOS to the internet
- NAT logging retained for attribution

---

## 5. Visibility Architecture

| Component | Placement |
|---|---|
| Network TAPs | Internet edge (inside & outside firewall), DC core, IT/OT boundary |
| SPAN/RSPAN/ERSPAN | Where TAPs impractical; watch for oversubscription and drops |
| Packet broker | Aggregate, filter, deduplicate, slice; feed IDS/NDR/PCAP |
| NDR / Zeek / Suricata sensors | Behind brokers at key chokepoints |
| Flow (NetFlow/IPFIX/sFlow, VPC Flow Logs) | All routers/firewalls/cloud VPCs |
| Full PCAP | Edge + crown jewels; rolling retention (days) |
| DNS logs | Resolver query logs (all clients) |
| Cloud | VPC Traffic Mirroring / Azure vTAP / GCP Packet Mirroring for selected workloads |

TLS 1.3 + ECH reduce passive visibility — rely more on endpoint telemetry, DNS, JA4 fingerprints, and selective TLS inspection (`defensive-proxy-tls-inspection`).

---

## 6. Review Checklist

| # | Check |
|---|---|
| 1 | Current network diagram (L2/L3) and flow matrix exist and match reality |
| 2 | No flat networks: user, server, management, guest, IoT, OT separated |
| 3 | Default-deny between zones; rules have owners, tickets, and review dates |
| 4 | Management interfaces not reachable from user or internet zones |
| 5 | Edge devices on supported firmware, KEV patched within SLA, management not internet-exposed |
| 6 | Egress filtered; DNS forced through resolvers |
| 7 | Remote access via MFA + posture; no exposed RDP/SMB/Telnet/SNMP |
| 8 | Visibility: flow + DNS + IDS/NDR at chokepoints; logs in SIEM |
| 9 | L2 protections at access layer (port security, DHCP snooping, DAI, BPDU guard, RA guard) |
| 10 | Redundancy and HA for critical security devices; fail-closed decisions documented |
| 11 | Cloud network controls equivalent to on-prem; no 0.0.0.0/0 to admin ports |
| 12 | Network device configs backed up, changes logged, AAA via TACACS+/RADIUS |

---

## Engagement Cheatsheet

```text
inventory → zones + flow matrix → enforce at boundaries (NGFW/ACL/ZTNA/NAC/SG) → north-south + east-west
→ egress via proxy/DNS → visibility (TAP/broker/NDR/flow/DNS/PCAP) → OOB management → 12-point review
```

---

## Key References

- NIST SP 800-215 (Secure Enterprise Network Landscape, 2022); NIST SP 800-41 Rev 1 (Firewalls); NIST SP 800-94 (IDPS)
- CISA/NSA Network Infrastructure Security Guide; IEC 62443-3-2 (zones & conduits)
- Related: `defensive-network-segmentation`, `defensive-ngfw-policy`, `defensive-ids-ips-deployment`, `defensive-netflow-ndr`, `defensive-zero-trust-architecture`
