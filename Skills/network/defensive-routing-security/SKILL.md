---
name: defensive-routing-security
description: "Routing infrastructure security: BGP hardening (RPKI Route Origin Validation and ROAs, IRR-based prefix filtering, max-prefix, GTSM/TTL security, TCP-MD5 and TCP-AO, bogon and own-prefix filtering, route leak prevention with RFC 9234 roles, ASPA direction), MANRS actions, BCP 38/84 anti-spoofing and uRPF, IGP security (OSPF/IS-IS/EIGRP authentication with HMAC-SHA, passive interfaces), FHRP (HSRP/VRRP) authentication, control plane policing, BGP hijack and leak monitoring (BGPalerter, RIPE RIS, Cloudflare Radar), Cisco IOS-XE and Huawei VRP configs, and incident response for hijacks. Use when securing routers, BGP edges, or investigating route hijacks."
---

# Routing Security

Routing attacks redirect or black-hole traffic at internet scale (BGP hijacks, leaks) or inside your network (rogue IGP neighbors, FHRP takeover). Defense combines **cryptographic validation (RPKI), filtering, authentication, and monitoring**.

## Quick Workflow

1. Publish ROAs for all your prefixes; enable ROV on edge routers (drop invalids)
2. Filter BGP sessions (prefix lists from IRR/contracts, max-prefix, bogons)
3. Authenticate all routing adjacencies (BGP TCP-AO/MD5, OSPF/IS-IS HMAC-SHA, FHRP)
4. Anti-spoofing: BCP 38 ingress filtering, uRPF
5. Protect the control plane (CoPP, GTSM)
6. Monitor for hijacks/leaks of your prefixes

---

## 1. BGP Controls

| Control | Purpose |
|---|---|
| RPKI ROAs | Cryptographically state which AS may originate your prefixes (and max length) — create at RIR portal (APNIC for Philippines, ARIN, RIPE, etc.) |
| ROV | Drop routes with RPKI state **invalid** from peers |
| IRR prefix filters | Build per-customer/peer prefix lists (bgpq4) from IRR AS-SETs |
| Max-prefix | Tear down/alert when peer exceeds expected count |
| Bogon / own-prefix filters | Reject martians, private/reserved ranges, your own prefixes from outside |
| GTSM (RFC 5082) | Accept eBGP only with TTL 255 (one hop) — blocks remote spoofed sessions |
| TCP-AO (RFC 5925) / MD5 | Session authentication |
| RFC 9234 BGP roles + OTC | Prevent route leaks (provider/customer/peer roles) |
| ASPA (in development) | Path validation against leaks; track vendor support |
| Communities | Use RTBH/blackhole (RFC 7999) safely with authentication of signaling customers |

### Cisco IOS-XE

```text
router bgp 65001
 bgp rpki server tcp 192.0.2.10 port 3323 refresh 600
 neighbor 203.0.113.1 remote-as 64500
 neighbor 203.0.113.1 password <secret>
 neighbor 203.0.113.1 ttl-security hops 1
 address-family ipv4 unicast
  neighbor 203.0.113.1 route-map UPSTREAM-IN in
  neighbor 203.0.113.1 prefix-list OWN-OUT out
  neighbor 203.0.113.1 maximum-prefix 1200000 95 warning-only
!
ip prefix-list OWN-OUT seq 10 permit 198.51.100.0/22
ip prefix-list BOGONS seq 5 deny 10.0.0.0/8 le 32
ip prefix-list BOGONS seq 10 deny 172.16.0.0/12 le 32
ip prefix-list BOGONS seq 15 deny 192.168.0.0/16 le 32
ip prefix-list BOGONS seq 20 deny 198.51.100.0/22 le 32
ip prefix-list BOGONS seq 100 permit 0.0.0.0/0 le 24
!
route-map UPSTREAM-IN deny 10
 match rpki invalid
route-map UPSTREAM-IN permit 20
 match ip address prefix-list BOGONS
```

(RTR port depends on the validator — Routinator/rpki-client+stayrtr commonly 3323; IANA port 323.)

### Huawei VRP

```text
rpki
 session 192.0.2.10
  tcp port 3323
bgp 65001
 peer 203.0.113.1 as-number 64500
 peer 203.0.113.1 password cipher <secret>
 peer 203.0.113.1 valid-ttl-hops 1
 ipv4-family unicast
  prefix origin-validation enable
  peer 203.0.113.1 route-policy UPSTREAM-IN import
  peer 203.0.113.1 ip-prefix OWN-OUT export
  peer 203.0.113.1 route-limit 1200000 95 alert-only
route-policy UPSTREAM-IN deny node 10
 if-match origin-validation invalid
route-policy UPSTREAM-IN permit node 20
```

(Verify syntax for your NE/AR/CE platform and VRP version.)

Validators: Routinator, rpki-client + StayRTR, Fort. Run at least two.

---

## 2. MANRS Actions (network operators)

1. **Filtering** — prevent propagation of incorrect routing information
2. **Anti-spoofing** — prevent traffic with spoofed source IPs (BCP 38)
3. **Coordination** — maintain current contact info (PeeringDB, RIR, IRR)
4. **Global validation** — publish routing data (ROAs, IRR objects)

---

## 3. Anti-Spoofing

```text
! Cisco: strict uRPF on customer/edge-facing single-homed interface
interface GigabitEthernet0/0/2
 ip verify unicast source reachable-via rx
! loose mode for multi-homed: reachable-via any
```

```text
# Huawei
interface GigabitEthernet0/0/2
 urpf strict
```

Also: ingress ACLs denying your own and bogon source addresses from the internet; egress ACLs allowing only your prefixes as sources.

---

## 4. IGP & FHRP Authentication

### OSPF HMAC-SHA — Cisco

```text
key chain OSPF-KC
 key 1
  key-string <secret>
  cryptographic-algorithm hmac-sha-256
interface GigabitEthernet0/0/1
 ip ospf authentication key-chain OSPF-KC
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/0/1
```

### OSPF HMAC-SHA — Huawei

```text
interface GigabitEthernet0/0/1
 ospf authentication-mode hmac-sha256 1 cipher <secret>
ospf 1
 silent-interface all
 undo silent-interface GigabitEthernet0/0/1
```

FHRP: HSRP v2 MD5 authentication (`standby 1 authentication md5 key-chain HSRP-KC`), VRRPv3 has no auth in RFC — protect with ACLs/CoPP limiting VRRP (IP protocol 112) to known peers. Passive interfaces on all user-facing segments so rogue routers can't form adjacencies.

---

## 5. Control Plane Protection

CoPP/CPP policies rate-limit and filter traffic to the route processor: permit BGP only from configured neighbors, OSPF/IS-IS only on core interfaces, management protocols only from management networks, rate-limit ICMP and ARP.

---

## 6. Monitoring

| Tool | Purpose |
|---|---|
| BGPalerter | Self-hosted alerts on hijacks, visibility loss, RPKI invalid announcements of your prefixes |
| RIPE RIS / RIPEstat, RouteViews, bgp.tools | Global routing views |
| Cloudflare Radar route leak/hijack detection | Notifications for your ASN |
| Router logs | Neighbor flaps, max-prefix hits, authentication failures |

---

## 7. Hijack Response

1. Confirm via multiple looking glasses (is your prefix originated by another AS / more-specific announced?)
2. Announce more-specifics (if ≤ /24 allowed and ROA max-length permits) to win best-path
3. Contact the offending AS and its upstreams (PeeringDB contacts, NOC lists)
4. Ensure ROAs are correct so ROV-enforcing networks drop the hijack
5. Document timeline; review max-length on ROAs (too permissive max-length enables sub-prefix hijacks)

---

## Engagement Cheatsheet

```text
ROAs (tight max-length) + ROV drop invalid (2 validators) → IRR prefix filters (bgpq4) + bogons + max-prefix + GTSM + TCP-AO/MD5
→ RFC 9234 roles → BCP 38 + uRPF → OSPF/IS-IS HMAC-SHA + passive default + FHRP auth → CoPP → BGPalerter/Radar → hijack runbook
```

---

## Key References

- RFC 6811 (ROV), RFC 9319 (max-length guidance), RFC 5082 (GTSM), RFC 5925 (TCP-AO), RFC 9234 (BGP roles), BCP 38 (RFC 2827), BCP 84 (RFC 3704), RFC 7454 (BGP operations & security)
- MANRS; NIST SP 800-189 (Resilient Interdomain Traffic Exchange); White House Roadmap to Enhancing Internet Routing Security (2024)
- Related: `defensive-network-device-hardening`, `defensive-ddos`, `defensive-network-security-architecture`
