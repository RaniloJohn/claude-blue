---
name: defensive-network-segmentation
description: "Network segmentation and zero trust network design for defenders: zone and trust-level modeling, VLAN/VRF design, ACL design and placement (standard vs extended, inbound vs outbound), Cisco IOS and Huawei VRP ACL examples, role-based segmentation for campus networks, east-west restriction (workstation-to-workstation SMB/RDP/WinRM), admin jump hosts/PAWs, DMZ design, microsegmentation (host firewalls, SDN, Kubernetes NetworkPolicy), ZTNA replacing VPN, NIST SP 800-207 and CISA Zero Trust Maturity Model, and validating segmentation with testing. Use when designing, reviewing, or troubleshooting segmentation and ACL policies."
---

# Network Segmentation & Zero Trust

Segmentation limits blast radius: compromise of one zone should not grant reachability to everything else. Design from data flows, enforce least privilege between zones, and verify with tests.

## Quick Workflow

1. Inventory assets and classify (users, servers, Tier 0, OT, IoT, guests)
2. Map required flows (who needs to talk to what, on which ports)
3. Define zones and trust levels
4. Enforce with ACLs/firewalls (default deny between zones)
5. Restrict east-west inside zones (host firewalls)
6. Validate with scans and attack-path tests; monitor denies

---

## 1. Zone Model (example campus/enterprise)

| Zone | Contents | Inbound allowed from |
|---|---|---|
| Users (by role) | Staff, faculty, executives, students | Mgmt (for support tools only) |
| Admin / PAW | Admin workstations, jump hosts | Admins only (MFA) |
| Servers | Apps, file, DB | Users on app ports only |
| Tier 0 | DCs, ADCS, identity, backup | Specific servers + admin zone |
| DMZ | Internet-facing services | Internet on published ports |
| OT / IoT | Building systems, CCTV, printers | Specific management hosts |
| Guest | Visitors | Nothing internal; internet only |
| Management | Network device mgmt (SSH, SNMPv3) | Admin zone only |

Rule: **users never talk directly to users**; servers expose only required ports; Tier 0 reachable only from Tier 0 admin paths.

---

## 2. ACL Design Rules

- Default deny between zones; explicit permits for documented flows
- Extended ACLs close to the **source**; standard ACLs close to the **destination**
- Order specific → general; first match wins; implicit deny at end (log it)
- Permit return traffic statefully (firewall) or with `established` (router ACL, TCP only)
- Document every entry with ticket/owner
- Review hit counts; remove dead entries

### Cisco IOS (extended, named)

```text
ip access-list extended STUDENTS-IN
 remark Students: DNS/DHCP + web only; block internal servers except LMS
 permit udp 10.40.0.0 0.0.255.255 host 10.10.1.10 eq 53
 permit tcp 10.40.0.0 0.0.255.255 host 10.20.5.20 eq 443
 deny   ip 10.40.0.0 0.0.255.255 10.0.0.0 0.255.255.255 log
 permit tcp 10.40.0.0 0.0.255.255 any eq 443
 permit tcp 10.40.0.0 0.0.255.255 any eq 80
 deny   ip any any log
!
interface Vlan40
 ip access-group STUDENTS-IN in
```

### Huawei VRP (advanced ACL + traffic-filter)

```text
acl number 3040
 description STUDENTS-IN
 rule 5 permit udp source 10.40.0.0 0.0.255.255 destination 10.10.1.10 0 destination-port eq dns
 rule 10 permit tcp source 10.40.0.0 0.0.255.255 destination 10.20.5.20 0 destination-port eq 443
 rule 15 deny ip source 10.40.0.0 0.0.255.255 destination 10.0.0.0 0.255.255.255
 rule 20 permit tcp source 10.40.0.0 0.0.255.255 destination-port eq 443
 rule 25 permit tcp source 10.40.0.0 0.0.255.255 destination-port eq www
 rule 100 deny ip
#
interface Vlanif40
 traffic-filter inbound acl 3040
```

Verify keyword support (`destination-port eq dns/www`) on your platform/version; numeric ports always work.

---

## 3. East-West Restriction

| Flow | Default | Exception |
|---|---|---|
| Workstation → workstation SMB (445) | Deny | None |
| Workstation → workstation RDP (3389) | Deny | Helpdesk via jump host |
| Workstation → any WinRM (5985/5986) | Deny | Admin zone only |
| Workstation → DC | Allow auth ports only (88, 389/636, 445 for SYSVOL/NETLOGON, 135+dynamic RPC, 53) | — |
| Server → internet | Deny | Explicit allowlist (updates, APIs) via proxy |

Enforce on host firewalls (Windows Firewall GPO / Intune) where switches can't filter intra-VLAN traffic; private VLANs for guest/IoT.

---

## 4. Zero Trust Principles (NIST SP 800-207)

- Every access decision per request, based on identity, device posture, and context
- No implicit trust from network location
- Policy Decision Point / Policy Enforcement Point separation
- ZTNA (identity-aware proxy) instead of flat VPN access to whole networks
- CISA Zero Trust Maturity Model pillars: Identity, Devices, Networks, Applications & Workloads, Data; cross-cutting Visibility & Analytics, Automation & Orchestration, Governance

---

## 5. Microsegmentation

| Layer | Tool |
|---|---|
| Hosts | Windows Firewall/Intune, nftables/iptables, host-based agents (Illumio, Guardicore/Akamai) |
| Virtualization | NSX distributed firewall, Hyper-V/Azure NSGs |
| Cloud | Security groups/NSGs/VPC firewall rules; no 0.0.0.0/0 to admin ports |
| Kubernetes | NetworkPolicy default deny per namespace; Cilium policies |

---

## 6. Validation

```bash
nmap -Pn -sS -p 22,135,139,445,3389,5985,5986 10.40.0.0/24 --reason   # from a user VLAN test host
nmap -Pn -sU -p 53,161 10.10.0.0/24
```

- Test from each zone to each other zone; compare with intended matrix
- Attack-path tools (BloodHound session/ACL paths + reachability) to confirm segmentation breaks paths
- Monitor denied flows for misconfigurations and attacker probing

---

## 7. Segmentation Matrix Template

| From \ To | Users | Admin | Servers | Tier 0 | DMZ | OT | Guest | Internet |
|---|---|---|---|---|---|---|---|---|
| Users | ✗ | ✗ | app ports | auth ports | ✗ | ✗ | ✗ | via proxy |
| Admin | mgmt | — | mgmt | mgmt (T0 PAW) | mgmt | mgmt | ✗ | limited |
| Servers | ✗ | ✗ | required | auth ports | required | ✗ | ✗ | allowlist |
| Guest | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |

---

## Engagement Cheatsheet

```text
inventory → flow map → zones/trust → default-deny ACLs (extended near source) → host firewalls east-west
→ ZTNA for remote → microsegmentation in DC/cloud/K8s → validate with scans → monitor denies
```

---

## Key References

- NIST SP 800-207 Zero Trust Architecture; CISA Zero Trust Maturity Model v2
- Cisco IOS ACL configuration guide; Huawei VRP ACL & traffic policy configuration guide
- Microsoft: Securing privileged access (PAW, tiering)
- Related: `defensive-l2-security`, `defensive-firewall-analysis`, `defensive-network-device-hardening`
