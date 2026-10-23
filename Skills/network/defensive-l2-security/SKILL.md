---
name: defensive-l2-security
description: "Layer 2 and campus access-layer security on Cisco IOS/IOS-XE and Huawei VRP: DHCP snooping, Dynamic ARP Inspection, IP Source Guard, port security (sticky MAC, violation modes), BPDU Guard/BPDU protection, Root Guard, Loop Guard, storm control, VLAN hopping prevention (DTP off, native VLAN, trunk pruning), private VLANs, IPv6 First Hop Security (RA Guard, DHCPv6 Guard), 802.1X/MAB NAC with RADIUS (ISE, NPS, FreeRADIUS), plus detection of ARP spoofing, rogue DHCP, LLMNR/NBT-NS/mDNS poisoning, and MAC flooding. Use when hardening switches or investigating LAN attacks."
---

# Layer 2 Security

Most LAN attacks (ARP spoofing, rogue DHCP, LLMNR poisoning, VLAN hopping, MAC flooding) exploit trust at the access layer. Switch features stop them cheaply; host settings close the rest.

## Quick Workflow

1. Access ports: static access mode, port security, BPDU Guard, storm control
2. Enable DHCP snooping → DAI → IP Source Guard (in that order; DAI/IPSG depend on the snooping binding table)
3. Trunks: explicit allowed VLANs, unused native VLAN, DTP off
4. IPv6 FHS if IPv6 is enabled (it is, by default, on hosts)
5. 802.1X/MAB for port authentication
6. Disable LLMNR/NBT-NS/mDNS on hosts; detect poisoning attempts

---

## 1. Cisco IOS/IOS-XE

```text
! --- DHCP snooping ---
ip dhcp snooping
ip dhcp snooping vlan 10,20,30
no ip dhcp snooping information option          ! if relay/option82 causes issues
interface Gi1/0/48
 description UPLINK
 ip dhcp snooping trust
 ip arp inspection trust
!
! --- DAI ---
ip arp inspection vlan 10,20,30
ip arp inspection validate src-mac dst-mac ip
!
! --- Access port template ---
interface range Gi1/0/1-46
 switchport mode access
 switchport access vlan 20
 switchport nonegotiate
 switchport port-security
 switchport port-security maximum 2
 switchport port-security mac-address sticky
 switchport port-security violation restrict
 spanning-tree portfast
 spanning-tree bpduguard enable
 storm-control broadcast level 1.00
 storm-control multicast level 2.00
 storm-control action trap
 ip verify source                                ! IP Source Guard
 ip dhcp snooping limit rate 15
 no cdp enable
!
! --- Trunks ---
interface Gi1/0/48
 switchport mode trunk
 switchport nonegotiate
 switchport trunk native vlan 999                ! unused, not routed
 switchport trunk allowed vlan 10,20,30
 spanning-tree guard root                        ! on ports toward access switches (not toward root)
!
! --- Unused ports ---
interface range Gi1/0/47
 switchport mode access
 switchport access vlan 998
 shutdown
!
vtp mode transparent
errdisable recovery cause psecure-violation bpduguard dhcp-rate-limit arp-inspection
errdisable recovery interval 300
```

IPv6 RA Guard:

```text
ipv6 nd raguard policy HOSTS
 device-role host
interface range Gi1/0/1-46
 ipv6 nd raguard attach-policy HOSTS
```

802.1X + MAB (IOS-XE, classic syntax):

```text
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
dot1x system-auth-control
radius server ISE1
 address ipv4 10.10.1.50 auth-port 1812 acct-port 1813
 key <secret>
interface Gi1/0/5
 authentication port-control auto
 authentication order dot1x mab
 mab
 dot1x pae authenticator
```

---

## 2. Huawei VRP (S-series)

```text
dhcp enable
dhcp snooping enable
vlan batch 10 20 30
vlan 20
 dhcp snooping enable
#
interface GigabitEthernet0/0/24
 description UPLINK
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
 undo port trunk allow-pass vlan 1
 dhcp snooping trusted
#
interface GigabitEthernet0/0/1
 port link-type access
 port default vlan 20
 stp edged-port enable
 port-security enable
 port-security max-mac-num 2
 port-security mac-address sticky
 port-security protect-action restrict
 arp anti-attack check user-bind enable          ! DAI equivalent (uses snooping bindings)
 ip source check user-bind enable                ! IP Source Guard equivalent
 storm-control broadcast min-rate 100 max-rate 200
#
stp bpdu-protection                               ! shuts edge ports receiving BPDUs
interface GigabitEthernet0/0/23
 stp root-protection
```

Verify command syntax for your VRP version and model (S5700/S6700 vs newer CloudEngine campus); NAC on newer VRP uses unified authentication profiles (`authentication-profile`, `dot1x-access-profile`, `mac-access-profile`).

---

## 3. Verification

| Cisco | Huawei |
|---|---|
| `show ip dhcp snooping binding` | `display dhcp snooping user-bind all` |
| `show ip arp inspection statistics` | `display arp anti-attack statistics check user-bind` |
| `show port-security interface Gi1/0/1` | `display port-security` / `display mac-address sticky` |
| `show spanning-tree summary` | `display stp brief` |
| `show interfaces status err-disabled` | `display error-down recovery` |
| `show authentication sessions` | `display access-user` |

---

## 4. Attack → Control Map

| Attack | Control | Detection |
|---|---|---|
| ARP spoofing / MITM | DAI | DAI drop logs; Zeek/arpwatch MAC-IP flip alerts |
| Rogue DHCP | DHCP snooping (untrusted ports) | Snooping drops; multiple DHCP servers seen |
| MAC flooding | Port security max MAC | Violation logs/traps |
| VLAN hopping (DTP / double tagging) | `nonegotiate`, access mode, unused native VLAN | Trunk negotiation attempts on access ports |
| STP manipulation | BPDU Guard / BPDU protection, Root Guard | err-disable events |
| IP spoofing | IP Source Guard | IPSG drops |
| Rogue IPv6 RA / DHCPv6 (mitm6) | RA Guard, DHCPv6 Guard; disable IPv6 if unused (or manage it properly) | RA from non-router ports |
| LLMNR / NBT-NS / mDNS poisoning (Responder) | Host: disable LLMNR (GPO), disable NetBIOS over TCP/IP, disable mDNS where unneeded; SMB signing required | Honey name queries: canary hostname lookups answered by unexpected host |
| Rogue device | 802.1X/MAB, profiling | NAC auth failures, unknown MACs |

---

## 5. Detection on Hosts/Network

- MDI / NDR products flag LLMNR/NBT-NS responders directly where deployed
- PCAP/Zeek: one host sending LLMNR (udp/5355) or NBNS (udp/137) **responses** for many different names to many clients
- Honey query technique: a scheduled script resolves a nonexistent name (`fileshare-old`) via LLMNR/NBT-NS; any response = poisoner present.

---

## Engagement Cheatsheet

```text
access template (mode access, nonegotiate, port-security, portfast+BPDU guard, storm control)
→ DHCP snooping → DAI → IPSG → trunks (allowed VLANs, unused native) → RA Guard → 802.1X/MAB
→ host LLMNR/NBT-NS/mDNS off + SMB signing → detect via drops, err-disable, honey queries
```

---

## Key References

- Cisco Catalyst Security Configuration Guides (DHCP snooping, DAI, IPSG, port security, FHS)
- Huawei S-series Configuration Guide — Security (DHCP snooping, ARP security, IPSG, port security, NAC)
- CIS Cisco IOS Benchmark
- Related: `defensive-network-segmentation`, `defensive-network-device-hardening`, `defensive-wireless-design`
