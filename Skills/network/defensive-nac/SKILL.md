---
name: defensive-nac
description: "Network access control: 802.1X port-based authentication, EAP methods (EAP-TLS recommended, PEAP-MSCHAPv2 and EAP-TTLS risks, TEAP), MAC Authentication Bypass for headless devices and its spoofing risk, RADIUS servers (Cisco ISE, Aruba ClearPass, FreeRADIUS, PacketFence, Microsoft NPS), Blast-RADIUS (CVE-2024-3596) mitigations with Message-Authenticator and RadSec, dynamic VLAN/dACL/SGT (TrustSec) authorization, posture assessment, guest and BYOD onboarding, profiling, Cisco IOS-XE and Huawei VRP switch configs, monitor/low-impact/closed deployment modes, and NAC logging/detections. Use when deploying or auditing NAC or wired/wireless port authentication."
---

# Network Access Control (NAC)

NAC decides what may connect and what it may reach. Done right, a rogue laptop plugged into a conference-room port gets nothing; an unpatched corporate laptop lands in a remediation VLAN; a printer reaches only its print server.

## Quick Workflow

1. Inventory endpoints by type (managed, BYOD, IoT/headless, guest)
2. Choose auth per type: EAP-TLS (managed), MAB + profiling (headless), portal (guest)
3. Deploy in **monitor mode** → low-impact → closed
4. Authorize with VLAN/dACL/SGT per role; add posture for managed devices
5. Log RADIUS accounting/auth to SIEM; detect anomalies

---

## 1. Authentication Methods

| Method | Use | Notes |
|---|---|---|
| EAP-TLS | Managed devices (machine + user certs) | Strongest; requires PKI + auto-enrollment |
| TEAP (RFC 7170) | Machine + user chaining (EAP chaining) | Supported by Windows 10 2004+ and ISE/ClearPass |
| PEAP-MSCHAPv2 | Password-based | Vulnerable to credential capture if server cert validation is not enforced on clients; MSCHAPv2 crackable; Credential Guard blocks MSCHAPv2 SSO in Windows 11 22H2+ |
| EAP-TTLS/PAP | Password-based | Same server-validation requirement |
| MAB | Printers, cameras, IoT | MAC is spoofable — pair with profiling and tight dACL |
| Web portal | Guests | Isolated guest VLAN/VRF, internet only |

---

## 2. Authorization

| Result | Example |
|---|---|
| Dynamic VLAN | Corp → VLAN 10, IoT → VLAN 50, quarantine → VLAN 999 |
| Downloadable ACL (dACL) | Printer may reach print server TCP 9100/631 only |
| Security Group Tag (Cisco TrustSec) / Huawei security group | Role-based policy independent of IP |
| Posture result | Non-compliant → remediation network |

---

## 3. Cisco IOS-XE (classic syntax)

```text
aaa new-model
aaa authentication dot1x default group ISE
aaa authorization network default group ISE
aaa accounting dot1x default start-stop group ISE
aaa server radius dynamic-author
 client 10.10.10.5 server-key <secret>
radius server ISE1
 address ipv4 10.10.10.5 auth-port 1812 acct-port 1813
 key <long-random-secret>
aaa group server radius ISE
 server name ISE1
dot1x system-auth-control
interface GigabitEthernet1/0/10
 switchport mode access
 switchport access vlan 10
 authentication host-mode multi-auth
 authentication order dot1x mab
 authentication priority dot1x mab
 authentication port-control auto
 authentication open                 ! monitor/low-impact phase only
 mab
 dot1x pae authenticator
 dot1x timeout tx-period 10
 spanning-tree portfast
```

Remove `authentication open` for closed mode. Newer IOS-XE uses IBNS 2.0 (`access-session`, policy-maps) — `authentication display new-style` converts.

---

## 4. Huawei VRP (unified mode, S-series)

```text
radius-server template RAD
 radius-server shared-key cipher <long-random-secret>
 radius-server authentication 10.10.10.5 1812
 radius-server accounting 10.10.10.5 1813
aaa
 authentication-scheme AUTH
  authentication-mode radius
 accounting-scheme ACCT
  accounting-mode radius
 domain corp
  authentication-scheme AUTH
  accounting-scheme ACCT
  radius-server RAD
dot1x-access-profile name D1X
mac-access-profile name MAB
authentication-profile name AP
 dot1x-access-profile D1X
 mac-access-profile MAB
 access-domain corp force
interface GigabitEthernet0/0/10
 port link-type access
 authentication-profile AP
```

Verify: `display access-user`, `display dot1x`. (Syntax varies by model/VRP version.)

---

## 5. RADIUS Security

| Risk | Mitigation |
|---|---|
| Blast-RADIUS (CVE-2024-3596) — MD5-based Response Authenticator forgery against RADIUS/UDP for non-EAP auth (PAP, CHAP, MS-CHAP, MAB) | Patch servers and NAS; require and validate `Message-Authenticator` on all packets; use RADIUS over TLS (RadSec, RFC 6614) or over IPsec; isolate RADIUS traffic on management network |
| Weak shared secrets | Long random secrets unique per NAS |
| Server cert not validated by supplicants | Enforce server cert validation + server name pinning via GPO/MDM wireless/wired profiles |
| Fallback to open | Critical auth VLAN for RADIUS-down scenarios should be restricted, not full access |

---

## 6. Deployment Phases

| Phase | Behavior | Goal |
|---|---|---|
| Monitor | Auth runs, failures still get access (`authentication open`) | Discover all devices, fix supplicants |
| Low-impact | Pre-auth ACL allows DHCP/DNS/PXE; full access after auth | Reduce risk with low disruption |
| Closed | No access until auth | Full enforcement |

---

## 7. Monitoring & Detections

| Signal | Meaning |
|---|---|
| Same MAC authenticating on two ports/switches | MAC spoofing / cloning |
| MAB device profile changes (printer suddenly looks like Windows) | Spoofed MAC |
| Repeated auth failures on a port | Rogue device / misconfigured supplicant |
| New device in critical auth VLAN when RADIUS healthy | Abuse of fallback |
| Rogue DHCP/RA on access ports | Combine with `defensive-l2-security` |
| Endpoints behind unmanaged switch/hub (multiple MACs on single-host port) | Unauthorized network extension |

---

## Engagement Cheatsheet

```text
endpoint inventory → EAP-TLS/TEAP (managed), MAB+profiling (headless), portal (guest) → monitor → low-impact → closed
→ VLAN/dACL/SGT authorization + posture → Blast-RADIUS: Message-Authenticator + RadSec + mgmt isolation → enforce supplicant server validation
→ detect MAC cloning, profile change, fallback abuse
```

---

## Key References

- IEEE 802.1X-2020; RFC 3748 (EAP), RFC 5216 (EAP-TLS), RFC 7170 (TEAP), RFC 6614 (RadSec); Blast-RADIUS (blastradius.fail, CVE-2024-3596)
- Cisco ISE and Huawei Agile Controller/iMaster NCE deployment guides
- Related: `defensive-l2-security`, `defensive-wireless-design`, `defensive-network-segmentation`
