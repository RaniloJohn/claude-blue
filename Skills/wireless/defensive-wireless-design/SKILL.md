---
name: defensive-wireless-design
description: "Secure enterprise wireless architecture: WPA3-Enterprise (incl. 192-bit mode) and WPA3-Personal (SAE), transition-mode risks, Protected Management Frames (802.11w), 802.1X with EAP-TLS vs PEAP-MSCHAPv2, RADIUS server certificate validation on clients, NAC and dynamic VLAN assignment, guest isolation and captive portals, identity PSK / per-user PSK, WPS disablement, IoT segmentation, management plane security for controllers, Bluetooth/BLE policy, and Wi-Fi 6E/7 security requirements. Use when designing or auditing Wi-Fi security."
---

# Secure Wireless Design

Wi-Fi security is mostly decided by the authentication method and whether clients validate the network they join. EAP-TLS with enforced server validation plus PMF defeats most real-world wireless attacks.

## Quick Workflow

1. Classify SSIDs: corporate, BYOD, guest, IoT
2. Choose auth per SSID (EAP-TLS > PEAP-MSCHAPv2 > iPSK/SAE > PSK)
3. Enforce client-side RADIUS certificate validation via MDM/GPO
4. Require PMF; disable WPS; avoid transition modes where possible
5. Segment with dynamic VLANs/roles; isolate guests and IoT
6. Harden controller/AP management; monitor with WIDS

---

## 1. SSID Design

| SSID | Auth | Encryption | Segmentation |
|---|---|---|---|
| Corp | WPA3-Enterprise, EAP-TLS (device/user certs) | AES-CCMP/GCMP, PMF required | Dynamic VLAN/role by identity/posture |
| BYOD | EAP-TLS via onboarding portal, or PEAP with strong validation | | Internet + limited apps |
| Guest | Open + OWE (Enhanced Open) or WPA3-SAE; captive portal | OWE encrypts without auth | Client isolation; internet only |
| IoT | Identity PSK (per-device keys) / MAB + WPA2/3-PSK | | Dedicated VLAN; allowlisted destinations |

Fewer SSIDs = less airtime overhead; use role-based policy instead of many SSIDs.

---

## 2. Authentication Methods

| Method | Strength | Risk |
|---|---|---|
| EAP-TLS | Mutual certificate auth; no passwords | PKI management |
| EAP-TEAP / EAP-TTLS with certs | Strong when configured well | Support varies |
| PEAP-MSCHAPv2 | Password-based | Credential capture by evil twin if clients don't validate server cert; MSCHAPv2 hashes crackable; Credential Guard on Windows blocks MSCHAPv2 SSO with saved domain creds |
| WPA3-SAE | Resistant to offline dictionary attacks | Transition mode allows WPA2 downgrade; early Dragonblood issues patched |
| WPA2-PSK | Shared secret | Offline cracking of handshake/PMKID; key sharing |
| Identity PSK (iPSK/PPSK/MPSK) | Per-device PSK | Better revocation than single PSK |

Client cert validation (Windows GPO/Intune Wi-Fi profile): specify trusted root CA, expected RADIUS server names, disable "prompt user to trust new servers".

---

## 3. Protocol Settings

```text
[ ] PMF (802.11w) = Required on WPA3; Optional only where legacy clients force WPA2 transition
[ ] WPS disabled
[ ] TKIP/WEP disabled
[ ] WPA3 transition mode only temporarily; separate WPA2-only legacy SSID if needed
[ ] 6 GHz (Wi-Fi 6E/7): WPA3 or OWE mandatory by spec
[ ] Broadcast/multicast filtering and client isolation on guest
[ ] 802.11r Fast Transition with care (FT-PSK increases offline attack surface)
[ ] Disable legacy data rates (performance + reduces rogue legacy clients)
```

---

## 4. RADIUS & NAC

- Redundant RADIUS (ISE, ClearPass, NPS, FreeRADIUS) with TLS certs from internal PKI
- Dynamic VLAN/ACL/role assignment via RADIUS attributes (`Tunnel-Private-Group-ID`, vendor role attributes)
- Posture checks (MDM compliance) for corp access
- RADIUS accounting to SIEM: who connected where, when, with what device

---

## 5. Controller & AP Hardening

- Management on dedicated VLAN; HTTPS/SSH only; no default creds; MFA/TACACS+ for admins
- Firmware patched (controllers and APs are network infrastructure — subscribe to PSIRT)
- Disable unused services (Telnet, HTTP, SNMPv1/2c → SNMPv3)
- AP wired ports: 802.1X supplicant on APs or MAB + port security to stop AP impersonation

---

## 6. Bluetooth / BLE

- Inventory BLE devices in sensitive areas; disable discoverability by default via MDM
- Patch Bluetooth stacks (frequent CVEs)
- Restrict Bluetooth file transfer on managed devices where policy requires

---

## 7. Audit Checklist

```text
[ ] Every SSID documented with auth/encryption/segment
[ ] No WPA2-PSK for corporate access
[ ] EAP server cert validation enforced on all managed clients (test with rogue RADIUS in lab)
[ ] PMF required
[ ] Guest isolated from internal networks (verify by scan)
[ ] IoT VLAN egress allowlisted
[ ] WIDS enabled and alerting
[ ] PSKs rotated on staff departure / exposure
```

---

## Engagement Cheatsheet

```text
SSID classes → EAP-TLS + enforced server validation → WPA3 + PMF + no WPS → role/VLAN segmentation
→ OWE/isolation for guest → iPSK for IoT → harden controllers → WIDS
```

---

## Key References

- Wi-Fi Alliance WPA3 Specification; IEEE 802.11w/802.1X
- Microsoft: Credential Guard and Wi-Fi (MSCHAPv2) considerations
- Vendor hardening guides (Cisco, Aruba, Huawei WLAN)
- Related: `defensive-wireless-ids`, `defensive-network-segmentation`, `defensive-l2-security`
