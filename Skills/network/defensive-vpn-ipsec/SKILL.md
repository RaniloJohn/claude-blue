---
name: defensive-vpn-ipsec
description: "VPN and IPsec security: IKEv2 vs IKEv1 (avoid aggressive mode and weak PSKs), recommended cryptographic suites (AES-GCM, SHA-2, DH groups 19/20/21, CNSA 2.0 post-quantum direction), certificate vs PSK authentication, site-to-site and remote-access configs on Cisco IOS-XE and Huawei VRP, WireGuard, SSL-VPN risk and migration (FortiOS SSL-VPN tunnel mode removal), VPN appliance hardening and patching against KEV-listed CVEs, MFA and posture for remote access VPN, split tunneling decisions, logging and detection of VPN abuse, and post-compromise integrity checks. Use when configuring, auditing, or hardening VPNs."
---

# VPN & IPsec Security

VPN concentrators sit on the internet and grant network-level access — a top-tier target class. Use strong IKEv2 crypto, certificate authentication, MFA for users, aggressive patching, and minimal post-auth reach.

## Quick Workflow

1. Inventory VPN endpoints, firmware, exposed services (portal, management)
2. Patch to fixed versions for all KEV CVEs; plan replacements for end-of-support devices (CISA BOD 26-02 model)
3. Enforce IKEv2 + strong suites; certificates over PSK
4. Remote access: MFA, posture, per-group ACLs; consider ZTNA migration
5. Log to SIEM and monitor (§6)

---

## 1. Crypto Baseline

| Parameter | Recommended | Avoid |
|---|---|---|
| IKE version | IKEv2 | IKEv1 (esp. aggressive mode — exposes PSK hash) |
| Encryption | AES-256-GCM (or AES-256-CBC + HMAC-SHA-384) | DES, 3DES, AES-CBC without integrity |
| PRF/Integrity | SHA-384 / SHA-512 | MD5, SHA-1 |
| DH/key exchange | Group 20 (ECP-384), 21 (ECP-521), 19 (ECP-256); hybrid ML-KEM where supported (RFC 9370 multiple key exchanges) | Groups 1, 2, 5, 22–24 |
| PFS | Enabled (same group) | Disabled |
| Authentication | Certificates (ECDSA/RSA ≥ 3072) | Short/shared PSKs |
| Lifetimes | IKE SA 24 h, Child SA 1–8 h | Very long lifetimes |

CNSA 2.0 (NSA) direction for national security systems: AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87 — plan PQ-capable VPN refreshes (`defensive-tls-pki`).

---

## 2. Cisco IOS-XE Site-to-Site (IKEv2, VTI)

```text
crypto ikev2 proposal PROP-GCM
 encryption aes-gcm-256
 prf sha384
 group 20
crypto ikev2 policy POL
 proposal PROP-GCM
crypto ikev2 keyring KR
 peer SITE-B
  address 198.51.100.2
  pre-shared-key local <long-random-64+>
  pre-shared-key remote <long-random-64+>
crypto ikev2 profile PROF
 match identity remote address 198.51.100.2 255.255.255.255
 authentication remote pre-share
 authentication local pre-share
 keyring local KR
 lifetime 86400
crypto ipsec transform-set TS esp-gcm 256
 mode tunnel
crypto ipsec profile IPSEC
 set transform-set TS
 set pfs group20
 set ikev2-profile PROF
interface Tunnel0
 ip address 172.16.0.1 255.255.255.252
 tunnel source GigabitEthernet0/0/0
 tunnel mode ipsec ipv4
 tunnel destination 198.51.100.2
 tunnel protection ipsec profile IPSEC
```

Prefer `authentication remote rsa-sig` / `ecdsa-sig` with a PKI trustpoint over PSK. Verify: `show crypto ikev2 sa detailed`, `show crypto ipsec sa`.

---

## 3. Huawei VRP Site-to-Site (IKEv2)

```text
ike proposal 10
 encryption-algorithm aes-256
 dh group20
 authentication-algorithm sha2-384
 integrity-algorithm hmac-sha2-384
 prf hmac-sha2-384
ike peer SITE-B
 undo version 1
 pre-shared-key cipher <long-random-64+>
 ike-proposal 10
 remote-address 198.51.100.2
ipsec proposal P1
 esp authentication-algorithm sha2-384
 esp encryption-algorithm aes-256
acl number 3001
 rule 5 permit ip source 10.1.0.0 0.0.255.255 destination 10.2.0.0 0.0.255.255
ipsec policy MAP 10 isakmp
 security acl 3001
 ike-peer SITE-B
 proposal P1
 pfs dh-group20
interface GigabitEthernet0/0/1
 ipsec policy MAP
```

Verify: `display ike sa`, `display ipsec sa`. (Syntax varies across AR/USG/NE platforms and VRP versions — check the platform guide.)

---

## 4. WireGuard

```ini
[Interface]
PrivateKey = <server-private>
Address = 10.200.0.1/24
ListenPort = 51820
[Peer]
PublicKey = <client-public>
PresharedKey = <optional-psk-for-pq-hardening>
AllowedIPs = 10.200.0.10/32
```

Strengths: small codebase, modern crypto (Curve25519, ChaCha20-Poly1305). Gaps: no built-in user auth/MFA or posture — add via management plane (Tailscale/Netbird/Headscale SSO) or gateway. Rotate keys; restrict `AllowedIPs`.

---

## 5. SSL-VPN & Appliance Risk

- SSL-VPN portals (Fortinet, Ivanti Connect Secure, Pulse, Palo Alto GlobalProtect, Cisco ASA WebVPN, SonicWall, Citrix) are repeatedly exploited pre-auth; many appear in CISA KEV
- Fortinet has moved customers from SSL-VPN tunnel mode to IPsec/ZTNA (removed in FortiOS 7.6.3 — verify for your model)
- After a critical advisory: patch → run vendor integrity checker (e.g., Ivanti ICT, Cisco ASA guidance under CISA ED 25-03) → hunt for webshells/config changes → rotate credentials and certificates stored on the device → terminate sessions
- Never expose the management interface; restrict portal by geo/source where feasible

---

## 6. Monitoring

| Signal | Why |
|---|---|
| Auth failures spike / password spray against portal | Credential attacks |
| Success from hosting ASN / new country / impossible travel | Stolen creds |
| Same user, multiple concurrent sessions | Session theft |
| VPN IP pool address performing scanning/admin protocol fan-out | Post-auth lateral movement |
| Config changes, new local admins on appliance | Compromise |
| Appliance outbound connections to unusual IPs | Implant C2 |
| IKE negotiations with weak proposals | Misconfigured or downgrade attempts |

---

## 7. Split Tunneling

Full tunnel: all traffic inspected centrally, higher load. Split tunnel: SaaS direct, internal via tunnel — pair with endpoint SWG/SSE agent so internet traffic is still filtered. Never allow split-tunnel with local LAN access to untrusted networks for admin devices.

---

## Engagement Cheatsheet

```text
inventory + KEV patch + EoS replacement → IKEv2 only, AES-GCM-256, SHA-384, DH 20/21/19, PFS, certs > PSK
→ Cisco/Huawei/WireGuard configs → SSL-VPN → IPsec/ZTNA migration → post-advisory integrity check + cred/cert rotation
→ MFA + posture + per-group ACL → monitor sprays, geo/ASN, concurrent sessions, pool-IP fan-out, appliance config changes
```

---

## Key References

- NSA/CISA "Selecting and Hardening Remote Access VPN Solutions" (2021); NIST SP 800-77 Rev 1 (IPsec VPNs); RFC 7296 (IKEv2); RFC 9370
- NSA CNSA 2.0; CISA KEV; CISA ED 25-03; CISA BOD 26-02
- Related: `defensive-remote-access-ztna`, `defensive-incident-response`, `defensive-network-device-hardening`, `defensive-tls-pki`
