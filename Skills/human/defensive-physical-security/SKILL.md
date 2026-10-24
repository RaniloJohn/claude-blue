---
name: defensive-physical-security
description: "Physical security as part of cyber defense: layered physical controls (perimeter, building, floors, server rooms, racks), access control systems (badges, PIN, biometrics, anti-passback, mantraps), visitor management, tailgating prevention, CCTV and retention, protecting network jacks and wireless (port security/NAC, rogue AP detection), data center and wiring closet security, equipment and media handling and destruction (NIST SP 800-88), clean desk and screen lock, device theft and travel, hardware implants and rogue devices (drop boxes, keystroke injectors), physical security logging integrated with SIEM, and physical penetration test considerations. Use when assessing or improving physical controls that protect IT systems."
---

# Physical Security for Cyber Defense

Physical access defeats most logical controls: a plugged-in drop box bypasses the perimeter firewall; a stolen unencrypted laptop bypasses MFA. Treat physical security as a layer in defense in depth.

## Quick Workflow

1. Map physical zones and what IT assets each contains
2. Apply layered controls per zone (§1)
3. Neutralize network-level physical risks (NAC, disabled jacks, rogue device detection)
4. Secure media lifecycle and disposal
5. Integrate badge/CCTV logs with SIEM; test periodically

---

## 1. Layers

| Layer | Controls |
|---|---|
| Perimeter | Fencing, lighting, signage, guarded entry, vehicle barriers (risk-based) |
| Building entry | Badge access, reception, visitor sign-in with escort, turnstiles/anti-tailgating |
| Internal zones | Floor/zone badge restrictions, locked offices for sensitive functions |
| Server rooms / wiring closets | Restricted badge + PIN or biometric, mantrap for data centers, CCTV, access logs reviewed |
| Racks / devices | Locked racks, cage separation in colocation, tamper-evident seals, console ports secured |
| Endpoints | Full-disk encryption, screen lock, cable locks in public areas |

---

## 2. Access Control Systems

- Unique badges per person; revoke same day at offboarding (HR feed integration)
- Anti-passback, time-of-day restrictions, alarms on door forced/held open
- Legacy 125 kHz proximity cards are easily cloned — prefer modern encrypted smart credentials (e.g., DESFire EV2/EV3, SEOS) or mobile credentials
- Review access lists for sensitive rooms quarterly

---

## 3. Network-Level Physical Risks

| Risk | Control |
|---|---|
| Rogue device in open network jack | 802.1X/NAC (`defensive-nac`), disable unused ports, port security, guest VLAN for unauthenticated |
| Drop box with LTE backhaul | Rogue device detection (new MACs, NAC profiling), physical inspections, RF detection for cellular devices in sensitive areas |
| Rogue wireless AP | WIDS/WIPS (`defensive-wireless-ids`) |
| Keystroke injectors / USB implants | USB device control (`defensive-usb-device-control`), visual inspection of keyboards/cables in sensitive spaces |
| Console port access on network gear | Locked rooms, console passwords, AAA on console |

---

## 4. Media & Equipment

- Asset tags and inventory; check-in/out for loaner devices
- Sanitization per NIST SP 800-88 Rev 2 (clear, purge, destroy) before reuse/disposal; certificates of destruction from vendors
- SSDs: cryptographic erase / manufacturer secure erase or physical destruction
- Clean desk policy for printouts; secure print release; shredding

---

## 5. Monitoring & Integration

| Signal | Use |
|---|---|
| Badge logs → SIEM | Impossible travel (badge in office + VPN login abroad), after-hours server room access, access by terminated staff |
| Door forced/held alarms | SOC/guards response |
| CCTV | Retention per policy (e.g., 30–90 days) for investigations |
| Visitor logs | Correlate with incidents |

---

## 6. Testing

Physical penetration tests and social engineering assessments with explicit written authorization letters carried by testers, scope (buildings, hours, methods), emergency contacts, and legal review; coordinate with security guards' chain of command (without revealing timing if testing response).

---

## Engagement Cheatsheet

```text
zone map → layered controls (perimeter, entry, zones, server rooms, racks, endpoints) → modern encrypted badges + same-day revocation
→ NAC/disabled jacks/rogue device & AP detection/USB control → media sanitization (NIST 800-88) → badge & alarm logs in SIEM → authorized physical tests
```

---

## Key References

- NIST SP 800-88 Rev 2 (Media Sanitization); NIST SP 800-116 (PIV in physical access); ISO/IEC 27001:2022 Annex A physical controls (A.7)
- Related: `defensive-nac`, `defensive-usb-device-control`, `defensive-wireless-ids`, `defensive-security-awareness`
