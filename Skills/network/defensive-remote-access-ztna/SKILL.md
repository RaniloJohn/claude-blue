---
name: defensive-remote-access-ztna
description: "Secure remote access design and monitoring: ZTNA and identity-aware proxies (Zscaler Private Access, Cloudflare Access, Microsoft Entra Private Access, Google IAP/BeyondCorp, Tailscale/Netbird), migrating from VPN, RDP Gateway and bastion/jump hosts (Azure Bastion, AWS SSM Session Manager, GCP IAP TCP forwarding), third-party/vendor remote access with PAM and session recording, RMM tool governance (allowlisting, LOLRMM), securing exposed RDP/SSH, device posture checks, conditional access for remote access, logging and detections for remote access abuse, and Scattered Spider-style help-desk and RMM tradecraft defenses. Use when designing or reviewing remote access or vendor access."
---

# Remote Access & ZTNA

Remote access is one of the top initial access vectors: exploited VPN appliances, exposed RDP, stolen VPN credentials, and abused RMM tools. Move to **per-application, identity- and device-verified access** with no inbound-exposed services.

## Quick Workflow

1. Inventory every remote access path (VPNs, RDP/SSH exposure, RMM tools, vendor portals, cloud consoles)
2. Close exposed RDP/SSH/SMB; put admin protocols behind bastion/ZTNA
3. Migrate user apps to ZTNA per application; shrink VPN to legacy cases
4. Vendor access via PAM with approval, MFA, recording, time limits
5. Govern RMM: one sanctioned tool, block the rest
6. Monitor (§5)

---

## 1. Options

| Use case | Recommended pattern |
|---|---|
| Users → internal web apps | ZTNA / identity-aware proxy (ZPA, Cloudflare Access, Entra Private Access, Google IAP) |
| Users → legacy thick-client apps | ZTNA with app connectors (TCP/UDP per-app), or VPN with per-group ACLs |
| Admins → servers | Bastion (Azure Bastion, AWS SSM Session Manager, GCP IAP TCP forwarding) or PAM jump host; no direct RDP/SSH from internet |
| Vendors → specific systems | PAM vendor portal (CyberArk Vendor PAM, BeyondTrust PRA, Delinea) with just-in-time approval and recording |
| Device-to-device mesh | WireGuard-based overlays (Tailscale, Netbird) with ACLs and SSO — govern centrally |
| IT support → user endpoints | One sanctioned RMM with SSO + MFA + allowlisted technicians |

---

## 2. Hardening Exposed Services (if unavoidable)

| Service | Minimum |
|---|---|
| RDP | Never directly internet-exposed; RD Gateway with MFA (NPS extension/Entra), NLA required, account lockout, restricted user groups |
| SSH | Keys only (`PasswordAuthentication no`), `PermitRootLogin no`, MFA via PAM module or certificates (SSH CA), allowlist sources, `MaxAuthTries 3` |
| VPN | Patched within KEV SLA, MFA (phishing-resistant preferred), certificate-based device auth, posture checks, management interface not exposed, logs to SIEM |
| Citrix/VDI gateways | Patch (Citrix Bleed CVE-2023-4966, Citrix Bleed 2 CVE-2025-5777), terminate sessions after patching to kill stolen session tokens |

---

## 3. Posture & Conditional Access

Signals: managed/compliant device, EDR running and healthy, OS patch level, disk encryption, certificate present, user risk, location. Example Entra CA for Private Access apps: require compliant device + phishing-resistant MFA; block high-risk users; session lifetime 8–12 h.

---

## 4. RMM Governance

| Control | Detail |
|---|---|
| Single approved RMM | Document it; SSO + MFA for console |
| Block others | App control (WDAC/AppLocker) + DNS/proxy blocking of RMM vendor domains (LOLRMM list) |
| Detect installs | New services/processes for AnyDesk, ScreenConnect, TeamViewer, Atera, Splashtop, NetSupport, MeshCentral, SimpleHelp, Level, Action1 |
| Portable versions | Block execution from user-writable paths |
| MSP access | Contractual MFA, dedicated accounts, logging delivered to you |

Scattered Spider pattern (CISA/FBI July 2025): help desk impersonation → MFA reset → attacker installs RMM/tunnels (AnyDesk, TeamViewer, ScreenConnect, Ngrok, Tailscale, Teleport) → AWS SSM / ESXi → data theft + DragonForce encryption. Counter: verified help-desk identity procedures (callback to known number, manager approval, video verification), phishing-resistant MFA, RMM allowlisting, alert on new MFA registrations followed by remote tool installs.

---

## 5. Monitoring

| Signal | Source |
|---|---|
| VPN/ZTNA login from new country/ASN/hosting provider | VPN/ZTNA logs + enrichment |
| Concurrent sessions from distant locations | VPN logs |
| VPN logins for disabled/terminated users | HR feed correlation |
| Successful login after MFA reset within 24 h | IdP audit + VPN logs |
| RDP 4624 type 10 from non-gateway sources | Windows Security |
| SSH `Accepted password` on hosts configured for keys | auth.log |
| New RMM tool execution or domain contact | EDR, DNS, proxy |
| Bastion/SSM sessions outside change windows | CloudTrail `StartSession`, Bastion logs |
| Vendor sessions without ticket | PAM logs |

---

## 6. Migration Plan (VPN → ZTNA)

1. Inventory apps used over VPN (VPN flow logs)
2. Deploy connectors; publish top web apps via ZTNA
3. Pilot group; measure; expand
4. Move thick-client apps; leave VPN only for exceptions with documented owners
5. Remove broad VPN access; decommission or restrict concentrator (management never exposed)

---

## Engagement Cheatsheet

```text
inventory paths → kill exposed RDP/SSH/SMB → admins via bastion/SSM/IAP/PAM → users via per-app ZTNA + posture CA
→ vendors via PAM JIT + recording → one RMM, block LOLRMM rest → help-desk verification → monitor geo/ASN, post-MFA-reset, RMM installs
```

---

## Key References

- CISA/FBI Scattered Spider advisory (updated July 29, 2025); CISA "Guide to Securing Remote Access Software" (2023); LOLRMM project
- NIST SP 800-46 Rev 2 (telework); NIST SP 800-207
- Related: `defensive-zero-trust-architecture`, `defensive-vpn-ipsec`, `defensive-ad-hardening`, `defensive-phishing-triage`, `defensive-incident-response`
