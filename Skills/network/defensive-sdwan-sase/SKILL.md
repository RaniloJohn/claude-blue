---
name: defensive-sdwan-sase
description: "SD-WAN and SASE/SSE security: SASE components (SD-WAN plus SSE — secure web gateway, CASB, ZTNA, firewall-as-a-service, DLP, RBI), single-vendor vs multi-vendor SASE, SD-WAN overlay security (IPsec overlays, segmentation/VRFs, controller and orchestrator hardening as Tier 0 management plane, zero-touch provisioning risks), local internet breakout with cloud security, traffic steering and agent tamper protection, CASB API vs inline modes and shadow IT discovery, SSE policy design, logging into SIEM, migration from hub-and-spoke MPLS, and evaluation criteria. Use when designing, evaluating, or securing SD-WAN/SASE/SSE deployments."
---

# SD-WAN, SASE & SSE

SASE moves security enforcement from the data center to the cloud edge, close to users and branches. **SD-WAN** handles connectivity; **SSE** (Security Service Edge) delivers security services. Together they replace backhauling through a central firewall.

## Quick Workflow

1. Map users, branches, apps (SaaS vs private), and current backhaul paths
2. Define SSE policy (web, SaaS, private access, DLP) independent of location
3. Secure the SD-WAN fabric: overlay crypto, segmentation, controller hardening
4. Steer traffic (agents, tunnels from branch edges); enforce tamper protection
5. Integrate logs with SIEM and identity/EDR signals; migrate in phases

---

## 1. Components

| Component | Function |
|---|---|
| SD-WAN | Overlay WAN, path selection, local breakout, segmentation |
| SWG | URL/category filtering, malware scanning, TLS inspection for web |
| CASB | SaaS visibility and control (inline proxy + API scanning of data at rest) |
| ZTNA | Per-app private access (`defensive-remote-access-ztna`) |
| FWaaS | L3–L7 firewall for non-web traffic from branches/users |
| DLP | Content inspection across web, SaaS, email |
| RBI | Remote browser isolation for risky/uncategorized sites |
| DEM | Digital experience monitoring (performance) |

Single-vendor SASE simplifies policy and logging; multi-vendor (SD-WAN from one, SSE from another) avoids lock-in but needs integration work.

---

## 2. SD-WAN Fabric Security

| Area | Controls |
|---|---|
| Overlay | IPsec (AES-256-GCM), automated key rotation, certificate-based device identity |
| Segmentation | VRFs/VPNs per business segment (corp, guest, IoT, PCI) carried end-to-end |
| Controllers/orchestrators | Treat as Tier 0 management plane: no internet-exposed management UI, MFA, RBAC, dedicated admin network, patch on KEV timelines (SD-WAN managers/controllers have had exploited auth-bypass CVEs) |
| Zero-touch provisioning | Validate device serials/certificates; restrict ZTP to known devices; monitor new device enrollments |
| Branch edge | Local firewall policy, disable unused services, secure console ports, tamper-evident hardware |
| Local breakout | Only via SSE tunnels or local NGFW policy — never raw internet |
| Logs | Controller audit logs, config changes, device onboarding, tunnel status to SIEM |

---

## 3. SSE Policy Design

| Policy | Example |
|---|---|
| Web | Block malware/phishing/NRD; isolate uncategorized; TLS inspection with bypass list |
| SaaS (CASB inline) | Allow corporate tenant of M365/Google, block personal tenants (tenant restrictions headers); block uploads to unsanctioned storage |
| SaaS (CASB API) | Scan for public links, sensitive data, risky OAuth apps, misconfig |
| Private apps | ZTNA per app with posture |
| DLP | Block PII/PCI uploads to non-corporate destinations; coach users |
| Non-web | FWaaS: default deny outbound non-web except approved services |
| Identity-aware | Policies by group; risk signals from IdP/EDR adjust access (step-up, block) |

Tenant restrictions: Microsoft Tenant Restrictions v2, Google Workspace `X-GoogApps-Allowed-Domains` header — prevent data exfil to personal tenants.

---

## 4. Traffic Steering & Tamper Protection

- Endpoint agents (Zscaler Client Connector, Netskope Client, Cloudflare WARP, Entra Global Secure Access client, Prisma Access GlobalProtect) with uninstall/disable password and MDM enforcement
- Fail-closed for high-risk users or when off-network; captive portal handling
- Branch tunnels (IPsec/GRE) from SD-WAN edges to SSE PoPs with redundant PoPs
- Detect bypass: endpoints with agent disabled, direct internet traffic from branches, users on personal hotspots without agent

---

## 5. Shadow IT Discovery

CASB/SWG logs → SaaS app inventory with risk scores → sanction / tolerate / block decisions → feed third-party risk process (`defensive-frameworks`). Watch AI SaaS usage specifically (`defensive-ai-security`).

---

## 6. Logging & Detections

| Signal | Use |
|---|---|
| SWG/FWaaS logs with user identity | Same hunts as proxy logs (`defensive-proxy-tls-inspection`) |
| CASB alerts (mass download, impossible travel, risky OAuth) | Insider/compromise detection |
| ZTNA access logs | Remote access monitoring |
| Agent health/tamper events | Defense evasion |
| SD-WAN controller config changes | Infrastructure compromise |

---

## 7. Evaluation Criteria

PoP coverage near users (latency), TLS inspection capacity, policy unification across web/SaaS/private/DLP, log export (raw, near-real-time, to your SIEM), identity integrations, agent platform coverage (Windows/macOS/Linux/iOS/Android/ChromeOS), API for automation, data residency, vendor security posture (their own breach history and patch cadence).

---

## Engagement Cheatsheet

```text
map users/branches/apps → SSE policy (SWG + CASB inline/API + ZTNA + FWaaS + DLP + RBI) location-independent
→ SD-WAN overlay crypto + VRF segmentation + controllers as Tier 0 (no exposed mgmt, MFA, KEV patching, ZTP validation)
→ agent tamper protection + branch tunnels → tenant restrictions → shadow IT → SIEM integration → phased MPLS migration
```

---

## Key References

- Gartner SASE/SSE definitions (2019/2021); CISA/NSA guidance on network infrastructure; MEF SASE standards (MEF W117)
- Microsoft Tenant Restrictions v2 docs
- Related: `defensive-remote-access-ztna`, `defensive-proxy-tls-inspection`, `defensive-cspm`, `defensive-detect-exfiltration`, `defensive-zero-trust-architecture`
