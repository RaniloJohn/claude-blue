---
name: defensive-proxy-tls-inspection
description: "Secure web gateway, forward proxy, and TLS inspection: explicit vs transparent proxy, PAC files and WPAD risks, Squid configuration and access logs, cloud SWG/SSE (Zscaler, Netskope, Cloudflare Gateway, Microsoft Entra Internet Access), URL categorization and newly-registered-domain policy, file type and download controls, user identity in proxy logs, TLS interception architecture (internal CA, certificate deployment, bypass lists for privacy/pinned apps), TLS 1.3 and Encrypted Client Hello visibility impact, QUIC/HTTP3 blocking to force TCP, proxy log hunting (rare user agents, uploads, uncategorized domains), and privacy/legal considerations. Use when designing web egress control, deploying TLS inspection, or investigating with proxy logs."
---

# Proxy, SWG & TLS Inspection

Forcing web egress through a gateway gives you **policy** (block categories, risky downloads), **identity** (which user), and **visibility** (URL, user agent, bytes). TLS inspection extends that to encrypted content — at real cost in complexity and privacy.

## Quick Workflow

1. Decide topology: on-prem proxy, cloud SWG/SSE, or both (roaming users)
2. Enforce: block direct outbound 80/443 except from proxies; block QUIC (UDP 443) to force TCP
3. Policy: categories, NRD, uncategorized, file types, upload limits
4. TLS inspection: internal CA, deploy trust, bypass list, legal review
5. Log with user identity to SIEM; hunt (§6)

---

## 1. Proxy Modes

| Mode | Pros | Cons |
|---|---|---|
| Explicit (browser/OS configured) | User auth (Kerberos/NTLM), clear failures | Non-proxy-aware apps bypass |
| Transparent (intercept via firewall/WCCP/PBR) | No client config | Harder auth; TLS needs SNI-based or full interception |
| PAC file | Flexible routing | Host the PAC internally over HTTPS; avoid WPAD auto-discovery (spoofable via LLMNR/mDNS/DHCP/DNS) |
| Cloud SWG agent (Zscaler ZCC, Netskope client, WARP, Global Secure Access client) | Covers roaming devices | Agent tamper protection required |

Disable WPAD auto-detection if not used (GPO / `WinHttpAutoProxySvc` considerations) and register a `wpad` DNS record you control or block it in the global query block list (Windows DNS blocks `wpad` and `isatap` by default).

---

## 2. Squid Essentials

```text
# /etc/squid/squid.conf (excerpts)
acl localnet src 10.0.0.0/8
acl SSL_ports port 443
acl CONNECT method CONNECT
acl blocked_cats dstdomain "/etc/squid/blocked_domains.txt"
http_access deny CONNECT !SSL_ports
http_access deny blocked_cats
http_access allow localnet
http_access deny all
logformat sec %ts.%03tu %>a %un %rm "%ru" %>Hs %<st %>st "%{User-Agent}>h" %ssl::>sni
access_log /var/log/squid/access.log sec
```

TLS bump (`ssl_bump peek` → `bump` / `splice`) requires an internal CA and careful bypass ACLs.

---

## 3. Policy Baseline

| Policy | Setting |
|---|---|
| Malware, phishing, C2, cryptomining categories | Block |
| Newly registered domains (< 30 days) | Block or isolate (remote browser isolation) |
| Uncategorized / parked / dynamic DNS | Block for servers; warn/isolate for users |
| File downloads | Block executables/scripts/archives from uncategorized; sandbox from others |
| Uploads | Limit to sanctioned SaaS; DLP inspection |
| Personal cloud storage, paste sites, file sharing | Block or read-only per policy |
| Anonymizers, VPNs, Tor | Block |
| Servers | Default deny; allowlist update and API domains |

---

## 4. TLS Inspection

| Element | Guidance |
|---|---|
| CA | Dedicated intermediate from internal PKI (HSM-backed); not used for anything else |
| Trust deployment | GPO/Intune/MDM to OS and browser stores (Firefox `security.enterprise_roots.enabled`) |
| Bypass list | Banking/financial, healthcare, government ID services, certificate-pinned apps (some update services, mobile apps), mutual-TLS endpoints, privacy-sensitive categories |
| Upstream validation | Proxy must validate server certs strictly (reject expired/self-signed/name mismatch) — otherwise it hides MITM |
| Protocols | Support TLS 1.3; block downgrade; enforce modern ciphers upstream |
| Performance | Inspection is CPU-heavy — size appliances or use cloud SSE |
| Legal | Notify users (AUP), works council/union consultation where required, data protection impact assessment (e.g., GDPR, PH Data Privacy Act) |

### Visibility headwinds

| Change | Effect | Mitigation |
|---|---|---|
| TLS 1.3 | Server cert encrypted; passive inspection sees less | Full proxy interception or endpoint telemetry |
| Encrypted Client Hello (ECH) | SNI hidden from passive observers | Proxy terminating TLS still sees names; block ECH-capable DoH configs; endpoint DNS logs |
| QUIC / HTTP/3 (UDP 443) | Bypasses many TCP proxies | Block UDP 443 egress; browsers fall back to TCP |
| Certificate pinning | Breaks under interception | Bypass list |

---

## 5. Logging Fields

Timestamp, user, source IP, method, full URL (or host for non-inspected), status, bytes in/out, user agent, category, action, SNI, server IP, content type, file hash (if scanned). Forward to SIEM with ≥ 90 days hot retention.

---

## 6. Hunting with Proxy Logs

| Hunt | Logic |
|---|---|
| Rare user agents | UA seen on < 3 hosts fleet-wide |
| Non-browser UAs from user workstations | `python-requests`, `curl`, `Go-http-client`, PowerShell UA |
| Uploads | Large POST/PUT to uncategorized or personal storage |
| Beaconing | Regular intervals to same host (see C2 pack) |
| Direct IP URLs | `http://203.0.113.5/...` |
| Long URLs / Base64 in query | Data smuggling |
| Blocked-then-allowed | User retrying via different category domains |
| Auth failures | Proxy 407 storms from malware without credentials |

```spl
index=proxy
| stats dc(src) as hosts values(src) as srcs count by http_user_agent
| where hosts < 3 AND count > 20
| sort - count
```

---

## Engagement Cheatsheet

```text
topology (on-prem/cloud SWG/agent) → block direct 80/443 + UDP 443 → avoid WPAD → category/NRD/file/upload policy
→ TLS inspection (dedicated CA, trust deploy, bypass list, strict upstream validation, legal) → TLS1.3/ECH/QUIC compensations
→ log user+URL+UA+bytes → hunt rare UA, uploads, beacons, IP URLs
```

---

## Key References

- NSA "Managing Risk from Transport Layer Security Inspection" (2019); NIST NCCoE TLS 1.3 visibility work (SP 1800-37)
- Squid docs; IETF ECH specification
- Related: `defensive-dns-security`, `defensive-sdwan-sase`, `defensive-detect-exfiltration`, `defensive-detect-command-and-control`, `defensive-tls-pki`
