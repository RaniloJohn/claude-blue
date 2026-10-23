---
name: defensive-ddos
description: "DDoS defense and response: attack classes (volumetric UDP/amplification via DNS, NTP, memcached, CLDAP, SSDP; protocol SYN/ACK floods, fragmentation; application-layer HTTP floods, HTTP/2 Rapid Reset CVE-2023-44487, slowloris; carpet bombing), IoT botnets, mitigation architecture (CDN/anycast, cloud scrubbing — Cloudflare, Akamai Prolexic, AWS Shield Advanced, Azure DDoS Protection, Google Cloud Armor), on-prem appliances, ISP coordination, RTBH (RFC 7999) and BGP Flowspec (RFC 8955), rate limiting and SYN cookies, WAF bot rules, origin IP protection, detection via NetFlow, DDoS runbook and testing. Use when preparing for or responding to a DDoS attack."
---

# DDoS Defense

You cannot out-provision a multi-terabit botnet on your own links. DDoS defense is mostly **preparation**: upstream mitigation contracted in advance, origin hidden, application tuned, and a runbook rehearsed.

## Quick Workflow

1. Classify exposure: which services are internet-facing and business critical
2. Put them behind CDN/anycast or a scrubbing service (always-on or on-demand)
3. Hide/lock origin; tune application and network rate limits
4. Prepare ISP coordination (RTBH, Flowspec) and a runbook with contacts
5. Detect early (flow, CDN analytics); rehearse annually

---

## 1. Attack Classes

| Class | Examples | Measured in | Mitigation layer |
|---|---|---|---|
| Volumetric | UDP floods; reflection/amplification via DNS, NTP (monlist), memcached, CLDAP, SSDP, CharGEN, WS-Discovery | Gbps/Tbps | Upstream scrubbing/anycast, ISP filtering |
| Protocol | SYN/ACK/RST floods, fragmented packet floods, Ping of Death variants | Mpps | SYN cookies, stateless filtering, scrubbing |
| Application (L7) | HTTP GET/POST floods, cache-busting, login/search endpoint abuse, HTTP/2 Rapid Reset (CVE-2023-44487), slowloris/slow POST | Requests/sec | CDN/WAF rate limiting, bot management, app tuning |
| Carpet bombing | Spreading across many IPs in a prefix | Gbps across range | Prefix-wide scrubbing |
| DNS-specific | Random subdomain (water torture) attacks on authoritative DNS | QPS | Anycast DNS provider, RRL |

Record-scale attacks in 2025 reached tens of Tbps from IoT botnets (Aisuru-class) — on-prem-only mitigation is not viable for large volumetric attacks.

---

## 2. Mitigation Architecture

| Option | When |
|---|---|
| CDN/reverse proxy with DDoS protection (Cloudflare, Akamai, Fastly, CloudFront + Shield) | Web/API services — always-on |
| Cloud scrubbing via BGP diversion (Akamai Prolexic, Cloudflare Magic Transit, Radware, NETSCOUT Arbor Cloud) | Whole prefixes, non-HTTP services |
| Cloud-native | AWS Shield Standard (automatic) / Advanced (DRT, cost protection), Azure DDoS Network/IP Protection, Google Cloud Armor (Adaptive Protection) |
| On-prem appliance | Low-volume and L7 attacks, hybrid with cloud signaling |
| ISP clean pipe | ISP-provided filtering upstream |

---

## 3. Network-Level Controls

| Control | Detail |
|---|---|
| Origin protection | Only allow CDN/scrubber IP ranges to reach origin (firewall/SG); never leak origin IP in DNS history, MX records, headers, or certificates |
| SYN cookies | `net.ipv4.tcp_syncookies=1`; firewall SYN proxy |
| Disable amplifiers you own | Close open resolvers, NTP monlist, memcached UDP, SSDP/CLDAP exposure |
| RTBH (RFC 7999 BLACKHOLE community 65535:666) | Sacrifice the target IP to save the rest of the link |
| BGP Flowspec (RFC 8955) | Push granular drop/rate-limit rules (e.g., UDP src port 123 to victim) to upstream routers |
| ACLs at edge | Drop traffic to unused ports/protocols early |
| Rate limits | ICMP, UDP fragments, DNS response rate limiting (RRL) |

---

## 4. Application-Level Controls

- WAF rate-based rules per IP/session/API key on expensive endpoints (login, search, checkout)
- Bot management / JS challenges / managed challenges for suspicious clients
- Caching: maximize cache hit ratio; normalize query strings to stop cache-busting
- Patch web servers/proxies for HTTP/2 Rapid Reset and similar (limit concurrent streams, stream reset rate)
- Autoscaling with limits (avoid cost DoS); graceful degradation (static fallback pages)
- Timeouts for slow clients (`client_body_timeout`, `header_timeout` in nginx; `RequestReadTimeout` in Apache)

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/s;
location /login { limit_req zone=login burst=10 nodelay; }
http2_max_concurrent_streams 128;
```

---

## 5. Detection

| Signal | Source |
|---|---|
| Sudden pps/bps surge to one destination | NetFlow/sFlow, router counters |
| Many sources, one destination, UDP from amplifier ports (53, 123, 389, 1900, 11211) | Flow |
| Spike in SYN without ACK | Firewall/flow |
| L7: request rate, error rate (5xx), latency, cache miss surge | CDN/WAF analytics, APM |
| Ransom DDoS (RDDoS) emails threatening attack | Email — often precedes demonstration attack |

DDoS can be a **smokescreen** for intrusion — keep monitoring other alerts during an attack.

---

## 6. Runbook

```text
1. Detect & confirm (flow/CDN dashboards) — record start time, target, vectors, volume
2. Declare incident; open bridge with provider (scrubbing/CDN) and ISP NOC
3. Activate mitigation: divert to scrubbing (on-demand), enable "under attack" mode, tighten WAF rate rules
4. Network: Flowspec/ACLs for clear vectors; RTBH for non-critical target IPs as last resort
5. Communicate: status page, customer support scripts
6. Monitor for collateral (legit traffic loss) and intrusion attempts in parallel
7. Stand down gradually; post-incident: vectors, peak, duration, mitigation time, cost; report to CERT if extortion
```

Do not pay RDDoS extortion; report to law enforcement/CERT (CERT-PH, CISA).

---

## 7. Testing

Contracted DDoS simulation with provider approval (unannounced testing against cloud providers violates terms), tabletop with network/app/comms teams, verify origin lockdown by attempting direct origin access from outside.

---

## Engagement Cheatsheet

```text
inventory critical internet services → CDN/anycast/scrubbing contract (always-on vs on-demand) → origin lockdown
→ SYN cookies, close own amplifiers, RTBH/Flowspec with ISP → WAF rate limits, bot mgmt, cache, HTTP/2 limits, slow-client timeouts
→ flow + CDN detection → runbook + comms → watch for smokescreen intrusion → test annually
```

---

## Key References

- CISA/FBI/MS-ISAC "Understanding and Responding to DDoS Attacks" (2024); RFC 7999; RFC 8955; RFC 4987 (SYN flood mitigations)
- CVE-2023-44487 (HTTP/2 Rapid Reset) advisories
- Related: `defensive-netflow-ndr`, `defensive-routing-security`, `defensive-waf`, `defensive-dns-security`
