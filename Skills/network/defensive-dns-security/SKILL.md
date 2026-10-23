---
name: defensive-dns-security
description: "DNS security operations and hardening: protective DNS and RPZ (response policy zones), sinkholing, resolver logging (Windows DNS Analytical log, BIND query logs, Unbound, Infoblox, Route 53 Resolver query logs, Azure DNS security policy), Sysmon 22 and DNS-Client logging, DNSSEC signing and validation, DoH/DoT policy and blocking unsanctioned encrypted DNS, zone transfer restrictions and TSIG, open resolver and amplification prevention, dangling DNS and subdomain takeover, CAA records, domain registrar lock and monitoring, typosquat/lookalike detection, passive DNS for investigations, and DNS-based detections (tunneling, DGA, newly registered domains). Use when securing DNS infrastructure, deploying protective DNS, or investigating DNS activity."
---

# DNS Security

DNS is both a control point (block bad destinations for every device at once) and a top-tier sensor (every connection usually starts with a lookup). Force all clients through resolvers you log and filter.

## Quick Workflow

1. Force DNS through internal resolvers; block direct outbound 53/853 and unsanctioned DoH
2. Enable query logging on resolvers and forward to SIEM
3. Add protective DNS / RPZ filtering
4. Harden authoritative DNS (zone transfers, DNSSEC, registrar lock, CAA)
5. Monitor for tunneling, DGA, newly registered domains, and dangling records

---

## 1. Resolver Logging

| Platform | How |
|---|---|
| Windows DNS Server | Enable `Microsoft-Windows-DNSServer/Analytical` (EID 256 query received, 257 response) or debug logging; ship via Windows Event Forwarding/agent |
| Windows clients | Sysmon EID 22 (DnsQuery) with process; `Microsoft-Windows-DNS-Client/Operational` (EID 3006/3008) |
| BIND | `logging { channel q { file "/var/log/named/query.log" versions 10 size 100m; print-time yes; }; category queries { q; }; };` |
| Unbound | `log-queries: yes`, `log-replies: yes` (or dnstap) |
| dnstap | Structured binary logging (BIND, Unbound, Knot, CoreDNS) — preferred at scale |
| AWS | Route 53 Resolver query logging; Route 53 Resolver DNS Firewall |
| Azure | DNS security policy (DNS traffic logging/filtering for VNets) / Azure Firewall DNS proxy logs |
| GCP | Cloud DNS logging; Cloud DNS response policies |

```powershell
wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:true /q:true
```

---

## 2. Protective DNS / RPZ

```text
// BIND named.conf
options {
  response-policy { zone "rpz.local"; } qname-wait-recurse no;
};
zone "rpz.local" { type primary; file "/etc/bind/db.rpz.local"; allow-query { none; }; };
```

```text
; db.rpz.local
$TTL 60
@ IN SOA localhost. admin.localhost. ( 1 3600 600 86400 60 )
  IN NS localhost.
evil-c2.example        CNAME .                ; NXDOMAIN
*.evil-c2.example      CNAME .
phish.example          A 10.99.99.99          ; sinkhole to internal web page that logs hits
```

Feeds: commercial protective DNS (Cisco Umbrella, Cloudflare Gateway, Quad9 for blocking malicious domains, Infoblox Threat Defense, Akamai), CISA Protective DNS (US federal), abuse.ch/URLhaus RPZ, newly registered domain lists.

Sinkhole hits = infected/compromised host list → investigate every source.

---

## 3. Encrypted DNS Policy

| Approach | Detail |
|---|---|
| Provide sanctioned encrypted DNS | Internal resolvers support DoT/DoH; Windows 11 DoH to internal resolver via policy |
| Disable browser DoH | Chrome `DnsOverHttpsMode=off`/`secure` with enterprise template; Firefox `DNSOverHTTPS` policy, canary domain `use-application-dns.net` returns NXDOMAIN to disable |
| Block | Outbound TCP/UDP 853; known public DoH endpoints by SNI/IP list at proxy/NGFW (category "DNS over HTTPS") |
| Detect | Non-browser processes connecting to DoH providers |

---

## 4. Authoritative DNS Hardening

| Control | Detail |
|---|---|
| Zone transfers | `allow-transfer { secondaries; };` with TSIG keys; never `any` |
| Recursion | Authoritative servers non-recursive; resolvers not open to the internet (`allow-recursion { internal; };`) |
| Rate limiting | Response Rate Limiting (RRL) against amplification |
| DNSSEC | Sign zones (ECDSA P-256 alg 13 / Ed25519 alg 15), automate key rollover; validate on resolvers |
| Split horizon | Internal names not published externally |
| CAA records | `example.com. CAA 0 issue "letsencrypt.org"` — restrict which CAs can issue |
| Registrar | Registry/registrar lock, MFA on registrar account, monitor WHOIS/NS changes |
| Version hiding | `version "not disclosed";` |
| Windows DNS | Secure dynamic updates only; restrict `DnsAdmins` membership (DLL load abuse → Tier 0) |

```bash
dig AXFR example.com @ns1.example.com          # should fail from untrusted hosts
dig +dnssec example.com SOA | grep -i ad       # validation flag from validating resolver
delv example.com                               # DNSSEC validation trace
```

---

## 5. Dangling DNS & Subdomain Takeover

CNAMEs pointing to deprovisioned cloud resources (S3 buckets, Azure App Service, Heroku, GitHub Pages, CloudFront) can be claimed by attackers.

- Inventory all records (zone exports, cloud DNS APIs)
- Resolve CNAME targets; flag NXDOMAIN or provider "no such app/bucket" responses
- Tooling: `dnsReaper`, `subjack`-style checks, EASM platforms
- Process: delete DNS record **before** deleting the cloud resource

---

## 6. Detections

| Use case | Logic |
|---|---|
| Tunneling | Long/high-entropy labels, many unique subdomains per parent, TXT-heavy (see `defensive-detect-command-and-control`) |
| DGA | NXDOMAIN bursts with random-looking names from one host |
| Newly registered domains | Domain age < 30 days (enrichment) contacted by non-browser processes |
| Lookalikes | dnstwist permutations of your domains appearing in logs or newly registered |
| Direct-to-internet DNS | Firewall: UDP/TCP 53 or 853 egress from non-resolver hosts |
| Fast flux | Many A records with low TTL changing rapidly |
| Internal recon | AXFR attempts, PTR sweeps (reverse lookups across subnets) |

```bash
dnstwist --registered --format csv example.com > lookalikes.csv
```

---

## 7. Passive DNS (Investigations)

Historical resolution data (DomainTools, Farsight DNSDB, VirusTotal, SecurityTrails, CIRCL pDNS) answers: what did this domain resolve to last month? What other domains share this IP/name server? Use for Diamond Model infrastructure pivots.

---

## Engagement Cheatsheet

```text
force internal resolvers + block 53/853/DoH egress → resolver + Sysmon 22 logging → RPZ/protective DNS + sinkhole hits = incidents
→ authoritative: TSIG transfers, no open recursion, RRL, DNSSEC, CAA, registrar lock, DnsAdmins as Tier 0
→ dangling CNAME sweeps → tunneling/DGA/NRD/lookalike detections → passive DNS pivots
```

---

## Key References

- NIST SP 800-81 Rev 3 (Secure DNS Deployment — verify current status); CISA Protective DNS; ISC BIND RPZ docs
- CISA "Encrypted DNS Implementation Guidance" (2024); dnstwist; dnstap
- Related: `defensive-detect-command-and-control`, `defensive-vuln-management`, `defensive-proxy-tls-inspection`, `defensive-email-auth`
