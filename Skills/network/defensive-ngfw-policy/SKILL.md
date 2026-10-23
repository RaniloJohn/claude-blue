---
name: defensive-ngfw-policy
description: "Next-generation firewall policy design, review, and hardening across Palo Alto Networks (App-ID, User-ID, Content-ID, security profiles, zone protection, decryption), Fortinet FortiGate (policies, security profiles, ISDB, local-in policy), Cisco Secure Firewall/FTD and ASA, Check Point, pfSense/OPNsense, and cloud firewalls (AWS Network Firewall, Azure Firewall, GCP Cloud NGFW). Rule base hygiene (shadowed, redundant, any-any, unused by hit count, expired), application-based vs port-based rules, threat prevention profiles, geo/EDL blocking, admin interface exposure, change management, and firewall audit commands. Use when building or auditing a firewall rule base or tuning NGFW security profiles."
---

# NGFW Policy Design & Review

A firewall is only as good as its rule base. Aim for **zone-based, application-aware, user-aware, default-deny** policy with threat profiles on every allow rule — and a rule base small enough that humans can review it.

## Quick Workflow

1. Export rule base + hit counts
2. Flag hygiene issues (§2)
3. Convert port-based allows to application-based where supported
4. Attach threat prevention profiles to all allow rules
5. Harden the management plane (§5)
6. Put changes under ticketed change control with periodic recertification

---

## 1. Rule Design Principles

| Principle | Implementation |
|---|---|
| Default deny | Explicit deny-all at bottom with logging |
| Zone-based | Source zone + destination zone on every rule |
| Application-aware | App-ID / application control instead of `tcp/any` |
| User-aware | User-ID / FSSO / identity groups for user zones |
| Least privilege | Specific sources, destinations, services; no `any` in two+ fields |
| Profiles everywhere | AV, anti-spyware/IPS, vulnerability, URL, file blocking, WildFire/sandbox on allow rules |
| Log at session end | Log all allows and denies; forward to SIEM |
| Documented | Rule name, description, owner, ticket, expiry date in tags/comments |
| Ordering | Specific deny → specific allow → general → default deny; most-hit rules high for performance (where order-sensitive) |

---

## 2. Rule Base Hygiene

| Issue | Detection | Action |
|---|---|---|
| Shadowed | Rule never matches because earlier rule covers it | Remove or reorder |
| Redundant | Duplicate coverage | Merge |
| Unused | Zero hits in 90+ days | Disable → delete after 30 days |
| Overly permissive | `any` source/destination/service; large CIDRs; `application any` | Narrow from logs |
| Temporary rules without expiry | No end date | Add schedules/expiry |
| Disabled rules | Clutter | Delete |
| Rules without logging | No visibility | Enable |
| Inbound any to admin ports | 22/3389/443-mgmt from internet | Remove; use ZTNA |

Tools: Palo Alto Policy Optimizer (unused apps, port-based to App-ID), FortiManager policy analyzer, Tufin/AlgoSec/FireMon, Capirca/Batfish for config analysis, open-source `pan-os-python` scripts.

---

## 3. Vendor Commands

### Palo Alto PAN-OS

```text
show running security-policy
show rule-hit-count vsys vsys-name vsys1 rule-base security rules all
test security-policy-match from trust to untrust source 10.1.1.10 destination 8.8.8.8 protocol 6 destination-port 443 application ssl
show system info | match sw-version
show log traffic direction equal backward rule equal "allow-web" | match deny
```

Security profile group per allow rule: Antivirus, Anti-Spyware (DNS Security sinkhole), Vulnerability Protection (strict), URL Filtering, File Blocking, WildFire. Zone Protection profiles on untrust (flood, reconnaissance, packet-based attack protection).

### Fortinet FortiOS

```text
show firewall policy
diagnose firewall iprope show 100004 <policy-id>     # hit counters (varies by version)
get system status
diagnose debug flow filter addr 10.1.1.10
diagnose debug flow trace start 20
diagnose debug enable
show system interface | grep -A5 allowaccess        # check admin access on WAN
config firewall local-in-policy                      # restrict admin/VPN access by source
```

Use ISDB (Internet Service Database) objects for SaaS; security profiles: AV, IPS, web filter, DNS filter, application control, SSL inspection.

### Cisco ASA / FTD

```text
show access-list | include hitcnt=0
show running-config access-group
packet-tracer input inside tcp 10.1.1.10 12345 8.8.8.8 443 detailed
show conn count
```

FTD: manage via FMC/cdFMC; Access Control Policy with Intrusion Policy + File/Malware policy; prefilter for fastpath only trusted flows.

### pfSense / OPNsense

```bash
pfctl -sr            # rules
pfctl -vvsr | grep -B1 "Evaluations: 0"   # rough unused check
pfctl -ss | wc -l    # states
```

### Cloud

| Platform | Notes |
|---|---|
| AWS Network Firewall | Suricata-compatible stateful rules; strict rule order; domain allowlists for egress; alert + flow logs to S3/CloudWatch |
| Azure Firewall Premium | IDPS, TLS inspection, URL categories; Firewall Policy hierarchy (base → child) |
| GCP Cloud NGFW | Hierarchical firewall policies, FQDN/geo/threat intel objects, Enterprise tier IPS |

---

## 4. Blocking Feeds

- Geo-blocking for inbound admin/VPN where business allows
- EDLs (external dynamic lists): known malicious IPs/domains (abuse.ch, CISA AIS, vendor intel), Tor exit nodes for inbound
- Outbound: newly registered domains category, uncategorized, parked, dynamic DNS, and C2 categories → block or alert

---

## 5. Management Plane

| Control | Detail |
|---|---|
| No internet-exposed management | Admin GUI/SSH only on management interface/VRF; local-in policies |
| Patch cadence | Firewalls/VPNs are top KEV class (PAN-OS GlobalProtect CVE-2024-3400, FortiOS SSL-VPN CVEs, ASA CVE-2025-20333/20362) — emergency patch SLA |
| AAA | TACACS+/RADIUS with MFA, local break-glass only |
| Config backup & diff | Daily, alert on unexpected change |
| Integrity checks | Vendor integrity tools after compromise advisories (e.g., Cisco ASA ROM monitor checks per ED 25-03) |
| Logging | System/config logs to SIEM; alert on admin logins from new sources |

---

## 6. Change Management

Request (business justification, source, destination, app, duration) → security review → peer-reviewed implementation → validation (`test security-policy-match` / `packet-tracer`) → documentation → recertification every 6–12 months by rule owner.

---

## Engagement Cheatsheet

```text
export rules + hits → hygiene (shadowed/redundant/unused/any-any/no-expiry/no-log) → App-ID/User-ID conversion
→ profile group on every allow → EDL/geo/newly-registered blocks → lock down mgmt plane + KEV patch SLA → ticketed changes + recertification
```

---

## Key References

- NIST SP 800-41 Rev 1; vendor best-practice guides (Palo Alto Best Practice Assessment, Fortinet hardening guide, Cisco ASA/FTD hardening)
- CISA ED 25-03 (Cisco ASA/FTD, Sept 2025); CISA BOD 26-02 (end-of-support edge devices)
- Related: `defensive-firewall-analysis`, `defensive-network-security-architecture`, `defensive-incident-response`, `defensive-network-device-hardening`
