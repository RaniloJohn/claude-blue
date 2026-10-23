---
name: defensive-tool-misp-opencti
description: "Threat intelligence platforms MISP and OpenCTI deployment, hardening, and safe sharing: MISP hardening from the official wiki (TLS, MySQL/Redis localhost only, 2FA, IP filtering, diagnostics security audit, GPG settings, file permissions, updates), distribution levels and sharing groups, TLP tagging, warninglists to suppress false-positive indicators, sync servers and least-privilege sync users, feeds, decaying models, sightings, API key roles, PyMISP; OpenCTI STIX 2.1 data model, connectors (import, enrichment, stream) with per-connector tokens, markings enforcement through groups, SSO, protecting Redis/RabbitMQ/Elasticsearch/MinIO dependencies, and pushing intel to SIEM/EDR. Use when running a TIP or sharing intelligence safely."
---

# MISP & OpenCTI

MISP excels at **indicator sharing** within communities (ISACs, CERTs); OpenCTI excels at **knowledge modeling** (STIX 2.1 relationships among actors, campaigns, techniques, indicators). Many teams run both, connected. Versions observed: MISP 2.5.x, OpenCTI 7.x.

## Quick Workflow

1. Deploy behind TLS; lock dependencies to localhost/internal networks
2. SSO/2FA; roles; per-integration API keys
3. Define sharing policy: distribution levels, TLP, sharing groups
4. Enable warninglists and decaying to keep indicators actionable
5. Integrate: SIEM/EDR/firewall consumption, TheHive/Cortex enrichment
6. Monitor platform health and audit logs; patch regularly

---

## 1. MISP Hardening (official wiki)

| Area | Practice |
|---|---|
| Web | TLS on all services; Apache hardening; expose only what's needed |
| Database | MySQL bound to localhost (or restricted users/IPs + passwords if remote) |
| Redis | Localhost only |
| Accounts | 2FA for publicly reachable instances; IP filtering or basic auth for semi-public |
| GPG | Review Encryption settings (signing/encrypting email notifications) |
| Audit | Configure audit logging; review Security settings tab fully |
| Diagnostics | Run the built-in diagnostics page — includes a security audit with severities |
| System | Patch OS and MISP; monitor CVEs of running services; correct file/dir permissions; monitor logs |

Additional practices: separate org admin vs site admin, API keys tied to least-privilege roles (e.g., "User" or a custom read-only role for SIEM pulls), sync users with "Sync user" role only, disable self-registration.

---

## 2. MISP Sharing Model

| Distribution | Reach |
|---|---|
| Your organisation only | Internal |
| This community only | Users of this instance |
| Connected communities | Instance + directly synced instances |
| All communities | Propagates through sync chains |
| Sharing group | Explicit org/instance list |

Rules: tag every event with TLP (`tlp:amber`, `tlp:amber+strict`, …), set distribution to match TLP, review before publishing, strip internal hostnames/usernames from shared events, use `to_ids` only for detection-quality indicators.

---

## 3. Keeping Indicators Useful

| Feature | Use |
|---|---|
| Warninglists | Flag/suppress known-benign values (public DNS, CDN ranges, top domains, RFC1918) — prevents blocking Google DNS by mistake |
| Decaying models | Score indicators down over time (IPs decay fast, hashes slowly) |
| Sightings | Record when an indicator was seen (or false positive) — feeds decay |
| Correlation | Find overlaps across events; disable correlation on noisy attributes |
| Feeds | Curate (abuse.ch, CIRCL OSINT, ISAC feeds); cache and review before enabling `to_ids` |

```python
from pymisp import PyMISP
misp = PyMISP("https://misp.example.local", KEY, ssl=True)
attrs = misp.search(controller="attributes", type_attribute=["ip-dst", "domain"], to_ids=True, last="1d", enforce_warninglist=True, pythonify=True)
for a in attrs:
    print(a.type, a.value, a.Event.info)
```

Export for SIEM/EDR: REST search with `returnFormat` (`csv`, `stix2`, `suricata`, `snort`, `text`), or feed generator.

---

## 4. OpenCTI

| Area | Practice |
|---|---|
| Dependencies | Elasticsearch/OpenSearch, Redis, RabbitMQ, MinIO/S3 — internal network only, authentication enabled |
| Access | SSO (OIDC/SAML/LDAP) with MFA; groups define **allowed markings** (users only see data up to their marking clearance) |
| Connectors | One token/user per connector, minimal capabilities; review third-party connectors; enrichment connectors send observables externally — gate by marking |
| Data model | STIX 2.1 SDOs/SROs: Threat Actor, Intrusion Set, Campaign, Malware, Tool, Attack Pattern (ATT&CK), Indicator (pattern), Observable, Report; relationships (`uses`, `targets`, `indicates`) |
| Rules engine | Inference rules can create relationships — enable selectively |
| Streams | Live streams (TAXII/SSE) to consumers (SIEM, MISP) |
| Retention | Policies for old observables/indicators |

---

## 5. Integration Pattern

```text
Feeds/ISAC/reports → MISP (sharing, warninglists, sightings) ⇄ OpenCTI (context, ATT&CK, reports)
→ indicators (to_ids, high confidence, not decayed) → SIEM watchlists / EDR custom IOCs / firewall EDLs / DNS RPZ
→ sightings back from SIEM hits → decay and retire
```

---

## 6. Safety Notes

- Shared intel may contain live malicious URLs — defang in reports/emails; analysts open only in isolated browsers
- Never auto-block from unvetted feeds without warninglist filtering and an allowlist of critical services
- Respect TLP/PAP and sharing agreements (ISAC terms) — leaking TLP:RED/AMBER+STRICT breaks trust
- Personal data in intel (emails, usernames) → privacy assessment

---

## Engagement Cheatsheet

```text
TLS + DB/Redis/RabbitMQ/ES internal only + 2FA/SSO → roles & per-integration keys → distribution + TLP + sharing groups
→ warninglists + decay + sightings → curated feeds → OpenCTI markings via groups + scoped connector tokens → export vetted IOCs to SIEM/EDR/FW/DNS → feedback sightings
```

---

## Key References

- MISP Hardening wiki; MISP user guide (distribution, warninglists, decaying); PyMISP
- OpenCTI documentation (deployment, connectors, markings); FIRST TLP 2.0
- Related: `defensive-cti`, `defensive-ioc-management`, `defensive-tool-thehive-cortex`, `defensive-tool-safety`
