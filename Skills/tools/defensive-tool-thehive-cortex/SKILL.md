---
name: defensive-tool-thehive-cortex
description: "TheHive (StrangeBee) case management and Cortex analysis engine deployment and safe operation: TheHive 6 architecture (Cassandra, Elasticsearch — Lucene unsupported since 5.1, file storage on local/NFS/S3), licensing tiers, authentication (local, LDAP/AD, OAuth2, OIDC, SAML), organizations and profiles, TLS via reverse proxy, alerts to cases, observables with TLP/PAP, case templates and tasks, MISP integration, Cortex analyzers and responders running as Docker containers, max TLP/PAP enforcement per analyzer to prevent data leakage, API key scoping, backups, and hardening. Use when deploying or operating TheHive/Cortex for incident response."
---

# TheHive & Cortex

TheHive is a collaborative case management platform for SOC/CERT teams; Cortex runs **analyzers** (enrichment) and **responders** (actions) against observables. TheHive 6 is current (2026); Cortex 4.2.0 observed.

## Quick Workflow

1. Deploy TheHive (Cassandra + Elasticsearch + file storage) behind TLS reverse proxy
2. Configure SSO, organizations, profiles (least privilege)
3. Build case templates per incident type with task lists
4. Connect alert sources (SIEM, email, MISP) to create alerts → promote to cases
5. Deploy Cortex; enable analyzers with **max TLP/PAP** limits; restrict responders
6. Back up Cassandra, Elasticsearch, and attachments; test restore

---

## 1. Architecture & Licensing

| Component | Role |
|---|---|
| TheHive | Cases, alerts, tasks, observables, dashboards |
| Cassandra | Data store |
| Elasticsearch | Index (Lucene indexing not supported since TheHive 5.1 — migrate) |
| File storage | Local FS (standalone) or NFS/S3-compatible (cluster) |
| Cortex | Analyzer/responder execution (Docker-based workers), own Elasticsearch |

Licensing: StrangeBee provides community and paid licenses with different feature/usage limits — check current terms before production rollout.

---

## 2. Hardening

| Area | Practice |
|---|---|
| TLS | Nginx/reverse proxy HTTPS; TLS between TheHive and Cassandra/Elasticsearch; JVM truststore for internal CAs |
| Authentication | OIDC/SAML/OAuth2 with MFA; LDAP/AD where SSO unavailable; disable or protect local admin |
| Authorization | Organizations per team/customer (MSSP), profiles with minimal permissions (analyst vs read-only vs org-admin) |
| Brute force | Fail2ban (documented) or IdP lockout |
| Datastores | Cassandra/Elasticsearch auth enabled, bound to internal network, not internet-reachable |
| API keys | Per integration, per-org, minimal profile, rotated |
| Attachments | Malware samples stored zipped/password-protected; access-restricted |
| Updates | Follow StrangeBee release notes; upgrade guides from 4.x/5.x/6.x |
| Backups | Documented backup/restore for Cassandra + Elasticsearch + storage |

---

## 3. Case Workflow

```text
Alert (SIEM/email/MISP/API) → triage → merge duplicates → promote to Case (template) → tasks assigned
→ observables added (TLP/PAP) → Cortex analyzers → responders (approved) → resolution (TP/FP, impact) → report/metrics
```

Case template example — Phishing: tasks "Collect message & headers", "Analyze URLs/attachments", "Scope recipients", "Purge", "Block indicators", "User notification", "Close & lessons learned".

Observable fields: type, value, TLP (`TLP:CLEAR/GREEN/AMBER/AMBER+STRICT/RED`), PAP (permissible actions: CLEAR/GREEN/AMBER/RED), IOC flag, sighted flag, tags.

---

## 4. Cortex Safety

| Risk | Control |
|---|---|
| Data leakage to third-party services (VirusTotal, URLscan, Shodan, etc.) | Set **max TLP and max PAP** on each analyzer — e.g., public-service analyzers max TLP:GREEN / PAP:GREEN; internal analyzers higher |
| Uploading files to public sandboxes | Prefer hash-lookup analyzers; restrict file-submission analyzers to private sandboxes |
| Responders taking destructive actions | Enable only reviewed responders; restrict which TheHive profiles can run them; log every run |
| Analyzer code supply chain | Use official Docker images pinned by digest; review custom analyzers |
| API keys for services | Store in Cortex org config; least-privilege service accounts |
| Network | Cortex reachable only from TheHive and admins |

---

## 5. Integrations

- MISP: import events as alerts; export case IOCs to MISP with correct distribution/TLP
- SIEM/SOAR: create alerts via API with deduplication `sourceRef`
- Notifications: webhooks to chat/ticketing
- Metrics: case durations, TP/FP ratios by alert source (`defensive-security-metrics`)

```bash
curl -s -H "Authorization: Bearer $THEHIVE_KEY" -H 'Content-Type: application/json' \
  https://thehive.example.local/api/v1/alert -d '{"type":"siem","source":"sentinel","sourceRef":"INC-1234","title":"Suspicious PowerShell on ws-042","description":"See SIEM incident","severity":2,"tlp":2,"pap":2,"observables":[{"dataType":"hostname","data":"ws-042"}]}'
```

---

## Engagement Cheatsheet

```text
TheHive 6 (Cassandra + Elasticsearch + storage) behind TLS → SSO+MFA, orgs, least-privilege profiles → case templates per incident type
→ alerts via API (sourceRef dedupe) → observables with TLP/PAP → Cortex analyzers with max TLP/PAP, hash-lookup over upload → reviewed responders only → backups tested
```

---

## Key References

- docs.strangebee.com (TheHive, Cortex installation, authentication, licensing); FIRST TLP 2.0; PAP definitions
- Related: `defensive-tool-misp-opencti`, `defensive-soar-automation`, `defensive-incident-response`, `defensive-tool-safety`
