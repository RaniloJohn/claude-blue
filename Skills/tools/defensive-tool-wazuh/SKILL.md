---
name: defensive-tool-wazuh
description: "Wazuh deployment hardening and safe operation from official documentation and advisories: current 4.14.x line (4.14.9 observed; 5.0 in beta), patch-critical CVEs (CVE-2025-24016 API deserialization RCE exploited by Mirai and in CISA KEV, CVE-2026-30893 cluster path traversal, CVE-2026-34150 analysisd unauthenticated DoS), default credential changes (OVA wazuh/wazuh-wui, indexer admin/kibanaserver), API hardening (host binding, trusted certs, rate limiting, login attempt limits, RBAC), certificates tool, port exposure (1514, 1515, 1516, 55000, 9200, 9300, 443), secure agent enrollment (password, agent/manager certificate verification), cluster key, remote commands kept disabled, active response safety, centralized agent groups, FIM whodata, Sysmon collection, vulnerability detection, custom rules testing with wazuh-logtest, and index retention. Use when deploying, hardening, upgrading, or auditing a Wazuh environment."
---

# Wazuh (Deployment Hardening & Operations)

Detection content and queries live in `defensive-wazuh`. This skill covers **running Wazuh safely**: Wazuh servers have been mass-exploited (Mirai via CVE-2025-24016), so the SIEM itself must be patched, hardened, and kept off the internet. Latest observed release: 4.14.9 (2026-10-23); Wazuh 5.0 is in beta.

## Quick Workflow

1. Upgrade to the current 4.14.x (≥ 4.14.5 minimum for 2026 CVEs) — all components same version
2. Change every default password; replace self-signed certs
3. Restrict ports by source; never expose API (55000), indexer (9200/9300), or cluster (1516) to the internet
4. Secure agent enrollment (password and/or certificate verification)
5. Keep remote commands disabled; scope active response
6. Configure retention (ISM), backups, and audit of admin actions

---

## 1. Security Advisories That Matter

| CVE | Component | Affected | Fixed | Notes |
|---|---|---|---|---|
| CVE-2025-24016 (CVSS 9.9) | Server API / DistributedAPI unsafe deserialization → RCE | 4.4.0–4.9.0 | 4.9.1 | Exploited by Mirai variants from March 2025; CISA KEV June 10, 2025; requires API access (compromised dashboard/server/agent context) |
| CVE-2026-30893 (CVSS 9.9) | Cluster synchronization extraction path traversal → code execution | 4.4.0 – < 4.14.4 | 4.14.4 | Requires cluster peer + cluster mode; PoC public (advisory April 29, 2026); ~3,500 exposed servers counted May 2026 |
| CVE-2026-34150 (CVSS 7.5) | `wazuh-analysisd` heap overflow → unauthenticated DoS (alert processing halts) | ≤ 4.14.4 incl. wazuh-docker | 4.14.5 | Network-reachable |

Subscribe to github.com/wazuh/wazuh security advisories; treat the manager like any internet-exposed critical server (emergency patch SLA).

---

## 2. Ports & Exposure

| Port | Service | Allowed sources |
|---|---|---|
| 1514/TCP | Agent communication | Agent networks (internet only if remote agents — prefer VPN/ZTNA or dedicated hardened worker) |
| 1515/TCP | Agent enrollment (authd) | Agent networks during enrollment; disable or restrict when not enrolling |
| 1516/TCP | Cluster | Manager nodes only |
| 55000/TCP | Server API | Dashboard host + admin/automation hosts only |
| 9200/TCP | Indexer REST | Manager/dashboard/indexer nodes only |
| 9300/TCP | Indexer cluster transport | Indexer nodes only |
| 443/TCP | Dashboard | Analyst networks via SSO/VPN |
| 514/UDP/TCP | Syslog collection (optional) | Specific devices |

---

## 3. Credentials & Certificates

```bash
# All-in-one / package installs: change indexer + API passwords
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all
# Generate certificates (initial install / rotation)
bash wazuh-certs-tool.sh -A
```

- OVA defaults `wazuh:wazuh` (API) and `wazuh-wui:wazuh-wui`; indexer `admin`, `kibanaserver` — change all; changing `wazuh-wui` requires updating `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`
- Docker/Kubernetes: change secrets in compose `.env`/K8s secret manifests and re-run `securityadmin.sh` for indexer users (per docs; avoid `$`/`&` in indexer hash tool passwords)
- API password policy: 8–64 chars, upper, lower, number, symbol
- Dashboard SSO (SAML/OIDC via indexer security plugin) with MFA at the IdP; least-privilege indexer roles for analysts

---

## 4. API Hardening (`/var/ossec/api/configuration/api.yaml`)

```yaml
host: ['10.20.0.10']          # not 0.0.0.0 / ::
port: 55000
https:
  enabled: yes
  key: "server.key"
  cert: "server.crt"
  use_ca: True
  ca: "ca.crt"
access:
  max_login_attempts: 5
  block_time: 300
  max_request_per_minute: 120
auth_token_exp_timeout: 900
```

Use RBAC: separate read-only users/roles for integrations; restrict `run_as`; rotate service account passwords. Restart `wazuh-manager` after changes.

---

## 5. Agent Enrollment & Communication

```xml
<!-- Manager ossec.conf -->
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_password>yes</use_password>          <!-- /var/ossec/etc/authd.pass -->
  <ssl_verify_host>yes</ssl_verify_host>
  <ssl_agent_ca>/var/ossec/etc/rootCA.pem</ssl_agent_ca>
  <force><enabled>yes</enabled><key_mismatch>yes</key_mismatch><disconnected_time enabled="yes">1h</disconnected_time><after_registration_time>1h</after_registration_time></force>
</auth>
<cluster>
  <key>[32 random characters, unique per deployment]</key>
</cluster>
```

- Enrollment password stored with restrictive permissions; rotate after mass deployment
- Agent certificate verification blocks rogue agents from enrolling
- Remove stale/never-connected agents (`manage_agents`, API) — they are noise and potential impersonation targets

---

## 6. Remote Commands & Active Response

| Setting | Guidance |
|---|---|
| `logcollector.remote_commands` / `wazuh_command.remote_commands` (`local_internal_options.conf`) | Keep `0` (default). Enabling lets centralized config push commands that agents execute — a compromised manager becomes fleet RCE |
| Active response | Only for high-confidence rules; set `<timeout>`; `<repeated_offenders>` escalation; `<white_list>` for gateways, DNS, scanners, admin IPs, cloud LB IPs; test in lab |
| Spoofing risk | Blocking source IPs from spoofable logs (UDP syslog) can be weaponized to block critical services |
| Custom AR scripts | Root-owned, reviewed, versioned |

```xml
<global><white_list>10.0.0.1</white_list><white_list>10.20.0.0/24</white_list></global>
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100210</rules_id>
  <timeout>600</timeout>
</active-response>
```

---

## 7. Agent Configuration (centralized `agent.conf` per group)

```xml
<agent_config os="Windows">
  <localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>
  <syscheck>
    <directories realtime="yes" whodata="yes" check_all="yes">C:\Windows\System32\drivers\etc</directories>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  </syscheck>
</agent_config>
<agent_config os="Linux">
  <syscheck>
    <directories realtime="yes" whodata="yes" check_all="yes">/etc,/usr/bin,/usr/sbin,/root/.ssh</directories>
    <ignore type="sregex">.log$|.swp$</ignore>
  </syscheck>
</agent_config>
```

whodata needs auditd (Linux) or SACL auditing (Windows). Vulnerability detection (4.8+ `<vulnerability-detection>` module using Wazuh CTI) relies on Syscollector inventory — keep Syscollector enabled. SCA policies for CIS benchmarks.

---

## 8. Custom Rules — Test Before Deploy

```xml
<!-- /var/ossec/etc/rules/local_rules.xml : IDs 100000–120000 -->
<group name="local,authentication,">
  <rule id="100200" level="10" frequency="20" timeframe="600">
    <if_matched_sid>60122</if_matched_sid>      <!-- Windows logon failure -->
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Possible password spray: 20+ failed logons from same source in 10 min</description>
    <mitre><id>T1110.003</id></mitre>
  </rule>
</group>
```

```bash
/var/ossec/bin/wazuh-logtest          # paste sample logs; confirm decoder + rule match
/var/ossec/bin/wazuh-analysisd -t     # config/rules syntax test
```

Use `overwrite="yes"` to modify built-in rules in local files (never edit `ruleset/` — upgrades overwrite it).

---

## 9. Operations

- Index State Management (ISM) policy for retention (e.g., hot 30 d → delete 180 d) per compliance
- Snapshot indexer to a repository; back up `/var/ossec/etc`, `api/configuration`, rules/decoders, keys
- Upgrade order: indexer → manager(s) → dashboard → agents; read release notes; test in staging
- Monitor: agent disconnects, `analysisd` queue usage/EPS drops, indexer cluster health
- Audit dashboard/API admin actions (indexer audit log)

---

## Engagement Cheatsheet

```text
≥4.14.5 (latest 4.14.x) everywhere → change OVA/indexer/API defaults + certs → restrict 1514/1515/1516/55000/9200/9300/443 by source
→ api.yaml host binding, HTTPS CA, login limits, rate limit, short tokens, RBAC → enrollment password + ssl_verify_host + unique cluster key
→ remote_commands=0 → AR only high-confidence with timeout + white_list → agent groups (Sysmon, FIM whodata, Syscollector)
→ local_rules 100000+ tested in wazuh-logtest → ISM retention + snapshots → patch per advisories
```

---

## Key References

- documentation.wazuh.com (Securing the Wazuh server API, changing default passwords, agent enrollment security, active response, rules syntax)
- CVE-2025-24016 (Akamai SIRT / Censys advisory; CISA KEV); CVE-2026-30893 (Wazuh advisory Apr 29 2026); CVE-2026-34150
- Related: `defensive-wazuh`, `defensive-tool-safety`, `defensive-sysmon`, `defensive-soar-automation`
