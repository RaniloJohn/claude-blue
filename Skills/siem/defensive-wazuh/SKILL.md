---
name: defensive-wazuh
description: "Wazuh open-source SIEM/XDR operations (4.x): architecture (agent, manager, indexer, dashboard), agent enrollment and groups, centralized agent.conf, Windows eventchannel and Sysmon collection, Linux auditd/journald collection, custom decoders and rules (levels, if_sid, if_group, field pcre2, frequency/timeframe, CDB lists), wazuh-logtest, FIM/syscheck with whodata, SCA, vulnerability detection, active response, integrations (VirusTotal, Shuffle, Slack, TheHive), MITRE mapping, archives, and troubleshooting. Use for Wazuh lab builds, rule writing, tuning, and SOC operations on Wazuh."
---

# Wazuh

Wazuh = OSSEC lineage manager + OpenSearch-based indexer + dashboard. Detection happens in `wazuh-analysisd` via decoders → rules. Everything else (dashboards, alerts index) is downstream of that.

## Quick Workflow

1. Deploy manager/indexer/dashboard (all-in-one for labs, distributed for prod)
2. Enroll agents into groups; push `agent.conf` per group
3. Collect the right channels (Security, Sysmon, PowerShell, auditd)
4. Write decoders only when built-ins don't parse; write rules in `local_rules.xml`
5. Test with `wazuh-logtest`
6. Tune with child rules (level 0) instead of editing stock rules

---

## 1. Architecture & Ports

| Component | Role | Port |
|---|---|---|
| Agent → manager events | Secure event channel | 1514/tcp |
| Agent enrollment | `wazuh-authd` | 1515/tcp |
| Manager API | REST | 55000/tcp |
| Indexer | OpenSearch-based | 9200/tcp |
| Dashboard | Web UI | 443/tcp |
| Cluster | Manager nodes | 1516/tcp |

Current line: 4.14.x (4.14.9 observed 2026-10-23; ≥ 4.14.5 required for CVE-2026-30893/CVE-2026-34150; CVE-2025-24016 exploited by Mirai — see `defensive-tool-wazuh` for hardening).

---

## 2. Agent Configuration (`/var/ossec/etc/shared/<group>/agent.conf`)

```xml
<agent_config os="Windows">
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5156 and EventID != 5158]</query>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>

<agent_config os="Linux">
  <localfile>
    <location>/var/log/audit/audit.log</location>
    <log_format>audit</log_format>
  </localfile>
  <localfile>
    <location>journald</location>
    <log_format>journald</log_format>
  </localfile>
</agent_config>
```

```bash
/var/ossec/bin/agent_groups -a -i 001 -g windows-servers   # assign group
/var/ossec/bin/agent_control -l                            # list agents
```

---

## 3. Rules

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="local,windows,credential_access,">
  <rule id="100100" level="12">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^10$</field>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">^0x(1010|1410|1438|143a|1fffff)$</field>
    <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)\\(MsMpEng|WerFault)\.exe$</field>
    <description>LSASS access by $(win.eventdata.sourceImage)</description>
    <mitre><id>T1003.001</id></mitre>
  </rule>

  <!-- Correlation: 8 failed Windows logons from same IP in 120 s -->
  <rule id="100101" level="10" frequency="8" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Possible brute force from $(win.eventdata.ipAddress)</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- Tuning: silence a known-good case of 100100 -->
  <rule id="100102" level="0">
    <if_sid>100100</if_sid>
    <field name="win.eventdata.sourceImage" type="pcre2">(?i)\\Program Files\\BackupVendor\\agent\.exe$</field>
    <description>Suppress backup agent LSASS access</description>
  </rule>
</group>
```

| Element | Notes |
|---|---|
| `level` 0–15 | 0 = no alert; ≥ `log_alert_level` (default 3) writes alert; ≥12 high |
| `if_sid` / `if_group` / `if_matched_sid` | Parent chaining / correlation |
| `field` + `type="pcre2"` | Regex on decoded JSON field; `negate="yes"` inverts |
| `list` | CDB list lookup (`etc/lists/`) e.g. malicious hashes |
| `same_field` / `different_field` | Correlation keys (newer syntax than `same_source_ip`) |
| Custom IDs | 100000–120000 |

Parent SIDs (e.g. 60122 for Windows logon failure) vary by ruleset version — confirm in `/var/ossec/ruleset/rules/`.

Test:

```bash
/var/ossec/bin/wazuh-logtest     # paste a raw log line / JSON event
systemctl restart wazuh-manager  # after rule changes
```

---

## 4. Decoders

Only when stock decoders miss. Place in `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="cb-app">
  <prematch>^cbapp: </prematch>
</decoder>
<decoder name="cb-app-fields">
  <parent>cb-app</parent>
  <regex type="pcre2">user=(\S+) action=(\S+) src=(\S+)</regex>
  <order>user, action, srcip</order>
</decoder>
```

JSON logs: built-in `json` decoder handles them; reference fields directly in rules.

---

## 5. FIM (syscheck)

```xml
<syscheck>
  <frequency>43200</frequency>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories whodata="yes">/var/www</directories>                <!-- who changed it (auditd/SACL) -->
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <ignore type="sregex">\.log$|\.tmp$</ignore>
</syscheck>
```

---

## 6. SCA, Vulnerability Detection, Inventory

- SCA: CIS-based policy checks per OS (`/var/ossec/ruleset/sca/`); results in dashboard
- Vulnerability detection (4.8+ module): correlates syscollector package inventory with Wazuh CTI feed; results in indexer `wazuh-states-vulnerabilities-*`
- Syscollector: hardware, OS, packages, ports, processes — useful for hunting (listening ports diff)

---

## 7. Active Response

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101</rules_id>
  <timeout>600</timeout>
</active-response>
```

Always set `timeout` for auto-revert. Never auto-respond on rules that attacker input can trigger against your own infrastructure (spoofed source IPs).

---

## 8. Integrations

```xml
<integration>
  <name>virustotal</name>
  <api_key>REDACTED</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
<integration>
  <name>custom-shuffle</name>
  <hook_url>https://shuffle.local/api/v1/hooks/webhook_xxx</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

---

## 9. Archives & Hunting

- `<logall_json>yes</logall_json>` in `ossec.conf` writes every event (not just alerts) to `archives.json`; enable `wazuh-archives-*` index in Filebeat for hunting. Size accordingly.
- Dashboard: Threat Hunting / Discover on `wazuh-alerts-*` and `wazuh-archives-*`

---

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| Agent disconnected | `/var/ossec/logs/ossec.log` on agent; port 1514 reachability; key mismatch |
| Events not alerting | `wazuh-logtest` with raw event; rule level ≥ alert threshold |
| Field not matching | Decoded field name/case (`win.eventdata.targetImage` camelCase) |
| Indexer missing alerts | Filebeat status; `wazuh-alerts-*` template |
| High EPS | Exclude noisy event IDs at agent with `<query>` XPath |

---

## Engagement Cheatsheet

```bash
agent.conf (groups) → wazuh-logtest raw event → local_rules.xml (100000+) →
restart manager → generate test event → verify in wazuh-alerts-* → tune with level 0 child rules
```

---

## Key References

- Wazuh documentation — https://documentation.wazuh.com/current
- Wazuh ruleset — https://github.com/wazuh/wazuh/tree/master/ruleset
- Related: `defensive-query-languages`, `defensive-soar-automation`, `defensive-sysmon`
