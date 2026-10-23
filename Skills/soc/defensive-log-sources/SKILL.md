---
name: defensive-log-sources
description: "Log source onboarding, telemetry coverage and visibility gap analysis. Use when deciding what to collect, mapping log sources to MITRE ATT&CK data components, configuring Windows Advanced Audit Policy, enabling command-line process auditing, PowerShell logging, Sysmon deployment, Linux auditd, cloud audit logs (CloudTrail, Entra, GCP), retention planning, parsing/normalization (ECS, CIM, ASIM, OCSF, UDM), log source health monitoring, silent-source detection, and estimating ingest volume and cost."
---

# Log Sources & Telemetry Coverage

Detection quality is capped by telemetry. A rule against data you don't collect is a false sense of coverage. Start every engagement by inventorying what exists, what is parsed, and what is retained.

## Quick Workflow

1. Inventory assets and their log-producing capabilities
2. Map sources to ATT&CK data components (v18 Detection Strategies / Analytics)
3. Configure audit policy at the source
4. Normalize to one schema
5. Set retention by use case (hunt vs compliance vs forensics)
6. Monitor source health — silence is a signal
7. Re-assess quarterly

---

## 1. Priority Sources (collect in this order)

| Priority | Source | Covers |
|---|---|---|
| 1 | EDR telemetry | Process, file, network, registry, injection |
| 2 | Identity: AD DC Security logs, Entra sign-in/audit | Auth, privilege, account changes |
| 3 | Sysmon / Windows Security 4688 + PowerShell 4104 | Execution detail where no EDR |
| 4 | Cloud control plane: CloudTrail, Azure Activity, GCP Admin Activity | API abuse |
| 5 | Email gateway + M365/Workspace audit | Phishing, BEC |
| 6 | DNS (resolver query logs) | C2, tunneling, DGA |
| 7 | Proxy / SWG / firewall egress | C2, exfil |
| 8 | VPN / remote access | Initial access |
| 9 | Network sensor: Zeek, Suricata | Protocol-level visibility |
| 10 | Linux auditd / eBPF, K8s audit | Server and container |
| 11 | SaaS audit (Okta, GitHub, Slack, Salesforce) | Identity/data in SaaS |
| 12 | Vulnerability/asset inventory | Context |

---

## 2. Windows Audit Policy (Advanced)

Apply via GPO: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration`.

| Subcategory | Setting | Key events |
|---|---|---|
| Account Logon › Credential Validation | S/F | 4776 |
| Account Logon › Kerberos Authentication Service | S/F | 4768, 4771 |
| Account Logon › Kerberos Service Ticket Operations | S/F | 4769 |
| Account Management › User/Security Group/Computer Account Mgmt | S/F | 4720, 4728, 4732, 4741 |
| Detailed Tracking › Process Creation | S | 4688 |
| Detailed Tracking › Process Termination | S | 4689 |
| DS Access › Directory Service Access | S/F (DCs) | 4662 |
| DS Access › Directory Service Changes | S (DCs) | 5136 |
| Logon/Logoff › Logon, Special Logon | S/F | 4624, 4625, 4672 |
| Object Access › Detailed File Share | F (or S on sensitive) | 5145 |
| Object Access › Other Object Access Events | S/F | 4698, 4702 |
| Policy Change › Audit Policy Change | S/F | 4719 |
| Privilege Use › Sensitive Privilege Use | S/F | 4673, 4674 |
| System › Security System Extension | S | 4697 |

Also enable:
- `Administrative Templates > System > Audit Process Creation > Include command line in process creation events` = Enabled
- `Force audit policy subcategory settings to override audit policy category settings` = Enabled
- PowerShell: Script Block Logging (4104), Module Logging (4103), Transcription to protected share
- Security log size ≥ 1 GB on DCs; forward via WEF/agent

Kerberos RC4 phase-out (CVE-2026-20833, KB5073381): the January 2026 updates added KDCSVC audit events 201–209 (System log on DCs) that flag RC4 usage. Collect them, plus 4768/4769 `TicketEncryptionType`, to find remaining RC4 dependencies.

NTLM: Server 2025 / Win11 24H2 ship enhanced NTLM auditing — collect `Microsoft-Windows-NTLM/Operational`.

---

## 3. Sysmon

- Baseline config: `SwiftOnSecurity/sysmon-config`; granular: `olafhartong/sysmon-modular`
- Native Sysmon: Windows 11 ships Sysmon as an optional feature (enable via Settings or `Dism /Online /Enable-Feature /FeatureName:Sysmon`, then `sysmon -i`). Uninstall the Sysinternals build first. Update cadence moves to Windows Update.
- Event 10 (ProcessAccess) and 7 (ImageLoad): include-only, targeted (LSASS, `clr.dll`, unsigned DLLs) or volume explodes
- Monitor EID 4 (state) and 16 (config change) for tampering

---

## 4. Linux

| Source | Config |
|---|---|
| auditd | execve, identity files, sudoers, SSH keys, cron, systemd, module load (see `defensive-linux-telemetry`) |
| journald/rsyslog | Forward `auth`, `authpriv`, `sshd`, `sudo` |
| eBPF | Falco, Tetragon, Tracee for kernel-level process/network/file |
| Sysmon for Linux | Process/network events in Sysmon schema |

---

## 5. Cloud Audit Logs

| Cloud | Must-enable | Commonly missed |
|---|---|---|
| AWS | CloudTrail org trail, all regions, log file validation, S3 + KMS | Data events (S3 object, Lambda), VPC Flow Logs, Route 53 resolver logs |
| Azure / Entra | SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AuditLogs, AzureActivity via Diagnostic Settings | Non-interactive & SP sign-ins, Key Vault, Storage logs |
| GCP | Admin Activity (always on), org-level sink | Data Access logs (off by default except BigQuery) |
| M365 | Unified Audit Log | Mailbox auditing actions (`MailItemsAccessed` — license-dependent) |
| Kubernetes | API server audit policy (Metadata for all, RequestResponse for secrets/rbac/exec) | Managed clusters need explicit enablement |

---

## 6. Normalization Schemas

| Schema | Platform |
|---|---|
| ECS (Elastic Common Schema) | Elastic, now converging with OpenTelemetry semantic conventions |
| CIM (Common Information Model) | Splunk |
| ASIM (Advanced Security Information Model) | Microsoft Sentinel |
| UDM (Unified Data Model) | Google SecOps |
| OCSF (Open Cybersecurity Schema Framework) | AWS Security Lake, multi-vendor |

Pick one canonical schema; map everything else to it. Write detections against the schema, not raw fields.

---

## 7. Retention

| Use | Hot (searchable) | Warm/cold | Notes |
|---|---|---|---|
| Detection/triage | 30–90 d | — | |
| Threat hunting | 90–180 d | 1 y | Median dwell time varies; keep enough to scope |
| Forensics/IR | — | 1 y+ | Immutable storage |
| Compliance | per regulation | PCI DSS: 12 mo with 3 mo immediately available | |

---

## 8. Source Health Monitoring

Silence is a detection. Alert when a source stops.

```spl
| tstats latest(_time) as last count where index=* by host sourcetype
| eval mins_since=round((now()-last)/60)
| where mins_since > 60
```

```kql
union withsource=TableName *
| where TimeGenerated > ago(7d)
| summarize Last = max(TimeGenerated) by TableName, Computer
| where Last < ago(1h)
```

Also alert on sudden volume drops per source (>50% below 7-day median) — indicates agent failure or ETW/agent tampering.

---

## 9. Coverage Mapping

- Use ATT&CK v18 Detection Strategies → Analytics → Data Components to list which sources each technique needs
- DeTT&CT (Rabobank) to score data source quality and visibility
- Produce a heatmap per tactic; prioritize gaps in Credential Access, Lateral Movement, Defense Evasion

---

## Engagement Cheatsheet

```text
[ ] Asset inventory with log capability
[ ] Audit policy GPO + cmdline + PowerShell logging
[ ] Sysmon/EDR deployed and healthy
[ ] Cloud audit (incl. non-interactive sign-ins, data events where needed)
[ ] DNS + proxy + firewall egress
[ ] Schema mapping done
[ ] Retention per use case
[ ] Silent-source alerts live
[ ] ATT&CK coverage heatmap published
```

---

## Key References

- Microsoft: Advanced security audit policy settings; Audit Process Creation
- MITRE ATT&CK v18 (Oct 2025): Detection Strategies, Analytics, Data Components (Data Sources deprecated)
- DeTT&CT — https://github.com/rabobank-cdc/DeTTECT
- OCSF — https://schema.ocsf.io
- Microsoft KB5073381 (Kerberos RC4 deprecation, CVE-2026-20833)
- Related: `defensive-windows-event-logs`, `defensive-sysmon`, `defensive-linux-telemetry`, `defensive-attack-mapping`
