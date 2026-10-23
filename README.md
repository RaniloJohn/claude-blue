# claude-blue

**Defensive security skills for Claude — drop-in `SKILL.md` files that turn Claude into a SOC analyst, detection engineer, threat hunter, and incident responder.**

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Skills](https://img.shields.io/badge/skills-78-blue.svg)
![Categories](https://img.shields.io/badge/categories-27-0a66c2.svg)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v18-informational.svg)
![Status](https://img.shields.io/badge/status-v1.0-brightgreen.svg)

[Overview](#overview) • [Quickstart](#quickstart) • [How It Works](#how-it-works) • [Categories](#categories) • [Skill Index](#skill-index) • [Red ↔ Blue Map](#red--blue-map) • [Roadmap](#roadmap) • [Contributing](#contributing)

---

## Overview

`claude-blue` is a library of defensive security skills for the [Claude Skills system](https://docs.claude.com), built as the blue-team counterpart to [claude-red](https://github.com/SnailSploit/claude-red). There are 77 focused skills, each covering one defensive surface, plus one umbrella skill, **`claude-blue`**. The umbrella sets operating standards, routes each task to the right specialist, and enforces fixed output templates.

Skills load on demand from conversational triggers. For example, pasting a 4769 event loads `defensive-ad-detection`, and asking for a Sigma rule loads `defensive-sigma`. You only pay context for what you use.

**Use cases:** SOC triage, incident response, DFIR, detection engineering, threat hunting, hardening reviews, vulnerability prioritization, purple teaming, SOC/SIEM lab builds, and analyst training.

**Standards every skill follows**

- Evidence before verdict. Observed facts are kept separate from inferences, and each conclusion carries a confidence level.
- Never fabricates IOCs, event fields, CVE details, or tool flags.
- UTC timestamps and defanged indicators.
- Evidence is preserved before containment, and every action states its blast radius.
- Detections are written in Sigma first, then translated to SPL, KQL, EQL, ES|QL, Wazuh, YARA, Suricata, or Falco.
- Content is current to October 2026: ATT&CK v18, D3FEND 1.0, OWASP Top 10:2025, DMARCbis (RFC 9989), CISA BOD 26-04, EPSS v4, the 2026 Kerberos RC4 removal, and native Sysmon.

---

## Quickstart

### Claude Code: all skills

```bash
git clone https://github.com/ranilojohn/claude-blue
cd claude-blue
./install.sh                         # copies all 78 skills to ~/.claude/skills
```

Claude Code discovers skills one level deep (`~/.claude/skills/<skill>/SKILL.md`). The installer flattens `Skills/<category>/<skill>` for you.

### Selected categories or skills

```bash
./install.sh --category soc,detection,siem,ir      # also installs the claude-blue router
./install.sh --skill defensive-wazuh,defensive-sigma
./install.sh --core-only                            # only the umbrella skill
./install.sh --link                                 # symlink, so `git pull` updates skills
./install.sh --target .claude/skills                # project-level (share with team via git)
./install.sh --list
```

### Manual

```bash
mkdir -p ~/.claude/skills
for d in Skills/*/*/; do cp -r "$d" ~/.claude/skills/; done
```

### Claude.ai

Zip a skill folder (for example `Skills/soc/defensive-alert-triage/`) and upload it as a custom skill. You can also paste a `SKILL.md` into a Project's instructions.

### Verify

In Claude Code, type `/claude-blue`. The router and the specialist skills appear in the slash menu.

---

## How It Works

```text
           ┌─────────────────────────────┐
 you  ───► │ claude-blue (router skill)  │ ── principles, workflows W1–W6, templates
           └──────────────┬──────────────┘
                          │ loads the matching specialist(s)
     ┌──────────┬─────────┼──────────┬──────────────┬─────────────┐
     ▼          ▼         ▼          ▼              ▼             ▼
  triage    detection   hunting    DFIR       cloud/identity   hardening ...
```

| Workflow | Input | Output template |
|---|---|---|
| W1 Triage & IR | Alert, logs, EVTX, PCAP summary | Threat Summary + Containment Playbook |
| W2 Detection Engineering | CVE, report, TTP | Detection Rule (Sigma + platform translations, FPs, evasions, validation) |
| W3 Threat Hunting | Actor / TTP / asset | Hunt Report |
| W4 DFIR Reconstruction | $MFT, Prefetch, Amcache, Volatility, KAPE/UAC output | DFIR Timeline |
| W5 Prioritization | CVE list, scan results | Vuln Priority Table (KEV, EPSS, CVSS v4, exposure) |
| W6 Hardening Review | Config, baseline question | Hardening Findings (fix, validation, rollback) |

**Examples**

```text
/claude-blue Triage: Sysmon EID 10, SourceImage C:\Users\Public\svc.exe, TargetImage lsass.exe, GrantedAccess 0x1410
Write a Kerberoasting detection for Splunk, Sentinel, and Wazuh.
Hunt for DNS tunneling using Zeek dns.log.
Here is windows.pslist, netscan, and malfind output — what happened?
Harden this Cisco access switch config against ARP spoofing and rogue DHCP.
Prioritize these 40 CVEs for our internet-facing servers.
```

---

## Categories

| Category | Skills | Focus |
|---|---:|---|
| [Core](#core) | 1 | Router, principles, workflows, templates |
| [SOC Operations](#soc-operations) | 4 | Triage, log sources, playbooks, SOAR |
| [Detection Engineering](#detection-engineering) | 5 | Sigma, YARA/YARA-X, Suricata/Snort, query languages, detection-as-code |
| [SIEM Platforms](#siem-platforms) | 5 | Wazuh, Elastic, Splunk, Sentinel/Defender XDR, Security Onion/Graylog |
| [Threat Hunting](#threat-hunting) | 3 | Methodology, Windows hunts, network hunts |
| [Incident Response](#incident-response) | 5 | IR command, live response, ransomware, BEC, cloud IR |
| [Digital Forensics](#digital-forensics) | 5 | Windows, Linux, macOS, memory, timelines |
| [Malware Analysis](#malware-analysis) | 3 | Static triage, dynamic analysis, malicious documents |
| [Threat Intelligence](#threat-intelligence) | 3 | CTI, ATT&CK/D3FEND mapping, IOC management |
| [Endpoint](#endpoint) | 5 | Windows event logs, Sysmon, Linux telemetry, EDR tuning, Windows hardening |
| [Active Directory](#active-directory) | 2 | AD/AD CS hardening, AD attack detection |
| [Identity](#identity) | 2 | Entra ID, secure auth implementation |
| [Application Security](#application-security) | 4 | Secure code review, WAF, API security, SAST/DAST |
| [Network Defense](#network-defense) | 5 | Zeek, PCAP, firewall/NetFlow, segmentation, L2 security |
| [Wireless](#wireless) | 2 | WIDS, secure Wi-Fi design |
| [Cloud](#cloud) | 4 | AWS, Azure, GCP, CSPM/IaC |
| [Container & Kubernetes](#container--kubernetes) | 2 | Container hardening, Kubernetes security |
| [Supply Chain & CI/CD](#supply-chain--cicd) | 3 | Pipeline hardening, secrets, SBOM/SLSA |
| [Vulnerability Management](#vulnerability-management) | 2 | Risk-based prioritization, patching |
| [Hardening](#hardening) | 2 | Linux, Cisco/Huawei network devices |
| [Email Security](#email-security) | 2 | SPF/DKIM/DMARC, phishing triage |
| [Deception](#deception) | 1 | Honeytokens, honey accounts, honeypots |
| [OT/ICS](#otics) | 1 | Purdue/IEC 62443, ICS protocol monitoring |
| [AI Security](#ai-security) | 1 | LLM & agent security (OWASP LLM + Agentic Top 10) |
| [Purple Team](#purple-team) | 2 | Detection validation, adversary emulation |
| [GRC](#grc) | 2 | Framework mapping, threat modeling & risk |
| [Utility](#utility) | 2 | IR reporting, 30-minute compromise checks |

---

## Skill Index

### Core
`Skills/core/`

| Skill | Description |
|---|---|
| [`claude-blue`](Skills/core/claude-blue/SKILL.md) | Router and standards: principles, workflows W1–W6, skill router, output templates, current-state notes |

### SOC Operations
`Skills/soc/`

| Skill | Description |
|---|---|
| [`defensive-alert-triage`](Skills/soc/defensive-alert-triage/SKILL.md) | Entity extraction, enrichment order, TP/BTP/FP verdicts, severity, escalation, closing notes |
| [`defensive-log-sources`](Skills/soc/defensive-log-sources/SKILL.md) | Audit policy, Sysmon, cloud logs, schemas (ECS/CIM/ASIM/OCSF/UDM), retention, silent-source alerts |
| [`defensive-soc-playbooks`](Skills/soc/defensive-soc-playbooks/SKILL.md) | Playbook template, containment authority, NIST 800-61r3, notification timelines, metrics |
| [`defensive-soar-automation`](Skills/soc/defensive-soar-automation/SKILL.md) | What to automate, guardrails, Shuffle/TheHive/Sentinel/Wazuh AR, securing automation |

### Detection Engineering
`Skills/detection/`

| Skill | Description |
|---|---|
| [`defensive-sigma`](Skills/detection/defensive-sigma/SKILL.md) | Rule anatomy, modifiers, correlation rules, filters, pySigma backends/pipelines, Hayabusa/Chainsaw |
| [`defensive-yara`](Skills/detection/defensive-yara/SKILL.md) | YARA/YARA-X rules, performance, migration, testing, memory scanning, YARA-L |
| [`defensive-suricata-snort`](Skills/detection/defensive-suricata-snort/SKILL.md) | Suricata 8 buffers, flowbits/datasets, thresholds, EVE analysis, Snort 3 |
| [`defensive-query-languages`](Skills/detection/defensive-query-languages/SKILL.md) | SPL, KQL, EQL, ES\|QL, Lucene, Wazuh XML, Graylog, Athena — operator map and patterns |
| [`defensive-detection-as-code`](Skills/detection/defensive-detection-as-code/SKILL.md) | Repo layout, CI, tests, staged rollout, ATT&CK v18 coverage, metrics |

### SIEM Platforms
`Skills/siem/`

| Skill | Description |
|---|---|
| [`defensive-wazuh`](Skills/siem/defensive-wazuh/SKILL.md) | Agents/groups, rules & decoders, wazuh-logtest, FIM, SCA, active response, integrations |
| [`defensive-elastic`](Skills/siem/defensive-elastic/SKILL.md) | Fleet integrations, ECS, rule types (EQL/ES\|QL/new terms), exceptions, Timeline, Osquery |
| [`defensive-splunk`](Skills/siem/defensive-splunk/SKILL.md) | TAs, CIM, tstats, ES 8, risk-based alerting, ESCU |
| [`defensive-sentinel`](Skills/siem/defensive-sentinel/SKILL.md) | Connectors/DCRs, analytics rules, ASIM, UEBA, data lake, Defender portal transition |
| [`defensive-security-onion`](Skills/siem/defensive-security-onion/SKILL.md) | NSM deployment, sensor placement, Hunt/Cases/PCAP, Graylog, lab design |

### Threat Hunting
`Skills/hunting/`

| Skill | Description |
|---|---|
| [`defensive-threat-hunting`](Skills/hunting/defensive-threat-hunting/SKILL.md) | PEAK, TaHiTI, hypotheses, data readiness, analysis techniques, hunt reports |
| [`defensive-hunt-windows`](Skills/hunting/defensive-hunt-windows/SKILL.md) | Lineage, LOLBins, PowerShell, persistence, credential access, injection, BYOVD, evasion |
| [`defensive-hunt-network`](Skills/hunting/defensive-hunt-network/SKILL.md) | Beaconing (CV), long connections, DNS tunneling/DGA, TLS/JA4, exfil, east-west |

### Incident Response
`Skills/ir/`

| Skill | Description |
|---|---|
| [`defensive-incident-response`](Skills/ir/defensive-incident-response/SKILL.md) | Roles, scoping, evidence, containment strategy & library, eradication, RCA, sitreps |
| [`defensive-live-response`](Skills/ir/defensive-live-response/SKILL.md) | Velociraptor, EDR live response, memory acquisition, volatile data, KAPE, UAC |
| [`defensive-ransomware-response`](Skills/ir/defensive-ransomware-response/SKILL.md) | Precursors, imminent-encryption signals, first-hour containment, identity-first recovery |
| [`defensive-bec-response`](Skills/ir/defensive-bec-response/SKILL.md) | AiTM token theft, inbox rules, OAuth grants, revocation order, payment recall |
| [`defensive-cloud-ir`](Skills/ir/defensive-cloud-ir/SKILL.md) | AWS/Azure/GCP credential revocation, scoping, persistence, snapshots, GuardDuty attack sequences |

### Digital Forensics
`Skills/forensics/`

| Skill | Description |
|---|---|
| [`defensive-windows-forensics`](Skills/forensics/defensive-windows-forensics/SKILL.md) | Artifact semantics table, EZ Tools commands, timestomping, execution validation |
| [`defensive-linux-forensics`](Skills/forensics/defensive-linux-forensics/SKILL.md) | Auth timeline, persistence sweep, package integrity, web shells, Volatility linux plugins |
| [`defensive-macos-forensics`](Skills/forensics/defensive-macos-forensics/SKILL.md) | Unified Log, eslogger/ESF, BTM, TCC, quarantine, infostealer patterns |
| [`defensive-memory-forensics`](Skills/forensics/defensive-memory-forensics/SKILL.md) | Volatility 3 process/injection/network analysis, MemProcFS |
| [`defensive-timeline-analysis`](Skills/forensics/defensive-timeline-analysis/SKILL.md) | Plaso, Timesketch, anchor-and-pivot, MACB, narrative output |

### Malware Analysis
`Skills/malware/`

| Skill | Description |
|---|---|
| [`defensive-malware-triage`](Skills/malware/defensive-malware-triage/SKILL.md) | PE structure, FLOSS, capa, packers, script deobfuscation, deliverables |
| [`defensive-dynamic-analysis`](Skills/malware/defensive-dynamic-analysis/SKILL.md) | Lab design, monitoring stack, anti-analysis, sandboxes, behavior → detection |
| [`defensive-maldoc-analysis`](Skills/malware/defensive-maldoc-analysis/SKILL.md) | Office/RTF/PDF/LNK/ISO/OneNote/HTML smuggling/SVG lure analysis |

### Threat Intelligence
`Skills/cti/`

| Skill | Description |
|---|---|
| [`defensive-cti`](Skills/cti/defensive-cti/SKILL.md) | PIRs, Diamond Model, TTP extraction, Admiralty code, estimative language, TLP 2.0 |
| [`defensive-attack-mapping`](Skills/cti/defensive-attack-mapping/SKILL.md) | ATT&CK v18 structure, coverage scoring, Navigator layers, D3FEND 1.0 |
| [`defensive-ioc-management`](Skills/cti/defensive-ioc-management/SKILL.md) | IOC quality gates, MISP, OpenCTI, STIX/TAXII, distribution, retro-hunting |

### Endpoint
`Skills/endpoint/`

| Skill | Description |
|---|---|
| [`defensive-windows-event-logs`](Skills/endpoint/defensive-windows-event-logs/SKILL.md) | Event ID reference, logon types, Kerberos/NTLM attacks, RPC pipes, ETW/AMSI |
| [`defensive-sysmon`](Skills/endpoint/defensive-sysmon/SKILL.md) | EID 1–29, config design, native Windows 11 Sysmon, Sysmon for Linux, volume control |
| [`defensive-linux-telemetry`](Skills/endpoint/defensive-linux-telemetry/SKILL.md) | auditd rules, Falco/Tetragon, osquery, Linux detection catalog |
| [`defensive-edr-tuning`](Skills/endpoint/defensive-edr-tuning/SKILL.md) | Coverage, exclusion governance, tamper protection, EDR-blinding detection |
| [`defensive-windows-hardening`](Skills/endpoint/defensive-windows-hardening/SKILL.md) | ASR rules, LSA PPL, Credential Guard, LAPS, WDAC, protocol hardening |

### Active Directory
`Skills/active-directory/`

| Skill | Description |
|---|---|
| [`defensive-ad-hardening`](Skills/active-directory/defensive-ad-hardening/SKILL.md) | Tier 0, tiering, attack-path reduction, Kerberos/NTLM changes, AD CS ESC1–ESC16 fixes |
| [`defensive-ad-detection`](Skills/active-directory/defensive-ad-detection/SKILL.md) | Kerberoast/AS-REP/DCSync/tickets/relay/shadow creds/AD CS detections, honey accounts |

### Identity
`Skills/identity/`

| Skill | Description |
|---|---|
| [`defensive-entra-id`](Skills/identity/defensive-entra-id/SKILL.md) | Conditional Access, PIM, Token Protection, CAE, consent governance, detections |
| [`defensive-auth-implementation`](Skills/identity/defensive-auth-implementation/SKILL.md) | OAuth 2.x/OIDC, JWT validation, SAML, sessions, passwords/MFA, negative tests |

### Application Security
`Skills/appsec/`

| Skill | Description |
|---|---|
| [`defensive-secure-code-review`](Skills/appsec/defensive-secure-code-review/SKILL.md) | OWASP Top 10:2025, sink-level fixes per language, write-up format |
| [`defensive-waf`](Skills/appsec/defensive-waf/SKILL.md) | OWASP CRS tuning, virtual patching, cloud WAFs, bypass classes |
| [`defensive-api-security`](Skills/appsec/defensive-api-security/SKILL.md) | OWASP API Top 10, BOLA-safe patterns, schema validation, GraphQL, abuse detection |
| [`defensive-sast-dast`](Skills/appsec/defensive-sast-dast/SKILL.md) | Semgrep/CodeQL/OSV/Trivy/gitleaks/ZAP pipeline, triage, SLAs |

### Network Defense
`Skills/network/`

| Skill | Description |
|---|---|
| [`defensive-zeek`](Skills/network/defensive-zeek/SKILL.md) | Log reference, conn_state, analysis snippets, Intel framework, scripting |
| [`defensive-pcap-analysis`](Skills/network/defensive-pcap-analysis/SKILL.md) | Capture, tshark triage, display filters, extraction, pattern recognition |
| [`defensive-firewall-analysis`](Skills/network/defensive-firewall-analysis/SKILL.md) | PAN-OS/FortiGate/ASA/pfSense logs, NetFlow, detections, rule-base review |
| [`defensive-network-segmentation`](Skills/network/defensive-network-segmentation/SKILL.md) | Zones, ACL design (Cisco & Huawei), east-west restriction, zero trust, validation |
| [`defensive-l2-security`](Skills/network/defensive-l2-security/SKILL.md) | DHCP snooping, DAI, IPSG, port security, STP guards, 802.1X (Cisco & Huawei) |

### Wireless
`Skills/wireless/`

| Skill | Description |
|---|---|
| [`defensive-wireless-ids`](Skills/wireless/defensive-wireless-ids/SKILL.md) | Rogue/evil twin/deauth detection, Kismet, wired correlation, response |
| [`defensive-wireless-design`](Skills/wireless/defensive-wireless-design/SKILL.md) | WPA3, EAP-TLS, PMF, server cert validation, guest/IoT segmentation |

### Cloud
`Skills/cloud/`

| Skill | Description |
|---|---|
| [`defensive-aws-security`](Skills/cloud/defensive-aws-security/SKILL.md) | SCP guardrails, identity, logging, GuardDuty, CloudTrail detections |
| [`defensive-azure-security`](Skills/cloud/defensive-azure-security/SKILL.md) | Azure Policy, RBAC/PIM, Defender for Cloud, Sentinel detections |
| [`defensive-gcp-security`](Skills/cloud/defensive-gcp-security/SKILL.md) | Org policies, service account security, audit logs, SCC, detections |
| [`defensive-cspm`](Skills/cloud/defensive-cspm/SKILL.md) | Prowler/Steampipe/native CSPM, toxic combinations, IaC scanning, drift |

### Container & Kubernetes
`Skills/container/`

| Skill | Description |
|---|---|
| [`defensive-container-hardening`](Skills/container/defensive-container-hardening/SKILL.md) | Dockerfile, runtime flags, capabilities, scanning, cosign signing, daemon hardening |
| [`defensive-k8s-security`](Skills/container/defensive-k8s-security/SKILL.md) | RBAC, Pod Security Admission, Kyverno, NetworkPolicy, audit policy & detections |

### Supply Chain & CI/CD
`Skills/supply-chain/`

| Skill | Description |
|---|---|
| [`defensive-cicd-hardening`](Skills/supply-chain/defensive-cicd-hardening/SKILL.md) | GitHub Actions hardening, pwn requests, cache poisoning, OIDC, trusted publishing |
| [`defensive-secrets-management`](Skills/supply-chain/defensive-secrets-management/SKILL.md) | Vaults, dynamic creds, scanning, leak response runbook per secret type |
| [`defensive-sbom-slsa`](Skills/supply-chain/defensive-sbom-slsa/SKILL.md) | CycloneDX/SPDX, VEX, SLSA, Sigstore, dependency defenses, compromised-upstream playbook |

### Vulnerability Management
`Skills/vuln-mgmt/`

| Skill | Description |
|---|---|
| [`defensive-vuln-management`](Skills/vuln-mgmt/defensive-vuln-management/SKILL.md) | CVSS v4, EPSS v4, KEV, SSVC, BOD 26-04 matrix, post-NVD data sources, EU CRA |
| [`defensive-patch-management`](Skills/vuln-mgmt/defensive-patch-management/SKILL.md) | Rings, emergency lane, edge appliances, verification, rollback, EOL |

### Hardening
`Skills/hardening/`

| Skill | Description |
|---|---|
| [`defensive-linux-hardening`](Skills/hardening/defensive-linux-hardening/SKILL.md) | OpenSCAP/Lynis, SSH, sudo/PAM, sysctl, SELinux/AppArmor, nftables |
| [`defensive-network-device-hardening`](Skills/hardening/defensive-network-device-hardening/SKILL.md) | Cisco IOS & Huawei VRP: AAA, SSH, SNMPv3, NTP auth, CoPP, routing auth |

### Email Security
`Skills/email/`

| Skill | Description |
|---|---|
| [`defensive-email-auth`](Skills/email/defensive-email-auth/SKILL.md) | SPF, DKIM, DMARCbis (RFC 9989), MTA-STS, TLS-RPT, BIMI, rollout |
| [`defensive-phishing-triage`](Skills/email/defensive-phishing-triage/SKILL.md) | Header/URL analysis, AiTM & quishing, scope, purge, verdict notes |

### Deception
`Skills/deception/`

| Skill | Description |
|---|---|
| [`defensive-deception`](Skills/deception/defensive-deception/SKILL.md) | Canarytokens, honey SPN/AS-REP accounts, OpenCanary, placement, MITRE ENGAGE |

### OT/ICS
`Skills/ot/`

| Skill | Description |
|---|---|
| [`defensive-ics-security`](Skills/ot/defensive-ics-security/SKILL.md) | Purdue/IEC 62443, ICS protocols, Malcolm/ICSNPP, safe vuln mgmt, OT IR |

### AI Security
`Skills/ai/`

| Skill | Description |
|---|---|
| [`defensive-ai-security`](Skills/ai/defensive-ai-security/SKILL.md) | OWASP LLM Top 10 2025, Agentic Top 10 2026, prompt injection, MCP, RAG, monitoring |

### Purple Team
`Skills/purple/`

| Skill | Description |
|---|---|
| [`defensive-purple-team`](Skills/purple/defensive-purple-team/SKILL.md) | Atomic Red Team, Caldera, outcome scoring, gap fixing, red↔blue pairing |
| [`defensive-adversary-emulation`](Skills/purple/defensive-adversary-emulation/SKILL.md) | CTI → procedures, plan structure, RoE, CTID library, metrics |

### GRC
`Skills/grc/`

| Skill | Description |
|---|---|
| [`defensive-frameworks`](Skills/grc/defensive-frameworks/SKILL.md) | NIST CSF 2.0, CIS v8.1, ISO 27001:2022, PCI DSS 4.0.1, NIS2, DORA, PH DPA crosswalk |
| [`defensive-risk-threat-modeling`](Skills/grc/defensive-risk-threat-modeling/SKILL.md) | STRIDE, attack trees, risk scoring, FAIR basics, risk register |

### Utility
`Skills/utility/`

| Skill | Description |
|---|---|
| [`defensive-ir-reporting`](Skills/utility/defensive-ir-reporting/SKILL.md) | Report structure, executive summaries, language standards, blameless reviews |
| [`defensive-quick-checks`](Skills/utility/defensive-quick-checks/SKILL.md) | 30-minute compromise checks for Windows/Linux/macOS/cloud with red-flag tables |

---

## Red ↔ Blue Map

Load both libraries for purple-team work. claude-red supplies the technique; claude-blue supplies its detection, containment, and hardening.

| claude-red | claude-blue |
|---|---|
| `offensive-sqli`, `offensive-xss`, `offensive-ssrf`, `offensive-ssti`, `offensive-deserialization`, `offensive-xxe` | `defensive-secure-code-review`, `defensive-waf` |
| `offensive-waf-bypass`, `offensive-request-smuggling` | `defensive-waf` |
| `offensive-api-security`, `offensive-api-abuse`, `offensive-graphql`, `offensive-idor` | `defensive-api-security` |
| `offensive-jwt`, `offensive-oauth` | `defensive-auth-implementation`, `defensive-entra-id` |
| `offensive-active-directory` | `defensive-ad-hardening`, `defensive-ad-detection`, `defensive-windows-event-logs` |
| `offensive-wifi`, `offensive-evil-twin`, `offensive-deauth-disassoc`, `offensive-wpa-enterprise` | `defensive-wireless-ids`, `defensive-wireless-design` |
| `offensive-cloud` | `defensive-aws-security`, `defensive-azure-security`, `defensive-gcp-security`, `defensive-cloud-ir` |
| `offensive-container-escape`, `offensive-k8s-attacks` | `defensive-container-hardening`, `defensive-k8s-security` |
| `offensive-cicd-pipeline`, `offensive-cicd-secrets` | `defensive-cicd-hardening`, `defensive-secrets-management` |
| `offensive-supply-chain`, `offensive-dependency-confusion` | `defensive-sbom-slsa` |
| `offensive-edr-evasion`, `offensive-shellcode`, `offensive-windows-mitigations` | `defensive-edr-tuning`, `defensive-sysmon`, `defensive-memory-forensics`, `defensive-windows-hardening` |
| `offensive-initial-access`, `offensive-phishing`, `offensive-social-engineering` | `defensive-phishing-triage`, `defensive-email-auth`, `defensive-maldoc-analysis` |
| `offensive-linux-privesc` | `defensive-linux-hardening`, `defensive-linux-telemetry`, `defensive-linux-forensics` |
| `offensive-windows-privesc` | `defensive-windows-hardening`, `defensive-hunt-windows` |
| `offensive-lateral-movement`, `offensive-persistence` | `defensive-hunt-windows`, `defensive-ad-detection`, `defensive-windows-forensics` |
| `offensive-data-exfiltration`, `offensive-c2-frameworks` | `defensive-hunt-network`, `defensive-zeek`, `defensive-firewall-analysis` |
| `offensive-anti-forensics` | `defensive-timeline-analysis`, `defensive-windows-forensics`, `defensive-log-sources` |
| `offensive-network-attacks` | `defensive-l2-security`, `defensive-pcap-analysis`, `defensive-network-segmentation` |
| `offensive-iot` | `defensive-ics-security` |
| `offensive-osint`, `offensive-osint-methodology` | `defensive-cti` |
| `offensive-ai-security` | `defensive-ai-security` |
| `offensive-crypto-attacks`, `offensive-tls-attacks` | `defensive-auth-implementation`, `defensive-secure-code-review` |
| `offensive-reporting` | `defensive-ir-reporting` |
| `offensive-fast-checking` | `defensive-quick-checks` |

Run offensive techniques only in environments you are authorized to test.

---

## Repository Layout

```text
claude-blue/
├── Skills/<category>/<skill>/SKILL.md    # 78 skills
├── install.sh                            # flattening installer (copy/link, category/skill filters)
├── claude-skills.json                    # generated manifest
├── tools/check-skill.sh                  # linter (frontmatter, name/folder, description ≤1024, sections, fences)
├── tools/build_manifest.py               # regenerates claude-skills.json
├── .github/workflows/validate.yml        # CI lint + manifest check
├── MINDMAP.md  CHANGELOG.md  CONTRIBUTING.md  SECURITY.md  LICENSE
```

---

## Roadmap

| Phase | Focus | Status |
|---|---|---|
| 1 | 78 skills across 27 categories, router skill, installer, linter, manifest | ✓ Complete (v1.0) |
| 2 | `tests/` — sample logs with expected verdicts per skill for regression testing | Planned |
| 3 | Tested Sigma rule pack with TP/FP samples and CI conversion to SPL/KQL/ES\|QL | Planned |
| 4 | Split dense skills (e.g., `defensive-hunt-windows` → persistence, credential access, injection) | Planned |
| 5 | Platform add-ons: CrowdStrike, SentinelOne, Google SecOps, QRadar, Chronicle YARA-L packs | Planned |
| 6 | macOS and mobile (MDM, iOS/Android) defense skills | Planned |
| 7 | Localized content: Philippine regulatory notes (NPC, DICT/CERT-PH), APAC threat profiles | Planned |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

1. One skill, one surface.
2. Frontmatter `name` must equal the folder name. The description should be dense with trigger terms and must be 1,024 characters or fewer.
3. Every event ID, field, command, and query must be verified against vendor docs or a lab.
4. Detections need TP/FP samples and validator output.
5. Run `bash tools/check-skill.sh` and `python3 tools/build_manifest.py` before opening a PR.

---

## Disclaimer

Detections, queries, and commands are starting points. Field names vary by ingestion pipeline and product version. Test in staging, and get approval before running containment actions in production. Use only on systems you are authorized to defend.

## License

[MIT](LICENSE). Use freely; attribution appreciated.

## Author

**Ranilo John Delos Angeles**, CCNA, Sec+ — [Portfolio](https://ranilojohn.github.io/Portfolio-Website/)

## Acknowledgements

- Structure and format inspired by [claude-red](https://github.com/SnailSploit/claude-red) by Kai Aizen (SnailSploit), MIT
- MITRE ATT&CK, D3FEND, ENGAGE and ATLAS; SigmaHQ; FIRST (CVSS, EPSS, TLP); CISA (KEV, SSVC, BOD 26-04)
- OWASP (Top 10, API, LLM and Agentic Top 10, CRS, ASVS); CIS (Benchmarks and Controls)
- Open-source defenders: Volatility Foundation, Eric Zimmerman, Plaso/Timesketch, Velociraptor, Zeek, Suricata, Wazuh, Security Onion, Falco, Atomic Red Team, Hayabusa, Chainsaw, YARA-X, Prowler

---

*Red finds the gap. Blue closes it.*
