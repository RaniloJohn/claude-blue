<p align="center">
  <img src="assets/claude-blue-header.png" alt="claude blue — a library of Claude blue team skills" width="100%">
</p>

<p align="center">
  <b>Defensive security skills for Claude: drop-in <code>SKILL.md</code> files that turn Claude into a context-aware blue team operator.</b><br>
  SOC triage · detection engineering · threat hunting · DFIR · network security · defense architecture · research-first analysis
</p>

<p align="center">
  <a href="LICENSE"><img alt="license MIT" src="https://img.shields.io/badge/license-MIT-0a66c2"></a>
  <img alt="skills 184" src="https://img.shields.io/badge/skills-184-1f6feb">
  <img alt="categories 32" src="https://img.shields.io/badge/categories-32-0e8a16">
  <img alt="MITRE ATT&CK v18" src="https://img.shields.io/badge/MITRE%20ATT%26CK-v18-informational">
  <img alt="version 1.2.4" src="https://img.shields.io/badge/version-1.2.4-brightgreen">
  <a href="https://github.com/ranilojohn/claude-blue/stargazers"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/ranilojohn/claude-blue?style=social"></a>
  <a href="https://github.com/ranilojohn/claude-blue/network/members"><img alt="GitHub Forks" src="https://img.shields.io/github/forks/ranilojohn/claude-blue?style=social"></a>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#defense-model">Defense Model</a> •
  <a href="#categories">Categories</a> •
  <a href="#skill-index">Skill Index</a> •
  <a href="#red--blue-map">Red ↔ Blue</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <sub>Built in the format of <a href="https://github.com/SnailSploit/claude-red"><b>claude-red</b></a> by <a href="https://github.com/SnailSploit"><b>Kai Aizen (SnailSploit)</b></a>. Full credit to him for the original skill-library concept and structure.</sub>
</p>

---

## Overview

`claude-blue` is a library of defensive security skills for [Claude Skills](https://docs.claude.com). It is the blue-team counterpart to [claude-red](https://github.com/SnailSploit/claude-red).

- **184 skills in 32 categories.** Each skill covers one defensive surface.
- **One umbrella skill, `claude-blue`.** It sets operating standards, routes each task to the right specialist, and enforces fixed output templates.

Skills load on demand from conversational triggers. For example, pasting a 4769 event loads `defensive-ad-detection`. Asking about a rogue router advertisement loads `defensive-ipv6-security`. Asking "should we deploy Velociraptor?" loads `defensive-blue-research` and `defensive-tool-velociraptor`. Context is spent only on what you use.

**Use cases**

- **SOC work:** L1/L2 triage, incident response, DFIR, detection engineering, threat hunting.
- **Security engineering:** network security design, zero trust and defense-in-depth reviews, hardening, vulnerability prioritization.
- **Programs and training:** tool deployment, SOC/SIEM lab builds, purple teaming, analyst training.

**What's in v1.1**

- **12 ATT&CK tactic detection packs.**
- **Defense model:** 10 skills covering fundamentals through resilience.
- **Network security:** 20 skills, with Cisco and Huawei configs.
- **SIEM/XDR:** 11 platforms.
- **Tools:** 23 skills built from official documentation and current advisories.
- **Research:** a research-first methodology skill.

**Standards every skill follows**

- **Evidence before verdict.** Observed facts are kept separate from inferences, and each conclusion carries a confidence level.
- **Research first, verify currency.** Versions, advisories, schemas, and laws change, so primary sources are checked and the date checked is stated.
- **No fabrication.** IOCs, event fields, CVE details, and tool flags are never invented.
- **UTC timestamps and defanged indicators.**
- **Preserve before containment.** Evidence is preserved first, and every action states its blast radius.
- **Tools are Tier 0.** Every tool is verified, pinned, hardened, and run with least privilege.
- **Sigma first.** Detections are written in Sigma, then translated to SPL, KQL, EQL, ES|QL, AQL, CQL, YARA-L, Wazuh, YARA, Suricata, or Falco.
- **Current to October 2026.** Coverage includes:
  - Frameworks: ATT&CK v18, D3FEND 1.0, OWASP Top 10:2025, NIST SP 800-63-4.
  - Vulnerability and policy: CISA BOD 26-02 and 26-04, EPSS v4, DMARCbis (RFC 9989).
  - Windows and Kerberos: the 2026 Kerberos RC4 removal and native Sysmon.
  - TLS: the CA/B SC-081 certificate lifetime cuts.
  - Tool changes: the Trivy supply chain compromise, Wazuh and Velociraptor 2026 advisories, Security Onion 3, Zeek 9, and Falco 0.44+.

---

## Quickstart

### Claude Code: all skills

```bash
git clone https://github.com/ranilojohn/claude-blue
cd claude-blue
./install.sh                         # copies all 184 skills to ~/.claude/skills
```

Claude Code discovers skills one level deep (`~/.claude/skills/<skill>/SKILL.md`). The installer flattens `Skills/<category>/<skill>` for you.

### Selected categories or skills

```bash
./install.sh --category soc,detection-packs,siem,network     # also installs the claude-blue router
./install.sh --category tools,research                        # doc-verified tool skills + research methodology
./install.sh --skill defensive-tool-wazuh,defensive-sigma
./install.sh --core-only                                      # only the umbrella skill
./install.sh --link                                           # symlink, so `git pull` updates skills
./install.sh --target .claude/skills                          # project-level (share with team via git)
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
            ┌──────────────────────────────────┐
  you  ───► │   claude-blue  (router skill)    │ ── 14 principles · workflows W1–W8 · output templates
            └────────────────┬─────────────────┘
                             │ loads the matching specialist(s)
   ┌───────────┬─────────────┼─────────────┬──────────────┬──────────────┬─────────────┐
   ▼           ▼             ▼             ▼              ▼              ▼             ▼
 triage &   detection     hunting &     network &      defense        tools &      research
 IR / DFIR  & ATT&CK      intel         cloud/identity  model          platforms    & GRC
            packs
```

| Workflow | Input | Output template |
|---|---|---|
| W1 Triage & IR | Alert, logs, EVTX, PCAP summary | Threat Summary + Containment Playbook |
| W2 Detection Engineering | CVE, report, TTP | Detection Rule (Sigma + platform translations, FPs, evasions, validation) |
| W3 Threat Hunting | Actor / TTP / asset | Hunt Report |
| W4 DFIR Reconstruction | $MFT, Prefetch, Amcache, Volatility, KAPE/Velociraptor output | DFIR Timeline |
| W5 Prioritization | CVE list, scan results | Vuln Priority Table (KEV, EPSS, CVSS v4, SSVC, exposure) |
| W6 Hardening Review | Config, baseline question | Hardening Findings (fix, validation, rollback) |
| W7 Defense Architecture | "Assess our defenses", network/zero-trust design | Coverage matrix + Hardening Findings + roadmap |
| W8 Research & Recommendation | "Should we…?", tool/product/CVE/regulation questions | Recommendation (confidence, verification, residual risk, cited sources with dates) |

**Examples**

```text
/claude-blue Triage: Sysmon EID 10, SourceImage C:\Users\Public\svc.exe, TargetImage lsass.exe, GrantedAccess 0x1410
Write a Kerberoasting detection for Splunk, Sentinel, Wazuh, and Google SecOps YARA-L.
Hunt for DNS tunneling and beaconing using Zeek and RITA.
Here is windows.pslist, netscan, and malfind output — what happened?
Design zones and a flow matrix for our campus + data center; give Cisco and Huawei ACLs.
Harden our IPv6 access layer against rogue RAs and mitm6.
Is our Wazuh deployment safe to expose to remote agents? Check current advisories.
Prioritize these 40 CVEs for our internet-facing servers.
```

---

## Defense Model

claude-blue is organized around a complete defensive model, not a list of tools:

```text
 GOVERN     security-operating-model · frameworks · risk-threat-modeling · security-metrics
 KNOW       security-fundamentals · kill-chain-defense · threat-informed-defense · cti · blue-research
 DESIGN     security-architecture · defense-in-depth · zero-trust-architecture · network-security-architecture
 PROTECT    hardening (Windows/Linux/network devices) · identity · AD · cloud · containers · appsec · email · NAC · VPN/ZTNA
 DETECT     12 ATT&CK detection packs · Sigma/YARA/Suricata · SIEM/XDR platforms · NDR/NetFlow · UEBA · deception
 RESPOND    alert triage · incident response · live response · ransomware/BEC/cloud IR · forensics · malware analysis
 RECOVER    cyber-resilience · ad-forest-recovery · ir-reporting
 VALIDATE   purple team · adversary emulation · d3fend-countermeasures · active-defense
 OPERATE    tool-safety + 22 doc-verified tool skills · log parsing · SOC building · SOAR
```

Every layer is mapped to **NIST CSF 2.0** (Govern, Identify, Protect, Detect, Respond, Recover), **MITRE ATT&CK v18**, and **MITRE D3FEND**.

---

## Categories

| Category | Skills | Focus |
|---|---:|---|
| [Core](#core) | 1 | Router, principles, workflows W1–W8, templates |
| [Research](#research) | 2 | Research-first methodology, CVE research & coordinated disclosure |
| [Defense Model](#defense-model) | 10 | Fundamentals, defense in depth, zero trust, architecture, kill chain, D3FEND, resilience |
| [SOC Operations](#soc-operations) | 8 | Triage, log sources & parsing, playbooks, SOAR, SOC build, metrics, UEBA |
| [Detection Engineering](#detection-engineering) | 5 | Sigma, YARA/YARA-X, Suricata/Snort, query languages, detection-as-code |
| [ATT&CK Detection Packs](#attck-detection-packs) | 12 | One pack per ATT&CK tactic: telemetry, rules, FPs, triage |
| [SIEM & XDR Platforms](#siem--xdr-platforms) | 11 | Wazuh, Elastic, Splunk, Sentinel, Security Onion, Graylog, QRadar, Google SecOps, Defender XDR, CrowdStrike, SentinelOne |
| [Threat Hunting](#threat-hunting) | 5 | Methodology, Windows hunts, network hunts |
| [Incident Response](#incident-response) | 7 | IR command, live response, ransomware, BEC, cloud IR |
| [Digital Forensics](#digital-forensics) | 9 | Windows, Linux, macOS, memory, timelines |
| [Malware Analysis](#malware-analysis) | 6 | Static triage, dynamic analysis, malicious documents |
| [Threat Intelligence](#threat-intelligence) | 3 | CTI, ATT&CK/D3FEND mapping, IOC management |
| [Endpoint](#endpoint) | 8 | Windows event logs, Sysmon, Linux telemetry, EDR tuning, Windows hardening, application control |
| [Active Directory](#active-directory) | 3 | AD/AD CS hardening, attack detection, forest recovery |
| [Identity](#identity) | 7 | Entra ID, secure auth implementation |
| [Application Security](#application-security) | 6 | Secure code review, WAF, API security, SAST/DAST |
| [Network Security](#network-security) | 20 | Architecture, NGFW, IDS/IPS, NDR, forensics, DNS, proxy/TLS, ZTNA, VPN, NAC, IPv6, BGP, SASE, DDoS, PKI, L2, segmentation |
| [Wireless](#wireless) | 2 | WIDS, secure Wi-Fi design |
| [Cloud](#cloud) | 7 | AWS, Azure, GCP, CSPM/IaC |
| [Container & Kubernetes](#container--kubernetes) | 2 | Container hardening, Kubernetes security |
| [Supply Chain & CI/CD](#supply-chain--cicd) | 3 | Pipeline hardening, secrets, SBOM/SLSA |
| [Vulnerability Management](#vulnerability-management) | 5 | Risk-based prioritization, patching, asset inventory, testing programs, PSIRT & disclosure handling |
| [Hardening](#hardening) | 3 | Linux, Cisco/Huawei network devices |
| [Email Security](#email-security) | 2 | SPF/DKIM/DMARC, phishing triage |
| [Deception](#deception) | 1 | Honeytokens, honey accounts, honeypots |
| [OT/ICS](#otics) | 1 | Purdue/IEC 62443, ICS protocol monitoring |
| [AI Security](#ai-security) | 1 | LLM & agent security (OWASP LLM + Agentic Top 10) |
| [Human & Physical](#human--physical) | 2 | Security awareness, physical security |
| [Purple Team](#purple-team) | 2 | Detection validation, adversary emulation |
| [GRC](#grc) | 5 | Framework mapping, threat modeling & risk |
| [Utility](#utility) | 2 | IR reporting, 30-minute compromise checks |
| [Tools](#tools) | 23 | Doc-verified safe operation of 22 tool families + tool-safety umbrella |
| **Total** | **184** | |

---

## Skill Index

### Core

`Skills/core/`

| Skill | What it covers |
|---|---|
| [`claude-blue`](Skills/core/claude-blue/SKILL.md) | Router and standards: principles, workflows W1–W6, skill router, output templates, current-state notes |

### Research

`Skills/research/`

| Skill | What it covers |
|---|---|
| [`defensive-blue-research`](Skills/research/defensive-blue-research/SKILL.md) | Research-first methodology: source hierarchy, currency checks, Admiralty grading, lab validation, option analysis, cited recommendations |
| [`defensive-cve-researcher`](Skills/research/defensive-cve-researcher/SKILL.md) | Finding and responsibly disclosing OSS vulnerabilities for a CVE: legal limits, patch-diff/variant analysis, lab proof with benign markers, CVSS/CWE, CNA selection, reports, embargo |

### Defense Model

`Skills/defense-model/`

| Skill | What it covers |
|---|---|
| [`defensive-active-defense`](Skills/defense-model/defensive-active-defense/SKILL.md) | Sliding Scale, MITRE Engage, honeytokens/sinkholes/tarpits, rules of engagement, legal limits on hack-back |
| [`defensive-cyber-resilience`](Skills/defense-model/defensive-cyber-resilience/SKILL.md) | NIST 800-160v2 goals & 14 techniques, minimum viable company, impact tolerances (DORA/UK), recovery engineering |
| [`defensive-d3fend-countermeasures`](Skills/defense-model/defensive-d3fend-countermeasures/SKILL.md) | D3FEND tactics (Model→Restore), ATT&CK→artifact→countermeasure mappings, vendor comparison, gap analysis |
| [`defensive-defense-in-depth`](Skills/defense-model/defensive-defense-in-depth/SKILL.md) | Layered controls (prevent/detect/respond/recover), Swiss cheese model, coverage matrices, reference stacks |
| [`defensive-kill-chain-defense`](Skills/defense-model/defensive-kill-chain-defense/SKILL.md) | Cyber Kill Chain + CoA matrix, Unified Kill Chain, Diamond Model pivoting, Pyramid of Pain, ICS kill chain |
| [`defensive-security-architecture`](Skills/defense-model/defensive-security-architecture/SKILL.md) | SABSA/TOGAF, enterprise access model planes, reference patterns, review checklist, ADR template |
| [`defensive-security-fundamentals`](Skills/defense-model/defensive-security-fundamentals/SKILL.md) | CIA/Parkerian, AAA, risk vocabulary, control categories & types, Saltzer–Schroeder principles, crypto essentials |
| [`defensive-security-operating-model`](Skills/defense-model/defensive-security-operating-model/SKILL.md) | Security function map, MSSP/MDR/co-managed sourcing, SOC-CMM, RACI, Three Lines, staffing math |
| [`defensive-threat-informed-defense`](Skills/defense-model/defensive-threat-informed-defense/SKILL.md) | Threat profiles, technique prioritization, CTID Mappings Explorer & Sensor Mappings, coverage scoring 0–4, validation |
| [`defensive-zero-trust-architecture`](Skills/defense-model/defensive-zero-trust-architecture/SKILL.md) | NIST 800-207 tenets & PE/PA/PEP, CISA ZTMM v2.0 pillars, ZTNA vs VPN, Conditional Access, roadmap |

### SOC Operations

`Skills/soc/`

| Skill | What it covers |
|---|---|
| [`defensive-alert-triage`](Skills/soc/defensive-alert-triage/SKILL.md) | Entity extraction, enrichment order, TP/BTP/FP verdicts, severity, escalation, closing notes |
| [`defensive-log-parsing`](Skills/soc/defensive-log-parsing/SKILL.md) | Syslog/CEF/LEEF/JSON parsing, ECS/OCSF/ASIM/UDM/CIM normalization, grok/VRL/DCR pipelines, parser testing |
| [`defensive-log-sources`](Skills/soc/defensive-log-sources/SKILL.md) | Audit policy, Sysmon, cloud logs, schemas (ECS/CIM/ASIM/OCSF/UDM), retention, silent-source alerts |
| [`defensive-security-metrics`](Skills/soc/defensive-security-metrics/SKILL.md) | MTTD/MTTA/MTTC, TP rate, validated coverage, vuln SLA & KEV window, board KRIs, KQL/SPL metric queries |
| [`defensive-soar-automation`](Skills/soc/defensive-soar-automation/SKILL.md) | What to automate, guardrails, Shuffle/TheHive/Sentinel/Wazuh AR, securing automation |
| [`defensive-soc-building`](Skills/soc/defensive-soc-building/SKILL.md) | SOC charter, log onboarding priority, use-case lifecycle (MaGMa), tiers & shifts, SLAs, 90-day/12-month plan |
| [`defensive-soc-playbooks`](Skills/soc/defensive-soc-playbooks/SKILL.md) | Playbook template, containment authority, NIST 800-61r3, notification timelines, metrics |
| [`defensive-ueba`](Skills/soc/defensive-ueba/SKILL.md) | Baselines, peer groups, MAD/percentile/first-seen analytics, Splunk RBA, Sentinel BehaviorAnalytics, Elastic ML |

### Detection Engineering

`Skills/detection/`

| Skill | What it covers |
|---|---|
| [`defensive-detection-as-code`](Skills/detection/defensive-detection-as-code/SKILL.md) | Repo layout, CI, tests, staged rollout, ATT&CK v18 coverage, metrics |
| [`defensive-query-languages`](Skills/detection/defensive-query-languages/SKILL.md) | SPL, KQL, EQL, ES\|QL, Lucene, Wazuh XML, Graylog, Athena — operator map and patterns |
| [`defensive-sigma`](Skills/detection/defensive-sigma/SKILL.md) | Rule anatomy, modifiers, correlation rules, filters, pySigma backends/pipelines, Hayabusa/Chainsaw |
| [`defensive-suricata-snort`](Skills/detection/defensive-suricata-snort/SKILL.md) | Suricata 8 buffers, flowbits/datasets, thresholds, EVE analysis, Snort 3 |
| [`defensive-yara`](Skills/detection/defensive-yara/SKILL.md) | YARA/YARA-X rules, performance, migration, testing, memory scanning, YARA-L |

### ATT&CK Detection Packs

`Skills/detection-packs/`

| Skill | What it covers |
|---|---|
| [`defensive-detect-collection`](Skills/detection-packs/defensive-detect-collection/SKILL.md) | TA0009: archiving & staging, share/SharePoint spikes, mailbox export/forwarding, S3/Blob reads, repo clones |
| [`defensive-detect-command-and-control`](Skills/detection-packs/defensive-detect-command-and-control/SKILL.md) | TA0011: beacon CV analytics, RITA, DNS tunneling/DGA/DoH, JA4/x509, tunnels & RMM, ingress transfer |
| [`defensive-detect-credential-access`](Skills/detection-packs/defensive-detect-credential-access/SKILL.md) | TA0006: LSASS/hive/NTDS/DCSync, Kerberoast/AS-REP/spray, MFA fatigue, token replay, cloud metadata theft |
| [`defensive-detect-defense-evasion`](Skills/detection-packs/defensive-detect-defense-evasion/SKILL.md) | TA0005: Defender/EDR/log tampering, silence detection, masquerading, LOLBin proxy execution, obfuscation |
| [`defensive-detect-discovery`](Skills/detection-packs/defensive-detect-discovery/SKILL.md) | TA0007: recon command bursts, AdFind/SharpHound/LDAP volume, internal scans, cloud enumeration, honeytokens |
| [`defensive-detect-execution`](Skills/detection-packs/defensive-detect-execution/SKILL.md) | TA0002: PowerShell content & lineage, 4104, WMI, service/PsExec patterns, user-writable execution, K8s exec |
| [`defensive-detect-exfiltration`](Skills/detection-packs/defensive-detect-exfiltration/SKILL.md) | TA0010: rclone/MEGA/WinSCP, bytes-out ratios, alt protocols, snapshot/bucket/SAS sharing, response steps |
| [`defensive-detect-impact`](Skills/detection-packs/defensive-detect-impact/SKILL.md) | TA0040: shadow-copy/backup deletion, service-kill sprees, mass encryption, wipers, ESXi kill, cloud destruction, auto-isolation |
| [`defensive-detect-initial-access`](Skills/detection-packs/defensive-detect-initial-access/SKILL.md) | TA0001: phishing, exploited edge/web apps, VPN/valid-account anomalies, help-desk MFA reset abuse, USB/HID |
| [`defensive-detect-lateral-movement`](Skills/detection-packs/defensive-detect-lateral-movement/SKILL.md) | TA0008: PsExec/WMI/WinRM/RDP/DCOM, PtH/PtT heuristics, workstation↔workstation, SSM/RunCommand, Zeek DCE-RPC |
| [`defensive-detect-persistence`](Skills/detection-packs/defensive-detect-persistence/SKILL.md) | TA0003: Windows ASEPs, WMI/COM/IFEO, Linux cron/systemd/preload/PAM, macOS BTM, identity & cloud persistence |
| [`defensive-detect-privilege-escalation`](Skills/detection-packs/defensive-detect-privilege-escalation/SKILL.md) | TA0004: UAC bypass, Potato/token abuse, service/DLL hijack, sudo/SUID, AD ACL/RBCD/ADCS, cloud IAM self-grants |

### SIEM & XDR Platforms

`Skills/siem/`

| Skill | What it covers |
|---|---|
| [`defensive-crowdstrike-falcon`](Skills/siem/defensive-crowdstrike-falcon/SKILL.md) | Prevention & content-update rings, CQL hunting, custom IOAs, RTR live response, containment, exclusions, FalconPy |
| [`defensive-defender-xdr`](Skills/siem/defensive-defender-xdr/SKILL.md) | ASR/tamper/EDR block mode, Advanced Hunting schema & queries, custom detections, response actions, AIR, MDI |
| [`defensive-elastic`](Skills/siem/defensive-elastic/SKILL.md) | Fleet integrations, ECS, rule types (EQL/ES\|QL/new terms), exceptions, Timeline, Osquery |
| [`defensive-google-secops`](Skills/siem/defensive-google-secops/SKILL.md) | UDM search, YARA-L 2.0 single & multi-event rules, reference lists, curated detections, retrohunts, SOAR |
| [`defensive-graylog`](Skills/siem/defensive-graylog/SKILL.md) | Inputs/streams/index sets, pipeline rules & lookup tables, search syntax, event definitions, Graylog Security |
| [`defensive-qradar`](Skills/siem/defensive-qradar/SKILL.md) | DSMs & QIDs, AQL for events/flows, CRE rules & building blocks, reference sets, offense tuning, SaaS transition note |
| [`defensive-security-onion`](Skills/siem/defensive-security-onion/SKILL.md) | NSM deployment, sensor placement, Hunt/Cases/PCAP, Graylog, lab design |
| [`defensive-sentinel`](Skills/siem/defensive-sentinel/SKILL.md) | Connectors/DCRs, analytics rules, ASIM, UEBA, data lake, Defender portal transition |
| [`defensive-sentinelone`](Skills/siem/defensive-sentinelone/SKILL.md) | Protect-mode policy, Storyline, PowerQuery hunting, STAR rules, kill/quarantine/remediate/rollback, Ranger, API |
| [`defensive-splunk`](Skills/siem/defensive-splunk/SKILL.md) | TAs, CIM, tstats, ES 8, risk-based alerting, ESCU |
| [`defensive-wazuh`](Skills/siem/defensive-wazuh/SKILL.md) | Agents/groups, rules & decoders, wazuh-logtest, FIM, SCA, active response, integrations |

### Threat Hunting

`Skills/hunting/`

| Skill | What it covers |
|---|---|
| [`defensive-hunt-linux`](Skills/hunting/defensive-hunt-linux/SKILL.md) | SSH brute→success, temp-dir exec, curl|sh, reverse shells, persistence stacking, privesc, miners, webshells, escapes |
| [`defensive-hunt-macos`](Skills/hunting/defensive-hunt-macos/SKILL.md) | ESF/eslogger/unified log/osquery hunts for infostealers, unsigned binaries, quarantine removal, launchd/BTM, TCC abuse |
| [`defensive-hunt-network`](Skills/hunting/defensive-hunt-network/SKILL.md) | Beaconing (CV), long connections, DNS tunneling/DGA, TLS/JA4, exfil, east-west |
| [`defensive-hunt-windows`](Skills/hunting/defensive-hunt-windows/SKILL.md) | Lineage, LOLBins, PowerShell, persistence, credential access, injection, BYOVD, evasion |
| [`defensive-threat-hunting`](Skills/hunting/defensive-threat-hunting/SKILL.md) | PEAK, TaHiTI, hypotheses, data readiness, analysis techniques, hunt reports |

### Incident Response

`Skills/ir/`

| Skill | What it covers |
|---|---|
| [`defensive-bec-response`](Skills/ir/defensive-bec-response/SKILL.md) | AiTM token theft, inbox rules, OAuth grants, revocation order, payment recall |
| [`defensive-cloud-ir`](Skills/ir/defensive-cloud-ir/SKILL.md) | AWS/Azure/GCP credential revocation, scoping, persistence, snapshots, GuardDuty attack sequences |
| [`defensive-incident-response`](Skills/ir/defensive-incident-response/SKILL.md) | Roles, scoping, evidence, containment strategy & library, eradication, RCA, sitreps |
| [`defensive-ir-readiness`](Skills/ir/defensive-ir-readiness/SKILL.md) | IR plan (800-61r3), authority, OOB comms, technical readiness checklist, jump bag, retainers/insurance/CERT contacts |
| [`defensive-live-response`](Skills/ir/defensive-live-response/SKILL.md) | Velociraptor, EDR live response, memory acquisition, volatile data, KAPE, UAC |
| [`defensive-ransomware-response`](Skills/ir/defensive-ransomware-response/SKILL.md) | Precursors, imminent-encryption signals, first-hour containment, identity-first recovery |
| [`defensive-web-compromise-response`](Skills/ir/defensive-web-compromise-response/SKILL.md) | Webshells, skimmers, SEO spam: evidence, log analysis, wp-cli checksums, backdoor hunting, rebuild, PCI 6.4.3/11.6.1 |

### Digital Forensics

`Skills/forensics/`

| Skill | What it covers |
|---|---|
| [`defensive-browser-forensics`](Skills/forensics/defensive-browser-forensics/SKILL.md) | Chromium/Firefox/Safari artifacts, SQL for visits/downloads, timestamp formats, extensions, cookie theft, ClickFix evidence |
| [`defensive-container-forensics`](Skills/forensics/defensive-container-forensics/SKILL.md) | Quarantine pods without deleting, docker/crictl evidence, checkpoints, overlay layers, K8s audit, escape and credential analysis |
| [`defensive-disk-imaging`](Skills/forensics/defensive-disk-imaging/SKILL.md) | Live vs dead acquisition, encryption keys, E01/dd with hashing, ddrescue, SSD caveats, VM and cloud snapshots, chain of custody |
| [`defensive-email-forensics`](Skills/forensics/defensive-email-forensics/SKILL.md) | Header analysis, sender classification, MIME extraction, message trace, EmailEvents/UrlClickEvents, UAL, BEC timeline |
| [`defensive-linux-forensics`](Skills/forensics/defensive-linux-forensics/SKILL.md) | Auth timeline, persistence sweep, package integrity, web shells, Volatility linux plugins |
| [`defensive-macos-forensics`](Skills/forensics/defensive-macos-forensics/SKILL.md) | Unified Log, eslogger/ESF, BTM, TCC, quarantine, infostealer patterns |
| [`defensive-memory-forensics`](Skills/forensics/defensive-memory-forensics/SKILL.md) | Volatility 3 process/injection/network analysis, MemProcFS |
| [`defensive-timeline-analysis`](Skills/forensics/defensive-timeline-analysis/SKILL.md) | Plaso, Timesketch, anchor-and-pivot, MACB, narrative output |
| [`defensive-windows-forensics`](Skills/forensics/defensive-windows-forensics/SKILL.md) | Artifact semantics table, EZ Tools commands, timestomping, execution validation |

### Malware Analysis

`Skills/malware/`

| Skill | What it covers |
|---|---|
| [`defensive-dynamic-analysis`](Skills/malware/defensive-dynamic-analysis/SKILL.md) | Lab design, monitoring stack, anti-analysis, sandboxes, behavior → detection |
| [`defensive-linux-malware`](Skills/malware/defensive-linux-malware/SKILL.md) | Miners, botnets, rootkits (preload/LKM/eBPF), webshells; triage commands, AVML, ELF analysis, detections, rebuild |
| [`defensive-maldoc-analysis`](Skills/malware/defensive-maldoc-analysis/SKILL.md) | Office/RTF/PDF/LNK/ISO/OneNote/HTML smuggling/SVG lure analysis |
| [`defensive-malware-triage`](Skills/malware/defensive-malware-triage/SKILL.md) | PE structure, FLOSS, capa, packers, script deobfuscation, deliverables |
| [`defensive-reverse-engineering`](Skills/malware/defensive-reverse-engineering/SKILL.md) | Lab safety, PE/ELF/Mach-O, unpacking, Ghidra/IDA/x64dbg workflows, .NET/Go/Rust notes, config extraction, YARA on code |
| [`defensive-script-deobfuscation`](Skills/malware/defensive-script-deobfuscation/SKILL.md) | PowerShell/JS/VBA/batch/Python deobfuscation, sink neutralization in VMs, 4104 capture, box-js/olevba, IOC extraction |

### Threat Intelligence

`Skills/cti/`

| Skill | What it covers |
|---|---|
| [`defensive-attack-mapping`](Skills/cti/defensive-attack-mapping/SKILL.md) | ATT&CK v18 structure, coverage scoring, Navigator layers, D3FEND 1.0 |
| [`defensive-cti`](Skills/cti/defensive-cti/SKILL.md) | PIRs, Diamond Model, TTP extraction, Admiralty code, estimative language, TLP 2.0 |
| [`defensive-ioc-management`](Skills/cti/defensive-ioc-management/SKILL.md) | IOC quality gates, MISP, OpenCTI, STIX/TAXII, distribution, retro-hunting |

### Endpoint

`Skills/endpoint/`

| Skill | What it covers |
|---|---|
| [`defensive-application-control`](Skills/endpoint/defensive-application-control/SKILL.md) | App Control for Business (WDAC) base/supplemental policies, managed installer, block rules, CiTool/Intune, CodeIntegrity events, fapolicyd, Santa |
| [`defensive-browser-security`](Skills/endpoint/defensive-browser-security/SKILL.md) | Extension governance post-MV2, Safe Browsing/ESM, App-Bound Encryption + DBSC vs cookie theft, ClickFix mitigations and RunMRU hunting |
| [`defensive-edr-tuning`](Skills/endpoint/defensive-edr-tuning/SKILL.md) | Coverage, exclusion governance, tamper protection, EDR-blinding detection |
| [`defensive-linux-telemetry`](Skills/endpoint/defensive-linux-telemetry/SKILL.md) | auditd rules, Falco/Tetragon, osquery, Linux detection catalog |
| [`defensive-sysmon`](Skills/endpoint/defensive-sysmon/SKILL.md) | EID 1–29, config design, native Windows 11 Sysmon, Sysmon for Linux, volume control |
| [`defensive-usb-device-control`](Skills/endpoint/defensive-usb-device-control/SKILL.md) | Defender Device Control, GPO/Intune, BitLocker To Go, USBGuard, HID injection detection, OT media kiosks |
| [`defensive-windows-event-logs`](Skills/endpoint/defensive-windows-event-logs/SKILL.md) | Event ID reference, logon types, Kerberos/NTLM attacks, RPC pipes, ETW/AMSI |
| [`defensive-windows-hardening`](Skills/endpoint/defensive-windows-hardening/SKILL.md) | ASR rules, LSA PPL, Credential Guard, LAPS, WDAC, protocol hardening |

### Active Directory

`Skills/active-directory/`

| Skill | What it covers |
|---|---|
| [`defensive-ad-detection`](Skills/active-directory/defensive-ad-detection/SKILL.md) | Kerberoast/AS-REP/DCSync/tickets/relay/shadow creds/AD CS detections, honey accounts |
| [`defensive-ad-forest-recovery`](Skills/active-directory/defensive-ad-forest-recovery/SKILL.md) | Cleanup vs recovery, isolated restore of one DC per domain, FSMO/RID/krbtgt/trust resets, persistence purge |
| [`defensive-ad-hardening`](Skills/active-directory/defensive-ad-hardening/SKILL.md) | Tier 0, tiering, attack-path reduction, Kerberos/NTLM changes, AD CS ESC1–ESC16 fixes |

### Identity

`Skills/identity/`

| Skill | What it covers |
|---|---|
| [`defensive-auth-implementation`](Skills/identity/defensive-auth-implementation/SKILL.md) | OAuth 2.x/OIDC, JWT validation, SAML, sessions, passwords/MFA, negative tests |
| [`defensive-entra-id`](Skills/identity/defensive-entra-id/SKILL.md) | Conditional Access, PIM, Token Protection, CAE, consent governance, detections |
| [`defensive-google-workspace-security`](Skills/identity/defensive-google-workspace-security/SKILL.md) | 2SV/admin enforcement, OAuth allowlisting, Context-Aware Access, Gmail/Drive/DLP, 6-month logs→BigQuery, ScubaGoggles |
| [`defensive-m365-security`](Skills/identity/defensive-m365-security/SKILL.md) | ScubaGear/Maester baselines, EXO presets, SMTP AUTH default-off end-2026, sharing/consent, audit retention, BEC detections |
| [`defensive-okta-security`](Skills/identity/defensive-okta-security/SKILL.md) | Admin hardening, FastPass binding caveats, help-desk resets, token governance, verified System Log eventTypes, agent patching |
| [`defensive-pam`](Skills/identity/defensive-pam/SKILL.md) | Entra PIM JIT, vaulting/session recording, Windows LAPS (native, encrypted), gMSA/dMSA + BadSuccessor, break-glass guidance |
| [`defensive-phishing-resistant-mfa`](Skills/identity/defensive-phishing-resistant-mfa/SKILL.md) | What qualifies, NIST 800-63-4 AAL2/AAL3, Entra auth strengths & passkey attestation, mandatory Azure MFA, secure recovery |

### Application Security

`Skills/appsec/`

| Skill | What it covers |
|---|---|
| [`defensive-api-security`](Skills/appsec/defensive-api-security/SKILL.md) | OWASP API Top 10, BOLA-safe patterns, schema validation, GraphQL, abuse detection |
| [`defensive-database-security`](Skills/appsec/defensive-database-security/SKILL.md) | Exposure/auth hardening per engine, least privilege, encryption, pgaudit/SQL Audit, detecting xp_cmdshell, dumps, SQLi |
| [`defensive-mobile-app-security`](Skills/appsec/defensive-mobile-app-security/SKILL.md) | OWASP MASVS/MASTG controls, server-side attestation (Play Integrity/App Attest), MobSF/jadx/Frida testing, SDK vetting |
| [`defensive-sast-dast`](Skills/appsec/defensive-sast-dast/SKILL.md) | Semgrep/CodeQL/OSV/Trivy/gitleaks/ZAP pipeline, triage, SLAs |
| [`defensive-secure-code-review`](Skills/appsec/defensive-secure-code-review/SKILL.md) | OWASP Top 10:2025, sink-level fixes per language, write-up format |
| [`defensive-waf`](Skills/appsec/defensive-waf/SKILL.md) | OWASP CRS tuning, virtual patching, cloud WAFs, bypass classes |

### Network Security

`Skills/network/`

| Skill | What it covers |
|---|---|
| [`defensive-ddos`](Skills/network/defensive-ddos/SKILL.md) | Attack classes, CDN/scrubbing/cloud protection, RTBH & Flowspec, L7 rate limits, origin lockdown, DDoS runbook |
| [`defensive-dns-security`](Skills/network/defensive-dns-security/SKILL.md) | Resolver logging, RPZ/protective DNS & sinkholes, DoH policy, DNSSEC/CAA/TSIG, dangling DNS, DNS detections |
| [`defensive-firewall-analysis`](Skills/network/defensive-firewall-analysis/SKILL.md) | PAN-OS/FortiGate/ASA/pfSense logs, NetFlow, detections, rule-base review |
| [`defensive-ids-ips-deployment`](Skills/network/defensive-ids-ips-deployment/SKILL.md) | Sensor placement, TAP/SPAN/inline + bypass, Suricata/Snort config, ruleset management, tuning, drop metrics |
| [`defensive-ipv6-security`](Skills/network/defensive-ipv6-security/SKILL.md) | RA Guard, DHCPv6 Guard, mitm6 defense, Cisco/Huawei first-hop security, ICMPv6 filtering, tunnel blocking |
| [`defensive-l2-security`](Skills/network/defensive-l2-security/SKILL.md) | DHCP snooping, DAI, IPSG, port security, STP guards, 802.1X (Cisco & Huawei) |
| [`defensive-nac`](Skills/network/defensive-nac/SKILL.md) | 802.1X EAP-TLS/TEAP, MAB & profiling, Cisco/Huawei configs, Blast-RADIUS mitigations, phased enforcement |
| [`defensive-netflow-ndr`](Skills/network/defensive-netflow-ndr/SKILL.md) | NetFlow/IPFIX/sFlow & cloud flow logs, Cisco FNF & Huawei NetStream export, nfdump/SiLK analytics, NDR evaluation |
| [`defensive-network-forensics`](Skills/network/defensive-network-forensics/SKILL.md) | PCAP capture architecture, evidence hashing, Zeek/Suricata retro-indexing, object extraction, TLS key logs, exfil sizing |
| [`defensive-network-security-architecture`](Skills/network/defensive-network-security-architecture/SKILL.md) | Zones & trust levels, north-south vs east-west, reference designs, egress & visibility architecture, review checklist |
| [`defensive-network-segmentation`](Skills/network/defensive-network-segmentation/SKILL.md) | Zones, ACL design (Cisco & Huawei), east-west restriction, zero trust, validation |
| [`defensive-ngfw-policy`](Skills/network/defensive-ngfw-policy/SKILL.md) | Rule-base hygiene, App-ID/User-ID, profiles on every allow, PAN-OS/FortiOS/ASA/pfSense/cloud FW commands, mgmt plane |
| [`defensive-pcap-analysis`](Skills/network/defensive-pcap-analysis/SKILL.md) | Capture, tshark triage, display filters, extraction, pattern recognition |
| [`defensive-proxy-tls-inspection`](Skills/network/defensive-proxy-tls-inspection/SKILL.md) | Explicit/transparent proxy, WPAD risk, SWG policy, TLS interception design & bypass, TLS 1.3/ECH/QUIC, proxy hunts |
| [`defensive-remote-access-ztna`](Skills/network/defensive-remote-access-ztna/SKILL.md) | ZTNA/IAP, bastions & SSM, vendor PAM, RMM governance, exposed RDP/SSH hardening, Scattered Spider defenses |
| [`defensive-routing-security`](Skills/network/defensive-routing-security/SKILL.md) | RPKI ROV, IRR filters, GTSM/TCP-AO, MANRS, uRPF/BCP 38, OSPF HMAC-SHA, CoPP, hijack response (Cisco/Huawei) |
| [`defensive-sdwan-sase`](Skills/network/defensive-sdwan-sase/SKILL.md) | SASE/SSE components, SD-WAN fabric & controller hardening, CASB/tenant restrictions, agent tamper, evaluation |
| [`defensive-tls-pki`](Skills/network/defensive-tls-pki/SKILL.md) | SC-081 lifetime cuts, ACME automation, TLS configs (nginx/Apache/IIS), OCSP/CRL changes, CT monitoring, internal PKI |
| [`defensive-vpn-ipsec`](Skills/network/defensive-vpn-ipsec/SKILL.md) | IKEv2 crypto baseline, Cisco IOS-XE & Huawei VRP IPsec, WireGuard, SSL-VPN risk & migration, VPN abuse monitoring |
| [`defensive-zeek`](Skills/network/defensive-zeek/SKILL.md) | Log reference, conn_state, analysis snippets, Intel framework, scripting |

### Wireless

`Skills/wireless/`

| Skill | What it covers |
|---|---|
| [`defensive-wireless-design`](Skills/wireless/defensive-wireless-design/SKILL.md) | WPA3, EAP-TLS, PMF, server cert validation, guest/IoT segmentation |
| [`defensive-wireless-ids`](Skills/wireless/defensive-wireless-ids/SKILL.md) | Rogue/evil twin/deauth detection, Kismet, wired correlation, response |

### Cloud

`Skills/cloud/`

| Skill | What it covers |
|---|---|
| [`defensive-aws-security`](Skills/cloud/defensive-aws-security/SKILL.md) | SCP guardrails, identity, logging, GuardDuty, CloudTrail detections |
| [`defensive-azure-security`](Skills/cloud/defensive-azure-security/SKILL.md) | Azure Policy, RBAC/PIM, Defender for Cloud, Sentinel detections |
| [`defensive-cloud-data-security`](Skills/cloud/defensive-cloud-data-security/SKILL.md) | Macie/Purview/SDP, public-access prevention, CMK/key policies, SSE-C abuse, data perimeters (SCP/RCP/VPC-SC), snapshot controls |
| [`defensive-cspm`](Skills/cloud/defensive-cspm/SKILL.md) | Prowler/Steampipe/native CSPM, toxic combinations, IaC scanning, drift |
| [`defensive-gcp-security`](Skills/cloud/defensive-gcp-security/SKILL.md) | Org policies, service account security, audit logs, SCC, detections |
| [`defensive-saas-security`](Skills/cloud/defensive-saas-security/SKILL.md) | SaaS posture, OAuth/connected-app governance, Salesloft Drift, UNC6040 vishing, Snowflake UNC5537 and MFA phases, SaaS IR |
| [`defensive-serverless-security`](Skills/cloud/defensive-serverless-security/SKILL.md) | Least-privilege function roles, secrets, event input validation, function URL auth, persistence and credential-theft detection |

### Container & Kubernetes

`Skills/container/`

| Skill | What it covers |
|---|---|
| [`defensive-container-hardening`](Skills/container/defensive-container-hardening/SKILL.md) | Dockerfile, runtime flags, capabilities, scanning, cosign signing, daemon hardening |
| [`defensive-k8s-security`](Skills/container/defensive-k8s-security/SKILL.md) | RBAC, Pod Security Admission, Kyverno, NetworkPolicy, audit policy & detections |

### Supply Chain & CI/CD

`Skills/supply-chain/`

| Skill | What it covers |
|---|---|
| [`defensive-cicd-hardening`](Skills/supply-chain/defensive-cicd-hardening/SKILL.md) | GitHub Actions hardening, pwn requests, cache poisoning, OIDC, trusted publishing |
| [`defensive-sbom-slsa`](Skills/supply-chain/defensive-sbom-slsa/SKILL.md) | CycloneDX/SPDX, VEX, SLSA, Sigstore, dependency defenses, compromised-upstream playbook |
| [`defensive-secrets-management`](Skills/supply-chain/defensive-secrets-management/SKILL.md) | Vaults, dynamic creds, scanning, leak response runbook per secret type |

### Vulnerability Management

`Skills/vuln-mgmt/`

| Skill | What it covers |
|---|---|
| [`defensive-asset-inventory`](Skills/vuln-mgmt/defensive-asset-inventory/SKILL.md) | CIS 1–2 inventory from directory/MDM/EDR/cloud/DHCP/NAC/scans, gap queries, attributes, software inventory, KPIs |
| [`defensive-patch-management`](Skills/vuln-mgmt/defensive-patch-management/SKILL.md) | Rings, emergency lane, edge appliances, verification, rollback, EOL |
| [`defensive-psirt-disclosure-handling`](Skills/vuln-mgmt/defensive-psirt-disclosure-handling/SKILL.md) | Vendor/maintainer side of CVD: policy & safe harbor, security.txt, GitHub PVR, triage SLAs & AI-report floods, EU CRA 24h/72h reporting, CNA records, CSAF/VEX advisories |
| [`defensive-security-testing-program`](Skills/vuln-mgmt/defensive-security-testing-program/SKILL.md) | Test types (pentest, red/purple, TLPT, VDP), RoE and authorization, vendor selection, findings→fixes→detections |
| [`defensive-vuln-management`](Skills/vuln-mgmt/defensive-vuln-management/SKILL.md) | CVSS v4, EPSS v4, KEV, SSVC, BOD 26-04 matrix, post-NVD data sources, EU CRA |

### Hardening

`Skills/hardening/`

| Skill | What it covers |
|---|---|
| [`defensive-linux-hardening`](Skills/hardening/defensive-linux-hardening/SKILL.md) | OpenSCAP/Lynis, SSH, sudo/PAM, sysctl, SELinux/AppArmor, nftables |
| [`defensive-network-device-hardening`](Skills/hardening/defensive-network-device-hardening/SKILL.md) | Cisco IOS & Huawei VRP: AAA, SSH, SNMPv3, NTP auth, CoPP, routing auth |
| [`defensive-web-server-hardening`](Skills/hardening/defensive-web-server-hardening/SKILL.md) | nginx/Apache/IIS/PHP/Tomcat hardening, dotfile/backup exposure, limits, security log format, verification |

### Email Security

`Skills/email/`

| Skill | What it covers |
|---|---|
| [`defensive-email-auth`](Skills/email/defensive-email-auth/SKILL.md) | SPF, DKIM, DMARCbis (RFC 9989), MTA-STS, TLS-RPT, BIMI, rollout |
| [`defensive-phishing-triage`](Skills/email/defensive-phishing-triage/SKILL.md) | Header/URL analysis, AiTM & quishing, scope, purge, verdict notes |

### Deception

`Skills/deception/`

| Skill | What it covers |
|---|---|
| [`defensive-deception`](Skills/deception/defensive-deception/SKILL.md) | Canarytokens, honey SPN/AS-REP accounts, OpenCanary, placement, MITRE ENGAGE |

### OT/ICS

`Skills/ot/`

| Skill | What it covers |
|---|---|
| [`defensive-ics-security`](Skills/ot/defensive-ics-security/SKILL.md) | Purdue/IEC 62443, ICS protocols, Malcolm/ICSNPP, safe vuln mgmt, OT IR |

### AI Security

`Skills/ai/`

| Skill | What it covers |
|---|---|
| [`defensive-ai-security`](Skills/ai/defensive-ai-security/SKILL.md) | OWASP LLM Top 10 2025, Agentic Top 10 2026, prompt injection, MCP, RAG, monitoring |

### Human & Physical

`Skills/human/`

| Skill | What it covers |
|---|---|
| [`defensive-physical-security`](Skills/human/defensive-physical-security/SKILL.md) | Layered physical controls, modern badges, rogue devices/jacks, media sanitization (800-88), badge logs in SIEM |
| [`defensive-security-awareness`](Skills/human/defensive-security-awareness/SKILL.md) | Behavior targets (QR, MFA fatigue, vishing, deepfakes, ClickFix), role-based training, ethical simulations, report-rate metrics |

### Purple Team

`Skills/purple/`

| Skill | What it covers |
|---|---|
| [`defensive-adversary-emulation`](Skills/purple/defensive-adversary-emulation/SKILL.md) | CTI → procedures, plan structure, RoE, CTID library, metrics |
| [`defensive-purple-team`](Skills/purple/defensive-purple-team/SKILL.md) | Atomic Red Team, Caldera, outcome scoring, gap fixing, red↔blue pairing |

### GRC

`Skills/grc/`

| Skill | What it covers |
|---|---|
| [`defensive-bcp-dr`](Skills/grc/defensive-bcp-dr/SKILL.md) | BIA (MTD/RTO/RPO), tiered DR strategies, cyber-aware recovery order, plans, testing types |
| [`defensive-frameworks`](Skills/grc/defensive-frameworks/SKILL.md) | NIST CSF 2.0, CIS v8.1, ISO 27001:2022, PCI DSS 4.0.1, NIS2, DORA, PH DPA crosswalk |
| [`defensive-policy-standards`](Skills/grc/defensive-policy-standards/SKILL.md) | Policy/standard/procedure hierarchy, core policy set incl. AI use, testable requirements, ISO 27001:2022 mapping, exceptions |
| [`defensive-privacy-data-protection`](Skills/grc/defensive-privacy-data-protection/SKILL.md) | Records of processing, minimization, DPIAs, pseudonymization, privacy in security monitoring, GDPR/PH DPA overview |
| [`defensive-risk-threat-modeling`](Skills/grc/defensive-risk-threat-modeling/SKILL.md) | STRIDE, attack trees, risk scoring, FAIR basics, risk register |

### Utility

`Skills/utility/`

| Skill | What it covers |
|---|---|
| [`defensive-ir-reporting`](Skills/utility/defensive-ir-reporting/SKILL.md) | Report structure, executive summaries, language standards, blameless reviews |
| [`defensive-quick-checks`](Skills/utility/defensive-quick-checks/SKILL.md) | 30-minute compromise checks for Windows/Linux/macOS/cloud with red-flag tables |

### Tools

`Skills/tools/`

| Skill | What it covers |
|---|---|
| [`defensive-tool-ad-assessment`](Skills/tools/defensive-tool-ad-assessment/SKILL.md) | BloodHound CE 9.x secure deployment & Privilege Zones, SharpHound/AzureHound, PingCastle, Purple Knight, Locksmith |
| [`defensive-tool-cloud-posture`](Skills/tools/defensive-tool-cloud-posture/SKILL.md) | Prowler 5 multi-cloud/M365, Steampipe + Powerpipe, kube-bench, native CSPM, read-only creds, findings→guardrails |
| [`defensive-tool-container-scanners`](Skills/tools/defensive-tool-container-scanners/SKILL.md) | Trivy compromise response, SHA pinning, Trivy/Syft/Grype usage, DB mirroring, gating policy, VEX |
| [`defensive-tool-cyberchef`](Skills/tools/defensive-tool-cyberchef/SKILL.md) | Offline use, shared-link data leakage, decoding recipes (PowerShell, gzip, XOR, charcodes), IOC extraction, Node API |
| [`defensive-tool-dast-scanners`](Skills/tools/defensive-tool-dast-scanners/SKILL.md) | ZAP baseline/API/full & Automation Framework, Nuclei rate limits/tags, signed code templates, authorization rules |
| [`defensive-tool-emulation`](Skills/tools/defensive-tool-emulation/SKILL.md) | Invoke-AtomicRedTeam safe workflow (prereqs, cleanup, Attire logs), Caldera local.yml hardening, results matrix |
| [`defensive-tool-falco`](Skills/tools/defensive-tool-falco/SKILL.md) | 0.44 removals, modern eBPF Helm deploy, rules/macros/exceptions, falcoctl, plugins, Falcosidekick/Talon, self-protection |
| [`defensive-tool-hayabusa-chainsaw`](Skills/tools/defensive-tool-hayabusa-chainsaw/SKILL.md) | Hayabusa 4.x dfir-timeline, logon-summary, live-response packages; Chainsaw hunt/search/SRUM/Shimcache |
| [`defensive-tool-honeypots`](Skills/tools/defensive-tool-honeypots/SKILL.md) | OpenCanary, Canarytokens, T-Pot (ports, data-sharing opt-out), Cowrie, Conpot; isolation, egress, legal & privacy |
| [`defensive-tool-kape-eztools`](Skills/tools/defensive-tool-kape-eztools/SKILL.md) | KAPE targets/modules/VSS/containers, EZ Tools reference (MFTECmd, EvtxECmd, PECmd, RECmd…), evidence handling |
| [`defensive-tool-misp-opencti`](Skills/tools/defensive-tool-misp-opencti/SKILL.md) | MISP hardening & sharing model, warninglists/decay/sightings, PyMISP, OpenCTI markings & connector tokens |
| [`defensive-tool-nmap`](Skills/tools/defensive-tool-nmap/SKILL.md) | Discovery & port scans, NSE category safety, rate limits, ndiff drift, OT cautions, detecting rogue scans |
| [`defensive-tool-osquery`](Skills/tools/defensive-tool-osquery/SKILL.md) | Config & packs, watchdog, evented tables, FIM, fleet manager risks, carver off, security query library |
| [`defensive-tool-plaso`](Skills/tools/defensive-tool-plaso/SKILL.md) | log2timeline scoping (presets, filter files, VSS), pinfo, psort outputs & filters, Timesketch, MACB/TZ pitfalls |
| [`defensive-tool-safety`](Skills/tools/defensive-tool-safety/SKILL.md) | Evaluate/verify/pin/harden any security tool; Trivy 2026 supply-chain lesson; attacker-abused tools; version snapshot |
| [`defensive-tool-sast`](Skills/tools/defensive-tool-sast/SKILL.md) | Semgrep CE licensing vs Opengrep vs CodeQL, taint rules with tests, diff-aware scans, safe scanning of untrusted builds |
| [`defensive-tool-secret-scanners`](Skills/tools/defensive-tool-secret-scanners/SKILL.md) | Gitleaks 8 git/dir/stdin, TruffleHog verification implications, push protection, leaked-secret response |
| [`defensive-tool-sigstore-cosign`](Skills/tools/defensive-tool-sigstore-cosign/SKILL.md) | cosign v3 defaults, keyless signing in CI, identity-pinned verification, attestations, KMS keys, Kyverno enforcement |
| [`defensive-tool-sysinternals`](Skills/tools/defensive-tool-sysinternals/SKILL.md) | Verification, Autoruns/Sigcheck/TCPView/AccessChk usage, VirusTotal privacy, PsExec/ProcDump abuse controls |
| [`defensive-tool-thehive-cortex`](Skills/tools/defensive-tool-thehive-cortex/SKILL.md) | TheHive 6 architecture & hardening, case templates, TLP/PAP observables, Cortex max-TLP/PAP gating, API alerts |
| [`defensive-tool-velociraptor`](Skills/tools/defensive-tool-velociraptor/SKILL.md) | Official deployment security (SSO, roles, lockdown, CA key offline), 0.77.x advisories, VQL, safe hunts, offline collectors |
| [`defensive-tool-volatility3`](Skills/tools/defensive-tool-volatility3/SKILL.md) | Install, symbols (offline packs, dwarf2json), Windows/Linux/macOS plugins, renderers, workflow, sensitive-data safety |
| [`defensive-tool-wazuh`](Skills/tools/defensive-tool-wazuh/SKILL.md) | 2025–2026 CVEs & fixed versions, default creds, api.yaml hardening, ports, secure enrollment, AR safety, logtest |

---

## Red ↔ Blue Map

Load both libraries for purple-team work. claude-red supplies the technique, and claude-blue supplies its detection, containment, and hardening.

| claude-red | claude-blue |
|---|---|
| `offensive-sqli`, `offensive-xss`, `offensive-ssrf`, `offensive-ssti`, `offensive-deserialization`, `offensive-xxe` | `defensive-secure-code-review`, `defensive-waf`, `defensive-tool-sast`, `defensive-tool-dast-scanners` |
| `offensive-waf-bypass`, `offensive-request-smuggling` | `defensive-waf`, `defensive-proxy-tls-inspection` |
| `offensive-api-security`, `offensive-api-abuse`, `offensive-graphql`, `offensive-idor` | `defensive-api-security` |
| `offensive-jwt`, `offensive-oauth` | `defensive-auth-implementation`, `defensive-entra-id` |
| `offensive-active-directory` | `defensive-ad-hardening`, `defensive-ad-detection`, `defensive-tool-ad-assessment`, `defensive-detect-credential-access` |
| `offensive-wifi`, `offensive-evil-twin`, `offensive-deauth-disassoc`, `offensive-wpa-enterprise` | `defensive-wireless-ids`, `defensive-wireless-design`, `defensive-nac` |
| `offensive-cloud` | `defensive-aws-security`, `defensive-azure-security`, `defensive-gcp-security`, `defensive-cloud-ir`, `defensive-tool-cloud-posture` |
| `offensive-container-escape`, `offensive-k8s-attacks` | `defensive-container-hardening`, `defensive-k8s-security`, `defensive-tool-falco` |
| `offensive-cicd-pipeline`, `offensive-cicd-secrets` | `defensive-cicd-hardening`, `defensive-secrets-management`, `defensive-tool-secret-scanners` |
| `offensive-supply-chain`, `offensive-dependency-confusion` | `defensive-sbom-slsa`, `defensive-tool-container-scanners`, `defensive-tool-sigstore-cosign` |
| `offensive-edr-evasion`, `offensive-shellcode`, `offensive-windows-mitigations` | `defensive-detect-defense-evasion`, `defensive-edr-tuning`, `defensive-sysmon`, `defensive-tool-volatility3` |
| `offensive-initial-access`, `offensive-phishing`, `offensive-social-engineering` | `defensive-detect-initial-access`, `defensive-phishing-triage`, `defensive-email-auth`, `defensive-maldoc-analysis` |
| `offensive-linux-privesc`, `offensive-windows-privesc` | `defensive-detect-privilege-escalation`, `defensive-linux-hardening`, `defensive-windows-hardening` |
| `offensive-lateral-movement`, `offensive-persistence` | `defensive-detect-lateral-movement`, `defensive-detect-persistence`, `defensive-hunt-windows` |
| `offensive-data-exfiltration`, `offensive-c2-frameworks` | `defensive-detect-exfiltration`, `defensive-detect-command-and-control`, `defensive-netflow-ndr`, `defensive-dns-security` |
| `offensive-anti-forensics` | `defensive-timeline-analysis`, `defensive-windows-forensics`, `defensive-tool-kape-eztools` |
| `offensive-network-attacks` | `defensive-l2-security`, `defensive-ipv6-security`, `defensive-routing-security`, `defensive-network-forensics` |
| `offensive-iot` | `defensive-ics-security`, `defensive-network-segmentation` |
| `offensive-osint`, `offensive-osint-methodology` | `defensive-cti`, `defensive-blue-research` |
| `offensive-ai-security` | `defensive-ai-security` |
| `offensive-crypto-attacks`, `offensive-tls-attacks` | `defensive-tls-pki`, `defensive-vpn-ipsec`, `defensive-auth-implementation` |
| `offensive-reporting` | `defensive-ir-reporting` |
| `offensive-fast-checking` | `defensive-quick-checks` |

Run offensive techniques only in environments you are authorized to test.

---

## Repository Layout

```text
claude-blue/
├── Skills/<category>/<skill>/SKILL.md    # 184 skills in 32 categories
├── install.sh                            # flattening installer (copy/link, category/skill filters)
├── claude-skills.json                    # generated manifest
├── tools/check-skill.sh                  # linter (frontmatter, name/folder, description ≤1024, sections, fences)
├── tools/build_manifest.py               # regenerates claude-skills.json
├── tools/build_readme_index.py           # regenerates the Categories table + Skill Index
├── tools/skill_summaries.json            # one-line summaries used by the index
├── .github/workflows/validate.yml        # CI lint + manifest check
├── assets/claude-blue-header.png         # README banner
├── MINDMAP.md  CHANGELOG.md  CONTRIBUTING.md  SECURITY.md  LICENSE
```

---

## Roadmap

| Phase | Focus | Status |
|---|---|---|
| 1 | 78 skills across 27 categories, router skill, installer, linter, manifest | ✓ Complete (v1.0) |
| 2 | ATT&CK tactic packs, defense model, network security (20), SOC/SIEM/XDR platforms, 23 doc-verified tool skills, research methodology, AD forest recovery | ✓ Complete (v1.1) |
| 2.5 | Identity & SaaS (PAM, phishing-resistant MFA, Okta, M365, Workspace, SaaS), forensics (disk, container, browser, email), malware (deobfuscation, RE, Linux), Linux/macOS hunts, IR readiness, web compromise, GRC (BCP/DR, policy, privacy), asset inventory, testing program, cloud data & serverless, human & physical, DB/mobile/web-server security | ✓ Complete (v1.2) |
| 3 | `tests/`: sample logs with expected verdicts per skill for regression testing | Planned |
| 4 | Tested Sigma rule pack with TP/FP samples and CI conversion to SPL/KQL/ES\|QL/YARA-L | Planned |
| 6 | Endpoint & mobile: macOS hardening, application control, PowerShell security, MDM, mobile forensics | Planned |
| 7 | Hunting & IR depth: cloud/identity hunts, edge-device compromise, insider threat, data breach response, tabletop exercises | Planned |
| 8 | Resilience & GRC: backup security, third-party risk, PQC crypto-agility, AD CS, virtualization, EASM | Planned |
| 9 | Localized content: Philippine regulatory notes (Data Privacy Act/NPC, DICT/CERT-PH, BSP), APAC threat profiles | Planned |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

1. **One skill, one surface.**
2. **Research first.** Cite primary sources (vendor docs, advisories, standards). Put retrieval dates on version-sensitive facts (see `defensive-blue-research`).
3. **Frontmatter rules.** `name` must equal the folder name. The description should be dense with trigger terms and must be 1,024 characters or fewer.
4. **Verify everything.** Every event ID, field, command, and query must be verified against vendor docs or a lab.
5. **Test detections.** Detections need TP/FP samples and validator output.
6. **Run the checks** before opening a PR:
   - `bash tools/check-skill.sh`
   - `python3 tools/build_manifest.py`
   - `python3 tools/build_readme_index.py` (when adding skills)

---

## Disclaimer

Detections, queries, configurations, and commands are starting points. Field names vary by ingestion pipeline and product version. Tool versions and advisories are a dated snapshot, checked 2026-10-23.

- Test in staging.
- Get approval before running containment actions or active scans in production.
- Use only on systems you are authorized to defend.

## License

[MIT](LICENSE). Use freely; attribution appreciated.

## Author

**Ranilo John Delos Angeles**, CCNA, Sec+. [Portfolio](https://ranilojohn.github.io/Portfolio-Website/)

## Acknowledgements

- **[Kai Aizen (SnailSploit)](https://github.com/SnailSploit)**, creator of [claude-red](https://github.com/SnailSploit/claude-red) (MIT). claude-blue follows its skill-library concept, folder structure, and format. This project would not exist without it.
- **MITRE:** ATT&CK, D3FEND, Engage, ATLAS, and the Center for Threat-Informed Defense.
- **Standards bodies and agencies:** NIST (CSF 2.0, SP 800-207, SP 800-160, SP 800-63-4), FIRST (CVSS, EPSS, TLP), and CISA (KEV, SSVC, BODs, ZTMM).
- **Community projects:** SigmaHQ, OWASP, CIS Controls and Benchmarks, and MANRS.
- **Open-source defenders:**
  - Volatility Foundation, Eric Zimmerman/Kroll, Plaso/Timesketch, Velociraptor, osquery.
  - Zeek, Suricata, Wazuh, Security Onion, Falco.
  - Atomic Red Team, Caldera, Hayabusa, Chainsaw, YARA-X, CyberChef.
  - TheHive/Cortex, MISP, OpenCTI, Prowler, Trivy/Syft/Grype, Sigstore.
  - BloodHound CE, PingCastle, OpenCanary, Canarytokens, T-Pot, Cowrie.

---

<p align="center"><i>Red finds the gap. Blue closes it.</i></p>
