# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [1.2.2] — 2026-10-25

### Added
- `defensive-cve-researcher`: researcher-side CVE workflow — authorization and legal limits (DOJ CFAA policy, PH RA 10175), patch-diff and variant analysis, lab validation with benign markers, CVSS 3.1/4.0 and CWE, CNA selection (CNA Rules v4.2.0), report writing, 90-day coordination (182 skills)

## [1.2.1] — 2026-10-25

### Added
- `defensive-browser-security`: extension governance after Chrome MV2 end (Chrome 139 / Web Store removal Aug 31, 2026), App-Bound Encryption and DBSC against cookie theft, Microsoft ClickFix mitigations and RunMRU hunting, macOS ClickFix variants (181 skills)

## [1.2.0] — 2026-10-24

### Added
- **30 new skills (180 total, 32 categories)**, version-sensitive facts verified against primary sources on 2026-10-24
- Identity & SaaS: `defensive-pam` (Windows LAPS, dMSA/BadSuccessor CVE-2025-53779, break-glass), `defensive-phishing-resistant-mfa` (NIST SP 800-63-4, Entra passkeys, mandatory Azure MFA), `defensive-okta-security`, `defensive-m365-security` (ScubaGear, SMTP AUTH default-off end-2026, Purview retention), `defensive-google-workspace-security`, `defensive-saas-security` (Salesloft Drift, UNC6040, Snowflake MFA phases)
- Forensics: disk imaging, container, browser, email
- Malware: script deobfuscation, reverse engineering, Linux malware
- Hunting: Linux, macOS
- IR: IR readiness, web compromise response
- GRC: BCP/DR, policy & standards, privacy & data protection
- Vuln mgmt: asset inventory, security testing program
- Endpoint: USB device control; Cloud: cloud data security, serverless security
- New **Human & Physical** category: security awareness, physical security
- AppSec/Hardening: database security, mobile app security, web server hardening

### Changed
- Router, README index, manifest updated

 — 2026-10-23

### Added
- **72 new skills (150 total, 31 categories)**
- **Research** (1): `defensive-blue-research` — research-first methodology (source hierarchy, currency verification, Admiralty grading, lab validation, recommendation format)
- **Defense Model** (10): security fundamentals, defense in depth, zero trust architecture, security architecture, kill chain/Diamond/Pyramid, threat-informed defense, active defense (MITRE Engage), cyber resilience (NIST 800-160v2), D3FEND countermeasures, security operating model
- **ATT&CK Detection Packs** (12): one per tactic — initial access through impact
- **Network Security** (+15 → 20): architecture, NGFW policy, IDS/IPS deployment, NetFlow/NDR, network forensics, DNS, proxy/TLS inspection, remote access/ZTNA, VPN/IPsec, NAC, IPv6, routing/BGP, SD-WAN/SASE, DDoS, TLS/PKI — Cisco IOS-XE and Huawei VRP examples
- **SOC** (+4): SOC building, security metrics, UEBA/RBA, log parsing
- **SIEM & XDR** (+6): Graylog, QRadar, Google SecOps (YARA-L), CrowdStrike Falcon (CQL/RTR), Defender XDR, SentinelOne
- **Active Directory** (+1): AD forest recovery
- **Tools** (23): `defensive-tool-safety` umbrella plus doc-verified skills for Velociraptor, osquery, KAPE/EZ Tools, Volatility 3, Hayabusa/Chainsaw, Plaso, CyberChef, TheHive/Cortex, MISP/OpenCTI, Falco, Trivy/Syft/Grype, Sigstore cosign, SAST (Semgrep/Opengrep/CodeQL), secret scanners, DAST (ZAP/Nuclei), Nmap, AD assessment (BloodHound CE/PingCastle), cloud posture (Prowler/Steampipe/kube-bench), emulation (Atomic Red Team/Caldera), Sysinternals, Wazuh operations, honeypots
- Router: principles 13–14 (research-first, tools are Tier 0), workflows W7 Defense Architecture and W8 Research & Recommendation, expanded skill router and current-state notes
- `tools/build_readme_index.py` and `tools/skill_summaries.json` to generate the README index

### Changed
- README rebuilt (centered header, badges, defense-model map, 150-skill index, expanded Red ↔ Blue map, roadmap)
- Security Onion skill updated for 3.x (Oracle Linux 9 only, Stenographer → Suricata PCAP, 2.4 EOL Oct 1 2026)
- Wazuh, Sysmon (native Sysmon behavior), CI/CD (Trivy compromise), Zeek (9.0 LTS), Suricata (8.0.x) updated
- Cross-references to unbuilt skills repointed to existing skills

### Content currency (verified 2026-10-23 from release tags, vendor docs, advisories)
- Trivy supply chain compromise CVE-2026-33634 (March 2026); Velociraptor 0.77.2/0.77.3 advisories; Wazuh CVE-2025-24016 (KEV), CVE-2026-30893, CVE-2026-34150
- Falco 0.44 removals (legacy eBPF, gVisor, gRPC output); cosign v3 defaults; Semgrep Rules License / Opengrep; Hayabusa 4.x `dfir-timeline`
- Security Onion 3.x; Zeek 9.0 LTS; Suricata 8.0.7; BloodHound CE 9.8.0; CA/B SC-081 certificate lifetimes; NIST SP 800-63-4

## [1.0.0] — 2026-10-23

### Added
- **Core router skill** `claude-blue`: operating principles, workflows W1–W6, skill router, output templates, current-state notes
- **77 specialist skills across 26 domains**: SOC operations (4), detection engineering (5), SIEM platforms (5), threat hunting (3), incident response (5), digital forensics (5), malware analysis (3), threat intelligence (3), endpoint (5), Active Directory (2), identity (2), application security (4), network defense (5), wireless (2), cloud (4), container & Kubernetes (2), supply chain & CI/CD (3), vulnerability management (2), hardening (2), email security (2), deception (1), OT/ICS (1), AI security (1), purple team (2), GRC (2), utility (2)
- `install.sh` with copy/symlink, category and skill filters, core-only, project-level target
- `tools/check-skill.sh` linter and `tools/build_manifest.py` manifest generator
- `claude-skills.json` manifest
- CI workflow `.github/workflows/validate.yml`

### Content currency (verified October 2026)
- MITRE ATT&CK v18 (Detection Strategies/Analytics), D3FEND 1.0
- OWASP Top 10:2025, OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026, OWASP API Top 10 2023
- DMARCbis RFC 9989/9990/9991 (May 2026)
- CISA BOD 26-04 (June 2026), EPSS v4 (March 2025), NVD enrichment triage (April 2026), EU CRA reporting (Sept 2026)
- Kerberos RC4 removal (CVE-2026-20833 / KB5073381), NTLM deprecation roadmap, KB5014754 full enforcement, AD CS ESC1–ESC16
- Native Sysmon in Windows 11, Sysmon v15 EID 29; Volatility 3 parity release; YARA-X 1.x; Suricata 8; Zeek 8
- Microsoft Sentinel Azure portal retirement (31 March 2027)
- Supply chain incidents: tj-actions/changed-files (CVE-2025-30066), Shai-Hulud npm worm family (2025–2026)
