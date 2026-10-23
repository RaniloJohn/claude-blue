# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

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
