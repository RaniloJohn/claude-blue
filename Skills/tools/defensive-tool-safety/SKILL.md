---
name: defensive-tool-safety
description: "Safe selection, deployment, and operation of defensive security tools: evaluating tools from official documentation, release cadence and maintenance health, verifying downloads (signatures, checksums, Sigstore, provenance), pinning versions and CI actions to commit SHAs (Trivy March 2026 supply chain compromise lesson), least-privilege execution, isolating analysis tools, hardening tool servers (default credentials, exposed UIs, API keys, TLS, SSO/MFA), evidence integrity, data protection for collected telemetry, licensing, tools abused by attackers (Velociraptor, RMM, scanners), change control, and a verified version snapshot of common blue team tools as of October 2026. Use before installing, upgrading, or operating any security tool."
---

# Defensive Tool Safety

Security tools run with high privilege, touch sensitive data, and are attractive targets. A compromised scanner, collector, or SIEM becomes the attacker's best foothold. Treat every tool as **Tier 0 software** until proven otherwise.

## Quick Workflow

1. **Evaluate** from official docs: purpose, maintenance, license, security advisories (`defensive-blue-research`)
2. **Acquire safely**: official source, verify signature/checksum/provenance, pin version
3. **Deploy hardened**: change defaults, TLS, SSO/MFA, RBAC, bind to internal interfaces, least-privilege service account
4. **Operate safely**: authorization for scans/tests, evidence integrity, data handling, logging of tool use
5. **Maintain**: subscribe to advisories, patch on a schedule, re-verify on upgrade, remove unused tools

---

## 1. Evaluation Checklist

| Check | What to look for |
|---|---|
| Official documentation | Install/hardening guides, supported platforms, known limitations |
| Maintenance health | Releases in last 6–12 months, issue response, multiple maintainers, archived repo warning |
| Security advisories for the tool | GitHub Security Advisories, vendor PSIRT, CVE history and response time |
| License | Open source vs source-available vs commercial; restrictions on commercial/SaaS use (e.g., Semgrep Rules License, FoxIO JA4+ license, TheHive licensing tiers) |
| Supply chain | Signed releases, SBOM, reproducible builds, provenance (SLSA), publisher identity |
| Data flows | Does it phone home? Send samples/hashes to cloud? Verify secrets against third-party APIs (TruffleHog verification)? |
| Privilege needed | Root/SYSTEM/kernel driver/domain admin? Can it run with less? |
| Blast radius | What can an attacker do with this tool's server, credentials, or agents? |

---

## 2. Acquiring & Verifying

```bash
# Checksums
sha256sum -c tool_1.2.3_checksums.txt --ignore-missing
# GPG signatures
gpg --verify tool-1.2.3.tar.gz.asc tool-1.2.3.tar.gz
# Sigstore (cosign) keyless verification of a release artifact
cosign verify-blob --bundle tool.sigstore.json \
  --certificate-identity-regexp '^https://github.com/<org>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com tool.tar.gz
# Container image by digest, not tag
docker pull ghcr.io/org/tool@sha256:<digest>
# GitHub artifact attestations
gh attestation verify tool.tar.gz --repo <org>/<repo>
```

Windows: `Get-AuthenticodeSignature .\tool.exe | Format-List Status,SignerCertificate` and `sigcheck -a -h tool.exe`.

### Supply chain lesson — Trivy (CVE-2026-33634)

On March 19, 2026, attackers using stolen credentials published malicious Trivy **v0.69.4** and force-pushed 76 of 77 `aquasecurity/trivy-action` tags (0.0.1–0.34.2) plus all `setup-trivy` tags (0.2.0–0.2.6) with credential-stealing code; a fallback exfiltration path created repositories named `tpcp-docs`. Rotation after an earlier (late Feb/March 1) incident was not atomic, letting the attacker keep access. Safe versions per the advisory: Trivy 0.69.2/0.69.3, trivy-action 0.35.0, setup-trivy 0.2.6 (recreated).

Lessons applied to every tool:
- Pin GitHub Actions and container images to **full commit SHAs/digests**, not tags
- Treat any secret reachable by a pipeline that ran a compromised version as **exposed** — rotate
- Search the org for indicators (`tpcp-docs` repositories, unexpected workflow runs)
- Security scanners in CI need **minimal** tokens (read-only, no cloud admin credentials)

---

## 3. Deployment Hardening (applies to all tool servers)

| Control | Detail |
|---|---|
| Default credentials | Change immediately (e.g., Wazuh OVA `wazuh:wazuh`/`wazuh-wui:wazuh-wui`, Caldera default users, BloodHound initial admin) |
| Authentication | SSO (OIDC/SAML) + MFA; built-in basic auth only for labs (Velociraptor docs: salted SHA-256 basic auth is weak offline) |
| Network exposure | Bind admin UIs/APIs to internal or localhost; IP allowlists (`GUI.allowed_cidr` in Velociraptor); never expose DBs (MISP: MySQL/Redis localhost only) |
| TLS | Trusted certs; pin internal CA for agents; no "insecure" flags in production |
| RBAC | Least privilege; identify admin-equivalent permissions (Velociraptor `ARTIFACT_WRITER`, `EXECVE`, `FILESYSTEM_WRITE`) |
| Secrets | API keys in vault; scoped; rotated; passphrase-protected on workstations |
| Service accounts | Dedicated low-privilege OS user where possible |
| Audit logging | Tool's own audit logs forwarded to SIEM (who ran what query/collection/scan) |
| Lockdown | Use built-in lockdown/read-only modes when not actively responding (Velociraptor `lockdown: true`) |
| Patching | Subscribe to tool advisories; tool servers are KEV-class targets |
| Backups | Config + content (rules, artifacts, playbooks) in version control |

---

## 4. Operating Safely

| Situation | Rule |
|---|---|
| Scanning/emulation | Written authorization, scope, time window, rate limits, stop conditions; never third-party assets |
| Live response | Change management or IR authority; document each command; minimize footprint |
| Forensics | Work on copies; hash evidence; write-block; record tool versions in reports |
| Malware analysis | Isolated lab (no host-only bridges to corp, snapshot/revert), never on analyst workstation |
| Untrusted content | Signed/reviewed rules and templates only (Nuclei code templates must be signed; Velociraptor artifacts reviewed before hunting) |
| Data handling | Collected telemetry contains PII/credentials — encrypt at rest, restrict access, retention limits, privacy review (PH Data Privacy Act / GDPR) |
| Cloud lookups | Don't upload confidential documents/samples to public services (VirusTotal uploads are shared with subscribers) — hash lookup instead |
| Output files | CSV exports can carry formula injection (Velociraptor CVE-2026-64955) — open in safe viewers or sanitize |

---

## 5. Tools Attackers Abuse

| Tool | Abuse | Defense |
|---|---|---|
| Velociraptor | Installed by intruders as persistent remote access/C2 (2025 reports, including outdated vulnerable builds) | Inventory sanctioned servers/client IDs; alert on unknown Velociraptor clients/services |
| RMM (AnyDesk, ScreenConnect, etc.) | Persistence and C2 | Single sanctioned RMM; block others (LOLRMM) |
| Scanners (Nmap, Advanced IP Scanner, Nuclei) | Discovery | Alert when run from non-scanner hosts |
| Rclone, Restic, WinSCP | Exfiltration | Detection pack `defensive-detect-exfiltration` |
| Sysinternals (PsExec, ProcDump) | Lateral movement, LSASS dumping | Restrict, alert outside admin hosts |
| BloodHound collectors (SharpHound) | AD recon | LDAP burst detection, honey objects |
| Atomic Red Team / Caldera agents | Real attacker reuse of public tests | Only run in authorized windows; clean up |

---

## 6. Version Snapshot (verified 2026-10-23 from release tags/advisories)

| Tool | Latest observed | Notes |
|---|---|---|
| Velociraptor | 0.77.3 | 0.77.2/0.77.3 fix many server CVEs (ACL bypasses, OIDC email spoofing, CSV injection) |
| osquery | 5.24.0 | |
| Volatility 3 | 2.28.x | Volatility 2 deprecated; parity release May 2025 |
| Plaso | 20260928 | Date-based versions |
| Hayabusa | 4.2.0 | v4.0+ replaced `csv-timeline`/`json-timeline` with `dfir-timeline` |
| Chainsaw | 2.17.1 | |
| CyberChef | 11.5.0 | |
| MISP | 2.5.x | |
| OpenCTI | 7.x | |
| TheHive | 6.x | Licensing via StrangeBee (community license available) |
| Cortex | 4.2.0 | |
| Falco | 0.45.1 | 0.44 removed legacy eBPF probe, gVisor engine, gRPC output |
| Trivy | 0.76.x | See March 2026 compromise above |
| Syft / Grype | 1.55.0 / 0.121.0 | |
| Cosign | 3.1.x | v3 defaults: bundle format, trusted root, signing config |
| Semgrep CE / Opengrep | 1.182.0 / 1.32.0 | Semgrep rules under non-OSI Semgrep Rules License |
| Gitleaks / TruffleHog | 8.30.1 / 3.99.x | |
| ZAP / Nuclei | 2.17.0 / 3.11.x | Nuclei code templates must be signed |
| Nmap | 7.99x | |
| BloodHound CE | 9.8.0 | SharpHound 2.17.0, AzureHound 3.1.1 |
| PingCastle | 4.0.x | Netwrix |
| Prowler | 5.45.x | ScoutSuite last PyPI release 2024 — low maintenance |
| Invoke-AtomicRedTeam / Caldera | 2.3.0 / 5.3.0 | |
| capa / FLOSS | 10.0.0 / 3.2.0 | |
| YARA / YARA-X | 4.5.x / 1.22.0 | YARA-X is the successor (CLI `yr`) |
| Sigma CLI | 3.1.0 | |
| Zeek | 9.0.0 (LTS) | Many security fixes; 8.0.x supported until 9.1 |
| Suricata | 8.0.7 | |
| Wazuh | 4.14.9 | 5.0 in beta |
| Security Onion | 3.3.0 | Oracle Linux 9 only; Stenographer removed (Suricata PCAP); 2.4 EOL Oct 1, 2026 |
| RITA | 5.1.x | |
| Arkime | 6.9.x | |
| Wireshark | 4.6.x stable (4.7 = development) | |
| Sleuth Kit / Autopsy | 4.15.0 / 4.23.x | |
| AVML / LiME | 0.21.0 / 1.12.0 | |
| T-Pot / Cowrie / OpenCanary | 24.04.x / 3.1.x / 0.9.10 | |
| Lynis / OpenSCAP / AIDE | 3.1.7 / 1.4.6 / 0.19.x | |
| Vector / Fluent Bit | 0.60.0 / 5.1.x | |
| MVT | 2026.10.12 | |

Re-verify before deploying — this table is a dated snapshot, not a source of truth.

---

## Engagement Cheatsheet

```text
evaluate (docs, maintenance, advisories, license, data flows, privilege, blast radius) → verify (checksum/GPG/cosign/attestation, digest pins, SHA-pinned actions)
→ harden (defaults, SSO+MFA, internal binding, TLS, RBAC, vaulted keys, audit logs, lockdown) → operate (authorization, evidence integrity, isolation, data protection)
→ watch for attacker abuse of the same tools → patch + re-verify on every upgrade
```

---

## Key References

- GHSA-69fq-xp46-6x23 / CVE-2026-33634 (Trivy); Velociraptor security advisories (docs.velociraptor.app); Velociraptor deployment security guide
- CISA/NSA "Securing the Software Supply Chain" guidance; OpenSSF Scorecard; SLSA
- Related: `defensive-blue-research`, `defensive-cicd-hardening`, `defensive-sbom-slsa`, `defensive-tool-velociraptor`
