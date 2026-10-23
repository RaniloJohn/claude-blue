---
name: defensive-tool-velociraptor
description: "Velociraptor DFIR platform deployment and safe operation from official documentation: server/client architecture, config generation, self-signed vs Let's Encrypt TLS, mTLS, SSO (OIDC/SAML) instead of basic auth, roles and admin-equivalent permissions (ARTIFACT_WRITER, EXECVE, FILESYSTEM_WRITE), GUI.allowed_cidr, API key scoping, lockdown mode, multi-org isolation, audit log forwarding, secrets_dek, artifact review and required_permissions, hunt resource limits, offline collectors with encrypted output, VQL basics and key artifacts, 0.77.2/0.77.3 security advisories, and detecting attacker-installed Velociraptor. Use when deploying, hardening, hunting, or collecting with Velociraptor."
---

# Velociraptor

Velociraptor gives responders remote, scalable endpoint visibility via VQL. That same power — run any artifact on every endpoint with SYSTEM/root — makes the server a crown-jewel system. Harden it like a domain controller.

## Quick Workflow

1. Deploy current release (0.77.3 as of 2026-10-23; 0.77.2/0.77.3 fix many server CVEs)
2. Generate config; remove CA private key from server config and store offline
3. SSO + MFA; least-privilege roles; restrict GUI by CIDR; API on localhost
4. Enable audit forwarding; consider `lockdown: true` outside active incidents
5. Review every artifact before hunting; set resource limits on hunts
6. Use offline collectors with encrypted output where agents can't be deployed

---

## 1. Deployment

```bash
velociraptor config generate -i > server.config.yaml          # interactive wizard
velociraptor --config server.config.yaml frontend -v           # run server
velociraptor --config server.config.yaml config client > client.config.yaml
velociraptor config repack --msi velociraptor-windows.msi client.config.yaml corp-velo.msi   # Windows MSI with embedded config
velociraptor gui                                               # local single-user test instance (labs only)
```

Run the server as a dedicated low-privilege Linux user; config file writable only by root.

---

## 2. Hardening (from the official deployment security guide)

| Area | Practice |
|---|---|
| CA key | Remove `CA.private_key` from server config; keep offline (needed only for API keys/cert rotation) |
| TLS | Self-signed mode pins internal CA (`Client.use_self_signed_ssl`) — stronger than public roots; with Let's Encrypt, GUI shares frontend port so port filtering can't isolate GUI |
| TLS inspection proxies | Add proxy CA to `Client.Crypto.root_certs`; never deploy `Client.insecure_network_trace_file` (disables verification) |
| mTLS | Require client certs at the frontend; plan reissue before 1-year expiry |
| Authentication | OIDC/OAuth2/SAML with MFA in production; basic auth (salted SHA-256) labs only; `initial_users` only to bootstrap |
| Roles | Built-in roles, least privilege; treat `ARTIFACT_WRITER`, `SERVER_ARTIFACT_WRITER`, `EXECVE`, `FILESYSTEM_WRITE` as admin-equivalent |
| API | Bind API to 127.0.0.1 unless needed; API clients need `api` role + minimal others; revoke by granting empty role; passphrase-encrypt API keys on workstations |
| GUI exposure | `GUI.allowed_cidr`; or bind GUI to localhost + SSH tunnel; segment network |
| Multi-org | SSO auto-role assignment grants roles in **every** org — assign manually or run separate instances for tenant isolation; deny `execve` via `security.denied_plugins`; restrict `file`/`fs` accessors (custom `denied_fs_accessor_prefix` replaces defaults — re-include `acl`, `backups`, `config`, `orgs`, `secrets`, `users`) |
| Lockdown | `lockdown: true` denies artifact writing, execution, machine-state modification even for admins |
| Enrollment | Stop new enrollments with `Frontend.resources.enrollments_per_second: -1` |
| Secrets | Set `security.secrets_dek` explicitly from env/secret manager |
| Trust | Identify clients by cryptographic client ID — hostnames/labels are client-reported |
| Audit | Review audit directory / `Server.Audit.Logs`; forward via `Logging.remote_syslog_server` |

---

## 3. Security Advisories

| Release | Fixed (selection) |
|---|---|
| 0.77.2 | Network ACL bypass in upload plugins (CVE-2026-18348), cross-org impersonation via `query` (CVE-2026-18635), VFS path deny-list bypass (CVE-2026-18636), notebook directory traversal (CVE-2026-18640), authenticated identity spoofing (CVE-2026-18972), OIDC email spoofing (CVE-2026-18639), hunt/org/collect_client permission checks, NTFS parser crashes, CSV formula injection (CVE-2026-64955) |
| 0.77.3 | Privilege escalation via a Sysmon monitoring artifact (CVE-2026-78411), cross-org WatchEvent streaming (CVE-2026-78412), server metadata permission check (CVE-2026-78413) |

If you can't move to 0.77.x, the advisory points to the latest 0.76.7 build. Open exported CSVs safely (formula injection).

---

## 4. VQL & Key Artifacts

```sql
SELECT Pid, Ppid, Name, CommandLine, Exe, Username FROM pslist() WHERE Name =~ "(?i)powershell|rundll32|mshta"
SELECT * FROM Artifact.Windows.Network.Netstat() WHERE Status = "ESTAB" AND NOT Raddr.IP =~ "^(10|192\\.168|172\\.(1[6-9]|2[0-9]|3[01]))\\."
SELECT FullPath, Size, Mtime FROM glob(globs="C:/Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/*")
```

| Artifact | Use |
|---|---|
| `Windows.KapeFiles.Targets` (`Windows.Triage.Targets` in newer releases) | KAPE-style triage collection |
| `Windows.EventLogs.EvtxHunter` | Keyword/regex across EVTX |
| `Windows.Hayabusa.Rules` / Sigma artifacts | Sigma-based event log triage (exchange/built-in, verify availability) |
| `Windows.Detection.Yara.Process` / `Generic.Detection.Yara.Glob` | YARA on memory/files |
| `Windows.Sysinternals.Autoruns` | Persistence sweep |
| `Windows.Forensics.Prefetch`, `Windows.Detection.Amcache`, `Windows.Registry.*` | Execution evidence |
| `Windows.System.Pslist`, `Windows.Network.Netstat` | Live state |
| `Linux.Sys.BashHistory`, `Linux.Sys.Crontab`, `Linux.Ssh.AuthorizedKeys` | Linux triage |
| `MacOS.System.*` | macOS triage |
| `Server.Monitor.Health` | Server health |

---

## 5. Hunting Safely

- **Review artifacts** (especially exchange/community ones) — a hostile artifact runs with full client privileges; set `required_permissions` on artifacts that execute commands; wrap dangerous ones in curated versions with fixed parameters
- Target with labels/OS conditions; start with a small pilot label
- Set resource limits: CPU limit %, `max_rows`, max upload bytes, timeout
- Large uploads (memory, full disks) only on scoped hosts
- Record hunt IDs and parameters in the case

---

## 6. Offline Collectors

Build via GUI (Server artifact `Server.Utils.CreateCollector`) for hosts without agents: choose artifacts, **encrypt the output container** (X.509 with server cert, PGP, or password), and if uploading to cloud/SFTP, use write-only, scoped, short-lived credentials (the collector binary embeds them). Deliver over a trusted channel, run as admin, verify hashes of returned archives, import into the server for analysis.

---

## 7. Detecting Malicious Velociraptor Use

Intruders have deployed Velociraptor (sometimes outdated, vulnerable builds) as remote access. Detect:
- Velociraptor service/binary on hosts not in your client inventory or with a server URL you don't own
- Network connections to unknown Velociraptor frontends (TLS to unexpected hosts from `velociraptor.exe`)
- New MSI installs of Velociraptor outside change windows

---

## Engagement Cheatsheet

```text
0.77.3+ → config generate → CA key offline → SSO+MFA, least-privilege roles (ARTIFACT_WRITER/EXECVE/FILESYSTEM_WRITE = admin) → API localhost, GUI.allowed_cidr
→ audit to syslog/SIEM → lockdown when idle → review artifacts + required_permissions → pilot hunts with CPU/rows/upload limits
→ encrypted offline collectors with scoped upload creds → alert on unknown Velociraptor clients
```

---

## Key References

- docs.velociraptor.app — Deployment Security, Security Advisories (0.77.2, 0.77.3), VQL reference, Artifact exchange
- Related: `defensive-tool-safety`, `defensive-live-response`, `defensive-tool-kape-eztools`, `defensive-threat-hunting`
