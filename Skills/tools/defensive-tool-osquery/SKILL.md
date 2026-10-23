---
name: defensive-tool-osquery
description: "osquery endpoint visibility from official documentation: osqueryi vs osqueryd, config sources (filesystem and TLS plugins), root-owned read-only config, flags vs options, schedule intervals and uptime semantics, differential vs snapshot results, packs with discovery queries and sharding, watchdog limits and denylisting, logging plugins and file permissions, evented tables (process auditing via audit/eBPF, EndpointSecurity on macOS, Windows event log/NTFS journal), file integrity monitoring with file_paths, YARA, carving and distributed query risks, fleet managers (Fleet), and security-relevant query library. Use when deploying osquery, writing osquery SQL, or hardening an osquery fleet."
---

# osquery

osquery exposes the OS as SQL tables. It's ideal for fleet-wide state questions ("which hosts have this persistence/listening port/vulnerable package?") and lightweight scheduled monitoring. Version observed: 5.24.0 (2026-10-23).

## Quick Workflow

1. Prototype in `osqueryi`; validate config with `osqueryi --verbose --config_path <file>` / `osqueryctl config-check`
2. Deploy `osqueryd` with root-owned, read-only config (`0444`) and restricted logs (`0600`)
3. Group queries into packs with discovery queries; roll out with `shard`
4. Tune watchdog; fix denylisted queries by rewriting SQL
5. Ship logs to SIEM; manage remotely via TLS (Fleet or similar) with strong enrollment secrets

---

## 1. Config Essentials (from docs)

| Topic | Practice |
|---|---|
| Config paths | `/etc/osquery/osquery.conf` (Linux), `/var/osquery/osquery.conf` (macOS), `C:\Program Files\osquery\osquery.conf`; modular `osquery.conf.d/` |
| Remote config | `--config_plugin=tls` (JSON response) |
| Flags vs options | Initialization flags only on CLI/flagfile; `options` only for CLI-overridable flags |
| Intervals | Max 604,800 s; counted in daemon uptime, not wall clock (laptops may delay) |
| Results | Differential by default (adds/removes, cached in RocksDB); `snapshot: true` for full sets |
| Startup | `startup_priority` for queries that must run at boot |
| Packs | Discovery queries gate execution (refresh every 60 min default); `platform`, `version`, `shard` at pack level |
| Splay | `schedule_splay_percent` to spread load |
| Decorators | One row each; avoid overwriting reserved top-level keys with `decorations_top_level` |

```json
{
  "options": { "schedule_splay_percent": 10, "host_identifier": "uuid" },
  "schedule": {
    "listening_ports": { "query": "SELECT p.name, p.path, l.port, l.address, l.protocol FROM listening_ports l JOIN processes p USING (pid) WHERE l.address NOT IN ('127.0.0.1','::1');", "interval": 3600 },
    "startup_items_win": { "query": "SELECT name, path, source, status FROM startup_items;", "interval": 3600, "platform": "windows" }
  },
  "file_paths": { "ssh": ["/home/%/.ssh/%%", "/root/.ssh/%%"], "etc": ["/etc/%%"] },
  "packs": { "persistence": "/etc/osquery/packs/persistence.conf" }
}
```

---

## 2. Watchdog & Performance

- Watchdog denylists queries exceeding limits (returns after 1-day cooldown); fix SQL instead of relying on `denylist: false`
- Tune `--watchdog_level`, `--watchdog_memory_limit`, `--watchdog_utilization_limit`, `--watchdog_delay` (default 60 s)
- Select only needed columns; use JOINs on indexed/required columns; avoid recursive `file` globs (`%%`) on large trees
- Measure with `osquery_schedule` table (`wall_time`, `user_time`, `average_memory`, `executions`, `denylisted`)

```sql
SELECT name, interval, executions, average_memory, wall_time_ms, denylisted FROM osquery_schedule ORDER BY wall_time_ms DESC LIMIT 10;
```

---

## 3. Evented Tables

| Platform | Tables | Enable |
|---|---|---|
| Linux | `process_events`, `socket_events` (audit), `bpf_process_events`, `bpf_socket_events` (eBPF), `file_events` (inotify) | `--disable_events=false`, `--audit_allow_process_events=true` or `--enable_bpf_events=true`; audit mode conflicts with auditd owning the audit netlink |
| macOS | `es_process_events`, `es_process_file_events` | `--disable_endpointsecurity=false` (requires Full Disk Access/System Extension approval via MDM) |
| Windows | `windows_eventlog`/`windows_events`, `ntfs_journal_events`, `powershell_events` | `--enable_windows_events_subscriber`, publisher flags |

Disable unneeded subscribers with `events.disable_subscribers`; check `SELECT * FROM osquery_events WHERE type = 'subscriber';`. Publishers are controlled by CLI flags only.

FIM: categories in `file_paths`, optional `file_accesses`; YARA mappings in `yara.file_paths` must match `file_paths` categories.

---

## 4. Security Considerations

| Risk | Mitigation |
|---|---|
| Fleet manager = remote query on every host (recon power) | SSO + MFA, RBAC (observer vs maintainer vs admin), audit live queries, restrict network access to the manager |
| Enrollment secret leakage | Rotate; per-team secrets; TLS with pinned server cert (`--tls_server_certs`) |
| File carving (`carves` table) can exfiltrate files | Keep `--disable_carver=true` unless needed; restrict who can request carves |
| Logs with sensitive data (command lines, file contents via YARA matches, shell history) | `0600` logs, encrypted transport, retention limits |
| Config tampering | Root-owned read-only config; FIM on config/flagfile |
| Cloud metadata tables outside cloud | Don't query Azure metadata tables off Azure (docs warn); EC2 tag retrieval needs `ec2:DescribeTags` |

---

## 5. Security Query Library

```sql
-- Processes running from deleted binaries (Linux)
SELECT pid, name, path, cmdline FROM processes WHERE on_disk = 0;
-- Unsigned processes from user-writable paths (Windows)
SELECT p.pid, p.name, p.path, s.result FROM processes p JOIN authenticode s ON p.path = s.path WHERE s.result != 'trusted' AND (p.path LIKE 'C:\Users\%' OR p.path LIKE 'C:\ProgramData\%');
-- SUID binaries outside standard locations
SELECT path, username, permissions FROM suid_bin WHERE path NOT LIKE '/usr/bin/%' AND path NOT LIKE '/usr/sbin/%' AND path NOT LIKE '/bin/%';
-- Authorized SSH keys
SELECT u.username, k.key_file, k.key FROM users u CROSS JOIN authorized_keys k USING (uid);
-- Scheduled tasks running script hosts (Windows)
SELECT name, action, path, enabled FROM scheduled_tasks WHERE action LIKE '%powershell%' OR action LIKE '%mshta%' OR action LIKE '%wscript%';
-- macOS launch items not from Apple
SELECT name, path, program, program_arguments FROM launchd WHERE path NOT LIKE '/System/%';
-- Kernel modules / browser extensions
SELECT name, size, used_by FROM kernel_modules;
SELECT u.username, c.name, c.identifier, c.permissions FROM users u CROSS JOIN chrome_extensions c USING (uid);
-- Listening on all interfaces
SELECT DISTINCT p.name, l.port FROM listening_ports l JOIN processes p USING (pid) WHERE l.address IN ('0.0.0.0','::');
```

---

## Engagement Cheatsheet

```text
osqueryi prototype → config-check → osqueryd with root-owned 0444 config + 0600 logs → packs + discovery + shard rollout
→ watchdog tuning via osquery_schedule → evented tables (audit/eBPF, ES, Windows events) + FIM file_paths
→ manager hardening (SSO/MFA/RBAC/audit), carver off, pinned TLS → security query library
```

---

## Key References

- osquery.readthedocs.io (Configuration, Process Auditing, File Integrity Monitoring, Remote Settings, Performance Safety); osquery schema (osquery.io/schema)
- Fleet documentation (fleetdm.com/docs)
- Related: `defensive-tool-safety`, `defensive-threat-hunting`, `defensive-linux-telemetry`, `defensive-macos-forensics`
