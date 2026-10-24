---
name: defensive-database-security
description: "Database security for SQL Server, PostgreSQL, MySQL/MariaDB, Oracle, MongoDB, Redis, Elasticsearch/OpenSearch and cloud managed databases (RDS/Aurora, Azure SQL, Cloud SQL): network exposure and authentication hardening, least-privilege roles and service accounts, removing defaults and sample data, encryption in transit and at rest (TDE), auditing (SQL Server Audit, pgaudit, MySQL audit plugins, MongoDB auditing), detecting abuse (xp_cmdshell, COPY TO PROGRAM, mass SELECTs, dumps), SQL injection defense from the DB side, backups and restore security, secrets rotation, and common exposure incidents (unauthenticated MongoDB/Elasticsearch/Redis on the internet). Use when hardening or monitoring databases."
---

# Database Security

Databases hold the data attackers want. Most breaches come from **exposure** (internet-reachable, no auth), **over-privileged app accounts**, or **SQL injection** — then mass export.

## Quick Workflow

1. Inventory databases (including shadow/dev copies) and exposure
2. Remove internet exposure; require authentication + TLS
3. Least-privilege accounts; remove defaults; rotate secrets
4. Enable auditing for privileged actions and bulk reads; send to SIEM
5. Encrypt at rest; protect backups; test restores

---

## 1. Exposure & Authentication

| Engine | Must-do |
|---|---|
| SQL Server | Windows/Entra auth preferred; disable `sa` or rename + strong password; `xp_cmdshell` disabled; TLS forced |
| PostgreSQL | `listen_addresses` restricted; `pg_hba.conf` with `scram-sha-256` (not `trust`/`md5`); `hostssl` lines |
| MySQL/MariaDB | `bind-address` internal; remove anonymous users/test DB (`mysql_secure_installation`); `require_secure_transport=ON` |
| MongoDB | `security.authorization: enabled`; bind to internal IPs (default localhost since 3.6 — don't change to 0.0.0.0 carelessly) |
| Redis | `protected-mode yes`, ACLs/`requirepass`, bind internal, rename/disable `CONFIG`, `FLUSHALL`, `MODULE` for app users |
| Elasticsearch/OpenSearch | Security features on (auth + TLS); never expose 9200 publicly |
| Cloud managed | No public endpoints (private subnets/Private Link/Private Service Connect); IAM/Entra auth where supported; enforce TLS |

Internet-exposed unauthenticated MongoDB/Elasticsearch/Redis instances are routinely wiped and ransomed within hours — check EASM (`defensive-asset-inventory`).

---

## 2. Privileges

- Separate accounts: app (CRUD on its schema only), migration (DDL), read-only analytics, DBA (individual, MFA via bastion/PAM)
- No app account with `db_owner`/`SUPERUSER`/`ALL PRIVILEGES`
- Row-level security / views for multi-tenant data
- Rotate credentials via secret manager; prefer IAM/managed identity auth (RDS IAM auth, Azure AD/Entra auth for Azure SQL, Cloud SQL IAM)

---

## 3. Encryption

TLS for all connections (verify certificates in clients); TDE or storage encryption at rest (default in cloud managed services); column-level encryption for highly sensitive fields (SQL Server Always Encrypted, application-level encryption); encrypted backups.

---

## 4. Auditing

| Engine | Mechanism | Audit at least |
|---|---|---|
| SQL Server | SQL Server Audit / Extended Events | Logins (success/fail), permission changes, `xp_cmdshell`/CLR enabling, `BACKUP`, schema changes |
| PostgreSQL | `pgaudit` (`pgaudit.log = 'ddl, role, write'` + read on sensitive tables), `log_connections` | Role changes, DDL, `COPY`, function creation |
| MySQL | Enterprise Audit / MariaDB Audit Plugin / Percona audit | Logins, privilege changes, DDL |
| MongoDB | Auditing (Enterprise/Atlas) | authCheck failures, user/role changes |
| Cloud | RDS/Aurora log exports, Azure SQL Auditing, Cloud SQL audit logs, Database Activity Streams | Same |

---

## 5. Detecting Abuse

| Behavior | Signal |
|---|---|
| OS command execution | SQL Server `sp_configure 'xp_cmdshell', 1`; PostgreSQL `COPY ... TO/FROM PROGRAM`, `CREATE FUNCTION ... LANGUAGE C`/untrusted languages; MySQL `INTO OUTFILE`/UDFs |
| Mass data access | `SELECT *` without `WHERE` on sensitive tables, row counts far above baseline, large result sets to new clients |
| Dumps | `mysqldump`, `pg_dump`, `bcp`, `sqlcmd -Q "BACKUP"` from unusual hosts/users |
| Brute force | Auth failures spikes |
| SQL injection | Errors (syntax errors spikes), `UNION SELECT`, `SLEEP(`/`WAITFOR DELAY`, `information_schema` queries from app accounts |
| Privilege changes | `GRANT`, `ALTER ROLE ... SUPERUSER`, new logins |

Database servers spawning shells (`sqlservr.exe` → `cmd.exe`, `postgres` → `sh`) are high-severity EDR detections.

---

## 6. Application Side

Parameterized queries/ORMs, stored procedures without dynamic SQL concatenation, input validation, least-privilege app accounts so injection impact is limited (`defensive-secure-code-review`, `defensive-waf`).

---

## Engagement Cheatsheet

```text
inventory + exposure (no public, private endpoints) → auth on (scram, Entra/IAM auth), remove defaults, TLS required → per-purpose least-privilege accounts + vaulted rotation
→ TDE/column encryption + encrypted backups → audit (SQL Audit/pgaudit/plugins/cloud) → detect xp_cmdshell/COPY PROGRAM, mass reads, dumps, SQLi patterns, DB→shell
```

---

## Key References

- CIS Benchmarks (SQL Server, PostgreSQL, MySQL, MongoDB); pgaudit docs; Microsoft SQL Server security best practices; vendor cloud database security guides
- Related: `defensive-secure-code-review`, `defensive-cloud-data-security`, `defensive-detect-collection`, `defensive-linux-hardening`
