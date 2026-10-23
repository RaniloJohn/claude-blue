---
name: defensive-secure-code-review
description: "Defensive secure code review mapped to OWASP Top 10:2025 (Broken Access Control incl. SSRF, Security Misconfiguration, Software Supply Chain Failures, Cryptographic Failures, Injection, Insecure Design, Authentication Failures, Software or Data Integrity Failures, Security Logging and Alerting Failures, Mishandling of Exceptional Conditions): root causes and fix patterns for SQL injection, XSS, SSRF, SSTI, XXE, command injection, path traversal, insecure deserialization, IDOR/BOLA, mass assignment, race conditions, open redirects, file upload, and secrets in code, with language-specific safe APIs (Python, Java, C#, JavaScript/TypeScript, PHP, Go). Use when reviewing code, writing remediation guidance, or triaging SAST findings."
---

# Secure Code Review

Review for sources (untrusted input), sinks (dangerous operations), and the controls between them. Fixes go at the sink with safe APIs, not in ad-hoc filters at the source.

## Quick Workflow

1. Map trust boundaries and entry points (routes, handlers, message consumers, file parsers)
2. Trace untrusted data to sinks
3. Check authorization on every object/function access
4. Check crypto, secrets, error handling, logging
5. Recommend sink-level fixes with code
6. Add tests and SAST rules to prevent regressions

---

## 1. OWASP Top 10:2025

| ID | Category | Review focus |
|---|---|---|
| A01 | Broken Access Control (incl. SSRF) | Object-level and function-level authz, tenant isolation, SSRF to metadata/internal |
| A02 | Security Misconfiguration | Debug modes, default creds, verbose errors, permissive CORS, security headers |
| A03 | Software Supply Chain Failures | Dependency pinning, provenance, build integrity, unmaintained packages |
| A04 | Cryptographic Failures | TLS, weak algorithms, hardcoded keys, randomness |
| A05 | Injection | SQL/NoSQL/OS/LDAP/template/XSS |
| A06 | Insecure Design | Missing threat model, business logic abuse, rate limits |
| A07 | Authentication Failures | Session, credential storage, MFA, brute-force protection |
| A08 | Software or Data Integrity Failures | Unsigned updates, insecure deserialization, CI/CD tampering |
| A09 | Security Logging and Alerting Failures | Missing/insufficient audit events, no alerting |
| A10 | Mishandling of Exceptional Conditions | Fail-open logic, unhandled errors, resource exhaustion paths |

---

## 2. Injection → Parameterize

| Language | Unsafe | Safe |
|---|---|---|
| Python (DB-API) | `cur.execute(f"SELECT * FROM u WHERE id={uid}")` | `cur.execute("SELECT * FROM u WHERE id=%s", (uid,))` |
| Java (JDBC) | `stmt.executeQuery("... WHERE id=" + id)` | `PreparedStatement ps = c.prepareStatement("... WHERE id=?"); ps.setInt(1,id);` |
| C# | `new SqlCommand("... '"+name+"'")` | `cmd.Parameters.AddWithValue("@name", name)` |
| Node (pg) | ``client.query(`... ${id}`)`` | `client.query('... WHERE id=$1', [id])` |
| PHP (PDO) | `$db->query("... $id")` | `$st=$db->prepare('... WHERE id=?'); $st->execute([$id]);` |
| Go | `db.Query("... " + id)` | `db.Query("... WHERE id=$1", id)` |

ORMs: watch raw-query escape hatches (`raw()`, `extra()`, `$queryRawUnsafe`, `FromSqlRaw` with interpolation). Identifiers (table/column/order-by) can't be parameterized — use allowlists.

OS command: avoid shells. `subprocess.run(["ping","-c","1",host], shell=False)` + validate `host` against strict regex/allowlist.

---

## 3. XSS → Contextual Output Encoding

- Use framework auto-escaping (React, Angular, Jinja2 autoescape, Razor)
- Danger APIs: `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `|safe`, `Html.Raw`, `document.write`, `eval`, `setTimeout(string)`
- Sanitize rich HTML with DOMPurify (client) / bleach-like allowlist sanitizers (server)
- Content Security Policy with nonces/hashes; `Trusted Types` for DOM sinks

---

## 4. SSRF

- Allowlist destination hosts/schemes; resolve DNS and validate the **resolved** IP against deny ranges (RFC1918, loopback, link-local `169.254.0.0/16`, IPv6 ULA/link-local, `fd00:ec2::254`)
- Re-validate after redirects (or disable redirects)
- Block metadata endpoints at network layer; enforce IMDSv2 (AWS), metadata header requirements (GCP/Azure)
- Use egress proxy for server-side fetches

---

## 5. Path Traversal & File Upload

```python
base = Path("/srv/uploads").resolve()
target = (base / user_filename).resolve()
if not target.is_relative_to(base): raise PermissionError
```

Uploads: generate server-side names; validate content type by magic bytes; store outside web root; no execution permissions; size limits; scan; serve with `Content-Disposition: attachment` and correct `Content-Type`.

---

## 6. Deserialization & Templates

| Risk | Fix |
|---|---|
| Java `ObjectInputStream` on untrusted data | Avoid; use JSON with explicit types; `ObjectInputFilter` allowlists |
| .NET `BinaryFormatter` | Removed/obsolete in modern .NET — migrate to `System.Text.Json` |
| Python `pickle`, `yaml.load` | `json`, `yaml.safe_load` |
| PHP `unserialize` | `json_decode`; `allowed_classes => false` |
| Jackson polymorphic typing | Disable default typing; allowlist subtypes |
| SSTI (Jinja2, Twig, Freemarker, Velocity) | Never render user-controlled templates; sandboxed environments; pass data as variables only |
| XXE | Disable DTDs/external entities in every XML parser |

---

## 7. Access Control

```text
[ ] Every handler enforces authN + authZ (deny by default)
[ ] Object ownership/tenant check on every ID from the request (BOLA/IDOR)
[ ] Function-level checks for admin routes (BFLA)
[ ] No mass assignment: explicit DTO/allowlisted fields (role, is_admin, tenant_id never bindable)
[ ] Server-side enforcement only (UI hiding ≠ authz)
[ ] Race-sensitive operations (balance, coupons, inventory) use transactions/locks/idempotency keys
```

---

## 8. Crypto & Secrets

- TLS 1.2+ (prefer 1.3); verify certificates (never `verify=False`)
- AEAD (AES-GCM, ChaCha20-Poly1305); no ECB; unique nonces
- CSPRNG (`secrets`, `SecureRandom`, `crypto.randomBytes`)
- Passwords: Argon2id/bcrypt
- Secrets from vault/env injection; never in code or repo; scan with gitleaks/trufflehog in CI

---

## 9. Errors & Logging

- Fail closed on exceptions in authz/validation paths (A10)
- Generic errors to clients; detailed logs server-side (no secrets/PII/tokens)
- Log security events: authn/authz failures, input validation failures, admin actions

---

## 10. Finding Write-up

```markdown
### <Title> — <OWASP 2025 ID> / CWE-<n> — Severity <CVSS 4.0 vector or rating>
Location: <file:line>
Source → Sink: <trace>
Impact: <what attacker gains>
Fix: <code diff using safe API>
Test: <unit/integration test proving fix>
Detection: <WAF/SIEM/log signal for exploitation attempts>
```

---

## Engagement Cheatsheet

```text
entry points → source→sink traces → authz on every object → injection/XSS/SSRF/path/deser
→ crypto/secrets → error handling → write-up with safe-API fix + test
```

---

## Key References

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- OWASP ASVS 5.0; OWASP Cheat Sheet Series
- CWE Top 25
- Related: `defensive-sast-dast`, `defensive-api-security`, `defensive-waf`
