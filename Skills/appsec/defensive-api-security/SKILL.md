---
name: defensive-api-security
description: "API security defense aligned to OWASP API Security Top 10 (2023): BOLA, broken authentication, BOPLA (excessive data exposure + mass assignment), unrestricted resource consumption, BFLA, unrestricted access to sensitive business flows, SSRF, misconfiguration, improper inventory management (shadow/zombie APIs), and unsafe consumption of third-party APIs. Covers schema validation (OpenAPI), gateway policies (rate limits, quotas, JWT validation, mTLS), GraphQL hardening (depth/complexity limits, introspection), gRPC and WebSocket security, API discovery, logging, and runtime detection. Use when designing, reviewing, or monitoring APIs."
---

# API Security

APIs expose business logic directly. The top risks are authorization failures, not injection. Every endpoint must answer: who is calling, are they allowed to touch *this* object, and how much can they do?

## Quick Workflow

1. Inventory all APIs (incl. versions, internal, partner, deprecated)
2. Enforce authN at gateway; authZ in service (object + function level)
3. Validate requests and responses against schema
4. Rate limit and quota by identity
5. Log with object IDs; detect enumeration and abuse
6. Test against OWASP API Top 10

---

## 1. OWASP API Security Top 10 (2023)

| ID | Risk | Defense |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | Per-object ownership/tenant check in data layer; non-guessable IDs are not authz |
| API2 | Broken Authentication | Standard OAuth/OIDC; strict JWT validation; no API keys as user auth; brute-force limits |
| API3 | Broken Object Property Level Authorization | Response DTOs (no full-object serialization); input allowlists (no mass assignment) |
| API4 | Unrestricted Resource Consumption | Rate limits, pagination caps, payload/size limits, timeouts, cost limits on SMS/email |
| API5 | Broken Function Level Authorization | Role checks per route; admin APIs separated; deny by default |
| API6 | Unrestricted Access to Sensitive Business Flows | Abuse controls on checkout, signup, reservations: bot detection, velocity, device signals |
| API7 | SSRF | URL allowlists; resolved-IP validation; egress proxy |
| API8 | Security Misconfiguration | CORS strictness, TLS, verbose errors off, unnecessary methods disabled |
| API9 | Improper Inventory Management | API catalog; retire old versions; spec-driven gateways; discovery from traffic |
| API10 | Unsafe Consumption of APIs | Validate third-party responses; timeouts; TLS verification; don't trust upstream redirects |

---

## 2. Authorization Patterns

```python
# BOLA-safe: scope query by caller
order = db.orders.find_one({"_id": order_id, "tenant_id": caller.tenant_id, "owner_id": caller.user_id})
if order is None: return 404   # not 403 — avoid existence oracle
```

- Centralize policy (OPA/Rego, Cedar, Casbin) for consistency
- Test with two users/tenants: every endpoint, every ID parameter, every method

---

## 3. Schema Validation

- OpenAPI 3.x spec as contract; validate at gateway or middleware (request AND response)
- `additionalProperties: false` on request bodies (blocks mass assignment)
- Explicit types, formats, min/max lengths, enums, array limits

```yaml
UpdateProfile:
  type: object
  additionalProperties: false
  properties:
    displayName: { type: string, maxLength: 64 }
    timezone:    { type: string, enum: [UTC, Asia/Manila, America/New_York] }
```

---

## 4. Gateway Controls

| Control | Example |
|---|---|
| JWT validation | Issuer, audience, alg allowlist, JWKS |
| mTLS | Service-to-service, partner APIs |
| Rate limit | Per token/user/IP: e.g., 100 req/min; login 5/min |
| Quota | Per client per day |
| Payload limits | Body ≤ 1 MB unless needed |
| Method allowlist | Only documented verbs per route |
| CORS | Explicit origins; no `*` with credentials |
| Spec enforcement | Reject undocumented paths/params |

Platforms: Kong, Apigee, AWS API Gateway, Azure API Management, Envoy, NGINX.

---

## 5. GraphQL

- Disable introspection in production (or restrict to authenticated developers)
- Depth limit (e.g., 10), complexity/cost analysis, query timeout
- Disable or limit batching and aliases used for brute force
- Field-level authorization in resolvers (BOLA applies per node)
- Persisted queries / allowlisted operations for public clients

---

## 6. gRPC & WebSocket

- gRPC: TLS/mTLS, per-method authz interceptors, message size limits, disable reflection in prod
- WebSocket: authenticate on upgrade; validate `Origin`; authorize each message type; rate limit messages; re-check auth on long sessions

---

## 7. Logging & Detection

Log per request: timestamp, client_id, user/tenant, route template, object IDs, status, latency, bytes, source IP/ASN, user agent.

| Abuse | Signal |
|---|---|
| BOLA enumeration | One identity accessing many distinct object IDs; high 404/403 ratio |
| Credential stuffing | Many usernames per IP; failure ratio > 90% |
| Scraping | High-volume paginated reads; sequential IDs |
| Shadow API use | Traffic to routes not in spec |
| Token misuse | Same token from multiple ASNs/countries |

```spl
index=api status IN (403,404)
| stats dc(object_id) as ids count by client_id src_ip route
| where ids > 200
```

---

## 8. Testing

- Automated: schema-based fuzzing (Schemathesis, RESTler), DAST with authenticated sessions (ZAP)
- Manual: two-account BOLA/BFLA matrix; mass assignment probes; rate-limit verification
- Contract tests in CI to prevent spec drift

---

## Engagement Cheatsheet

```text
inventory → gateway authN + rate limits → service authZ (object + function) → schema (additionalProperties:false)
→ GraphQL limits → logging with object IDs → detections (enumeration, stuffing, shadow routes) → test matrix
```

---

## Key References

- OWASP API Security Top 10 2023 — https://owasp.org/API-Security/
- OWASP REST / GraphQL Cheat Sheets
- Schemathesis; RESTler; OWASP crAPI (practice target)
- Related: `defensive-auth-implementation`, `defensive-secure-code-review`, `defensive-waf`
