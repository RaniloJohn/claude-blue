---
name: defensive-auth-implementation
description: "Secure authentication and authorization implementation review for applications and APIs: OAuth 2.0 / OAuth 2.1 and OpenID Connect (authorization code + PKCE, exact redirect URI matching, state/nonce, token audience/issuer validation, refresh token rotation, DPoP/mTLS sender-constrained tokens), JWT validation (algorithm pinning, alg:none and key confusion prevention, kid/jku/x5u handling, JWKS rotation, exp/nbf/iat), SAML signature validation and XML wrapping defenses, session management and cookies, passkeys/WebAuthn, password storage (Argon2id, bcrypt), MFA, and logging. Use when reviewing auth code, designing SSO, or remediating JWT/OAuth findings."
---

# Secure Auth Implementation

Most auth vulnerabilities are validation gaps: a token, redirect, or assertion is accepted without checking everything that should be checked. Use mature libraries, configure them strictly, and test negative cases.

## Quick Workflow

1. Identify flows (browser SSO, SPA, mobile, M2M, API)
2. Choose correct grant per flow
3. Verify token validation checklist
4. Verify session and cookie settings
5. Test negative cases (tampered tokens, wrong audience, redirect variants)
6. Log auth events with enough context for detection

---

## 1. Flow Selection

| Client | Flow |
|---|---|
| Server-side web app | Authorization Code (+ PKCE recommended) |
| SPA | Authorization Code + PKCE; tokens via BFF (backend-for-frontend) preferred over browser storage |
| Mobile/native | Authorization Code + PKCE, system browser (no embedded webviews) |
| Machine-to-machine | Client Credentials with private_key_jwt or mTLS |
| Devices without browser | Device Authorization Grant — restrict, since device-code phishing is common |
| Never | Implicit grant, Resource Owner Password Credentials (removed in OAuth 2.1) |

---

## 2. OAuth/OIDC Checklist

```text
[ ] Redirect URIs registered and matched EXACTLY (no wildcards, no open redirects on the allowed host)
[ ] PKCE S256 required for all public clients (and recommended for confidential)
[ ] `state` bound to user session (CSRF); `nonce` validated in ID token
[ ] ID token: iss, aud (= client_id), exp, iat, nonce, azp (if multiple audiences), signature
[ ] Access token audience validated by the resource server (no token passthrough)
[ ] Scopes enforced server-side per endpoint
[ ] Refresh tokens: rotation + reuse detection, or sender-constrained (DPoP/mTLS)
[ ] Client secrets not in SPA/mobile code
[ ] Consent screen shows real app identity; admin consent for high-risk scopes
[ ] Token revocation endpoint used on logout
```

---

## 3. JWT Validation

| Rule | Prevents |
|---|---|
| Pin accepted algorithms (e.g., `RS256`/`ES256` only); never trust header `alg` | `alg:none`, HS/RS key confusion |
| Separate verification keys per algorithm | Key confusion |
| Ignore `jku`/`x5u` unless allowlisted to your IdP; never fetch arbitrary URLs | Key injection |
| Sanitize `kid` (lookup in key set, not file path/SQL) | Path traversal/SQLi via kid |
| Validate `exp`, `nbf` with small clock skew; `iss`; `aud` | Replay, cross-service token use |
| Reject unsigned/unencrypted when signature expected | Downgrade |
| HMAC secrets ≥ 256-bit random; never default/example secrets | Offline cracking |
| JWKS caching with rotation (respect `kid`, refresh on unknown kid with rate limit) | Outages + key rollover issues |

```python
# PyJWT example — strict
import jwt
claims = jwt.decode(token, key=public_key, algorithms=["RS256"],
                    audience="api://orders", issuer="https://login.example.com/",
                    options={"require": ["exp", "iat", "iss", "aud"]})
```

```javascript
// jose (Node) — strict
const { payload } = await jwtVerify(token, JWKS, {
  algorithms: ['ES256'], issuer: 'https://idp.example.com/', audience: 'api://orders', clockTolerance: 30
});
```

---

## 4. SAML

- Validate signature over the **Assertion** (or Response) using the IdP's pinned certificate, not a certificate embedded in the message
- Use a library resistant to XML Signature Wrapping (XSW); verify the signed element is the one consumed
- Check `Audience`, `Recipient`, `NotOnOrAfter`, `InResponseTo`, `Destination`
- Disable DTD/external entities (XXE)
- Reject assertions reused (replay cache)

---

## 5. Sessions & Cookies

```http
Set-Cookie: __Host-session=<random 128+ bits>; Path=/; Secure; HttpOnly; SameSite=Lax
```

- Regenerate session ID on login and privilege change
- Idle + absolute timeouts; server-side invalidation on logout
- Bind sensitive actions to re-authentication (step-up)

---

## 6. Passwords & MFA

| Item | Standard |
|---|---|
| Storage | Argon2id (preferred), scrypt, bcrypt (cost ≥ 10–12), PBKDF2 (high iterations, FIPS contexts) |
| Policy | NIST SP 800-63B: length ≥ 8 (prefer ≥ 15 for single-factor), check against breached lists, no forced periodic rotation, no composition rules |
| MFA | Prefer passkeys/WebAuthn (phishing-resistant); TOTP acceptable; SMS last resort |
| Brute force | Rate limit per account + per IP; lockout with care (DoS); CAPTCHA after thresholds |
| Account recovery | As strong as primary auth; notify on changes |

---

## 7. Logging for Detection

Log (without secrets/tokens): auth success/failure with reason, MFA challenges and results, token issuance/refresh/revocation, consent grants, password/MFA changes, session creation/termination, IP, user agent, client_id. Feed to SIEM; alert on spray, MFA fatigue, refresh-token reuse, new device + sensitive action.

---

## 8. Negative Test Cases

| Test | Expected |
|---|---|
| JWT with `alg: none` | Rejected |
| RS256 token re-signed HS256 with public key | Rejected |
| Valid token for audience A sent to API B | Rejected |
| Expired token | Rejected |
| redirect_uri with extra path/param/subdomain | Rejected |
| Missing/mismatched `state` | Rejected |
| Refresh token reused after rotation | Rejected + family revoked |
| SAML with wrapped unsigned assertion | Rejected |

---

## Engagement Cheatsheet

```text
flows → grant per client → OAuth/OIDC checklist → JWT strict validation → SAML checks
→ cookie/session flags → password/MFA standards → auth logging → negative tests
```

---

## Key References

- OAuth 2.0 Security Best Current Practice (RFC 9700); OAuth 2.1 draft; RFC 7636 (PKCE); RFC 9449 (DPoP)
- RFC 8725 JWT Best Current Practices
- OWASP Cheat Sheets: Authentication, Session Management, JWT, SAML, Password Storage
- NIST SP 800-63B
- Related: `defensive-api-security`, `defensive-secure-code-review`, `defensive-entra-id`
