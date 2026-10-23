---
name: defensive-tls-pki
description: "TLS configuration and public/internal PKI operations: TLS 1.2/1.3 only, cipher suites and key exchange (ECDHE, hybrid X25519MLKEM768), HSTS and preload, OCSP stapling vs CRLs after Let's Encrypt ended OCSP, certificate lifetime reductions (CA/B Forum SC-081: 200 days March 2026, 100 days March 2027, 47 days March 2029), ACME automation (certbot, acme.sh, cert-manager), certificate inventory and expiry monitoring, Certificate Transparency monitoring for rogue issuance, CAA records, clientAuth EKU removal from public certs and mTLS on private PKI, internal CA design (offline root, HSM), key management, testing with testssl.sh/sslyze, and nginx/Apache/IIS hardening snippets. Use when configuring TLS, auditing certificates, or planning PKI and certificate automation."
---

# TLS & PKI

Shrinking certificate lifetimes make **automation mandatory**; certificate transparency makes rogue issuance **detectable**; TLS 1.3 makes good crypto the default if you let it.

## Quick Workflow

1. Inventory every certificate (public + internal): owner, expiry, issuer, key type, where deployed
2. Automate issuance and renewal (ACME) — target lifetimes well under the CA/B maximum
3. Configure TLS 1.2+ (prefer 1.3), modern suites, HSTS
4. Monitor CT logs for your domains; set CAA records
5. Run internal PKI with offline root, HSM, and documented issuance policy (`defensive-ad-hardening` for AD CS)

---

## 1. Certificate Lifetime Timeline (CA/B Forum SC-081)

| From | Max public TLS validity | Domain validation reuse |
|---|---|---|
| Mar 15, 2026 | 200 days | 200 days |
| Mar 15, 2027 | 100 days | 100 days |
| Mar 15, 2029 | 47 days | 10 days |

Implication: manual renewal processes will fail. Every public certificate needs ACME (or vendor API) automation and expiry monitoring.

Other changes:
- **OCSP:** CA/B made OCSP optional (CRLs required); Let's Encrypt shut down OCSP in 2025 — rely on CRLs/short lifetimes; OCSP stapling configs pointing to missing responders should be removed
- **clientAuth EKU:** public TLS certificates are dropping the client authentication EKU (Chrome Root Program dedicated-hierarchy requirement, 2026) — mTLS and server-to-server client certs must come from private PKI
- **Distrust events:** Chrome/Mozilla have distrusted CAs (e.g., Entrust for new certs after Nov 2024; Chunghwa Telecom and Netlock in 2025) — track root program announcements

---

## 2. TLS Configuration

| Setting | Recommendation |
|---|---|
| Protocols | TLS 1.3 + TLS 1.2; disable SSLv3, TLS 1.0, 1.1 |
| TLS 1.2 suites | ECDHE with AES-GCM or ChaCha20-Poly1305 only |
| Key exchange | X25519, P-256; enable hybrid X25519MLKEM768 where supported (browsers/OpenSSL 3.5+) |
| Certificates | ECDSA P-256 (or RSA 2048+/3072); full chain served |
| HSTS | `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` after confirming all subdomains are HTTPS |
| Compression | Off (CRIME) |
| Renegotiation | Secure only / disabled |
| 0-RTT | Disable unless replay-safe |

### nginx

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### Apache

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLHonorCipherOrder off
SSLSessionTickets off
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
```

### Windows / IIS

Use IIS Crypto or GPO/registry under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols` to disable TLS 1.0/1.1; set cipher suite order via GPO (SSL Configuration Settings). Windows Server 2022+ supports TLS 1.3.

Mozilla SSL Configuration Generator provides current templates (modern/intermediate).

---

## 3. Automation

```bash
certbot certonly --nginx -d www.example.com --key-type ecdsa --deploy-hook "systemctl reload nginx"
acme.sh --issue --dns dns_cf -d example.com -d '*.example.com' --keylength ec-256
```

Kubernetes: cert-manager with ACME Issuer (DNS-01 for wildcards), monitor `Certificate` readiness. ACME Renewal Information (ARI) lets CAs signal early renewal — enable in clients that support it.

---

## 4. Monitoring

| What | How |
|---|---|
| Expiry | Inventory + alerts at 30/14/7 days (Prometheus blackbox/ssl exporter, cert-manager metrics, CLM tools) |
| CT logs | crt.sh, Cert Spotter, Facebook CT monitor, Censys — alert on certs for your domains from unexpected CAs or for unknown subdomains |
| CAA | `example.com. CAA 0 issue "letsencrypt.org"`, `CAA 0 iodef "mailto:security@example.com"` |
| Weak configs | Periodic external scans (testssl.sh, sslyze, EASM) |

```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[] | [.not_before, .issuer_name, .name_value] | @tsv' | sort -u | tail -50
testssl.sh --severity MEDIUM https://www.example.com
sslyze www.example.com --mozilla_config=intermediate
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer -subject
```

---

## 5. Internal PKI

| Element | Guidance |
|---|---|
| Hierarchy | Offline root (powered off, HSM or air-gapped), online issuing CAs per purpose |
| Keys | HSM-protected CA keys; documented ceremonies |
| Policy | Certificate Policy/CPS: who can request what, validation, lifetimes |
| Templates | Least privilege enrollment rights; no "supply in request" subject for broad groups (ESC1) |
| Revocation | CRL distribution points reachable; short CRL validity on issuing CAs |
| Lifetimes | Short-lived certs for workloads (SPIFFE/SPIRE, Vault PKI, step-ca) |
| Monitoring | Issuance logs to SIEM; alert on certs for privileged identities |

---

## 6. Common Findings

Expired/expiring certificates, self-signed certs on internal admin portals (train users to click through warnings → MITM risk), TLS 1.0/1.1 still enabled, wildcard private keys copied to many servers, private keys in code repos, missing intermediate chain, HSTS absent, CT showing unknown subdomains (shadow IT).

---

## Engagement Cheatsheet

```text
inventory all certs → ACME/API automation (SC-081: 200d→100d→47d) → TLS1.2/1.3, ECDHE+AEAD, hybrid MLKEM, HSTS
→ drop OCSP stapling to dead responders; private PKI for mTLS (no clientAuth in public certs) → CT + CAA + expiry monitoring
→ internal PKI: offline root, HSM, tight templates → testssl/sslyze scans
```

---

## Key References

- CA/Browser Forum Baseline Requirements & ballot SC-081; Chrome Root Program Policy; Mozilla Root Store Policy
- Mozilla SSL Configuration Generator; NIST SP 800-52 Rev 2 (TLS guidelines); RFC 8446 (TLS 1.3); RFC 8555 (ACME)
- Related: `defensive-ad-hardening`, `defensive-waf`, `defensive-proxy-tls-inspection`
