---
name: defensive-security-fundamentals
description: "Core security concepts every defender reasons from: CIA triad and Parkerian hexad, AAA (authentication, authorization, accounting), non-repudiation, least privilege, need to know, separation of duties, Saltzer and Schroeder design principles, attack surface, threat/vulnerability/risk/exploit definitions, control categories (technical, managerial, operational, physical) and types (preventive, detective, corrective, deterrent, compensating, directive, recovery), defense vs detection trade-offs, trust boundaries, security by design and by default, assume breach, fail-safe vs fail-open, cryptography basics (symmetric, asymmetric, hashing, MAC, signatures, key exchange), and the Security+/CISSP mental model. Use to explain fundamentals, classify controls, or reason about a design from first principles."
---

# Security Fundamentals

The vocabulary and first principles underneath every other skill. Use these to classify controls, explain why something is a risk, and argue for a design choice without hand-waving.

## Quick Workflow

1. Name the asset and which property matters (C, I, A, authenticity, …)
2. Name the threat, the vulnerability, and the resulting risk
3. Pick controls by category and type; aim for prevent + detect + recover
4. Check the design against the principles in §4

---

## 1. Security Properties

| Property | Meaning | Typical controls |
|---|---|---|
| Confidentiality | Only authorized parties read data | Encryption, access control, DLP |
| Integrity | Data/systems not altered without authorization | Hashing, signatures, FIM, change control |
| Availability | Usable when needed | Redundancy, backups, DDoS protection, capacity |
| Authenticity | Origin is who it claims | Signatures, mutual TLS, DKIM |
| Non-repudiation | Actor cannot deny the action | Digital signatures + trustworthy logs |
| Possession / control | Parkerian: custody of the data (stolen encrypted laptop = loss of control) | Asset tracking, encryption |
| Utility | Parkerian: data still usable (lost key = useless data) | Key management, format longevity |

**AAA:** Authentication (who are you) → Authorization (what may you do) → Accounting (what did you do — logs). Identification precedes authentication.

---

## 2. Risk Vocabulary

| Term | Definition | Example |
|---|---|---|
| Asset | Something of value | Customer DB |
| Threat | Potential cause of harm | Ransomware crew |
| Threat actor | Who | Financially motivated eCrime |
| Vulnerability | Weakness | Unpatched VPN appliance |
| Exploit | Means of using a vulnerability | Public PoC |
| Risk | Likelihood × impact of threat exploiting vulnerability | High: KEV-listed, internet-facing |
| Attack surface | Sum of reachable entry points | Exposed services, users, APIs, supply chain |
| Attack vector | Path used | Phishing, exposed RDP |
| Control / countermeasure | Measure reducing risk | Patch, MFA, segmentation |
| Residual risk | Risk after controls | Accepted, documented |

Risk responses: **mitigate, transfer (insurance/contract), avoid (stop the activity), accept** (documented, owner-signed, time-bound).

---

## 3. Control Classification

| Category | Examples |
|---|---|
| Technical (logical) | Firewalls, EDR, MFA, encryption |
| Managerial (administrative) | Policies, risk assessments, security awareness program |
| Operational | Guards, change management, log review — performed by people |
| Physical | Locks, badges, CCTV, mantraps |

| Type | Purpose | Example |
|---|---|---|
| Preventive | Stop it | MFA, application allowlisting |
| Detective | Notice it | SIEM rule, IDS, audit |
| Corrective | Fix after event | Patch, reimage, restore |
| Deterrent | Discourage | Warning banners, visible cameras |
| Compensating | Alternative when primary isn't possible | Segmentation for unpatchable OT |
| Directive | Instruct behavior | Acceptable use policy |
| Recovery | Restore operations | Backups, DR site |

A mature design covers every asset with at least **preventive + detective + recovery**.

---

## 4. Design Principles (Saltzer & Schroeder 1975 + modern)

| Principle | Practical meaning |
|---|---|
| Economy of mechanism | Simple designs have fewer bugs; minimize custom security code |
| Fail-safe defaults | Default deny; access granted explicitly |
| Complete mediation | Check every access, not just the first (no stale authorization caches) |
| Open design | Security must not rely on secrecy of the design (Kerckhoffs) |
| Separation of privilege | Require two conditions (MFA, two-person rule) |
| Least privilege | Minimum rights for minimum time (JIT/JEA) |
| Least common mechanism | Minimize shared components between users/tenants |
| Psychological acceptability | Security people can actually use (or they bypass it) |
| Defense in depth | Independent layers; no single point of failure |
| Assume breach | Design detection and containment for when prevention fails |
| Secure by design / default | Safe out of the box (CISA Secure by Design pledge) |
| Zero trust | Never trust network location; verify explicitly each request |
| Separation of duties | No single person can complete a sensitive process alone |
| Need to know | Access limited to what the task requires, even within clearance |

**Fail-safe vs fail-open:** security controls (auth, firewalls) should fail closed; safety systems (fire doors, OT safety) may fail open — document which and why.

---

## 5. Cryptography Essentials

| Primitive | Use | Current guidance |
|---|---|---|
| Symmetric encryption | Bulk data | AES-256-GCM, ChaCha20-Poly1305 |
| Asymmetric encryption / key exchange | Key establishment | ECDHE (X25519, P-256/384); hybrid X25519MLKEM768 for PQ |
| Hash | Integrity, fingerprints | SHA-256/384/512, SHA-3; never MD5/SHA-1 for security |
| MAC | Integrity + authenticity with shared key | HMAC-SHA-256 |
| Digital signature | Authenticity, non-repudiation | Ed25519, ECDSA P-256, RSA-PSS ≥ 3072; ML-DSA (FIPS 204) for PQ |
| Password storage | Slow, salted hashing | Argon2id, scrypt, bcrypt, PBKDF2 (high iterations) |
| KDF | Derive keys | HKDF |

Encoding (Base64) ≠ encryption. Hashing ≠ encryption. Encryption without integrity (CBC without MAC) invites padding-oracle attacks.

---

## 6. Common Exam/Interview Distinctions

| Pair | Difference |
|---|---|
| Vulnerability scan vs pentest | Find known weaknesses vs prove exploitability |
| IDS vs IPS | Detect/alert vs inline block |
| Authentication vs authorization | Identity proof vs permission decision |
| Hashing vs encryption | One-way vs reversible with key |
| Event vs incident | Observable occurrence vs violation/threat to security policy |
| RPO vs RTO | Acceptable data loss vs acceptable downtime |
| False positive vs false negative | Alert without threat vs threat without alert |
| Threat hunting vs detection | Hypothesis-driven search vs automated alerting |

---

## Engagement Cheatsheet

```text
asset → property (CIA/authenticity/…) → threat + vuln → risk (L×I) → response (mitigate/transfer/avoid/accept)
→ controls: category (tech/managerial/operational/physical) × type (prevent/detect/correct/recover/…) → check S&S principles → assume breach
```

---

## Key References

- Saltzer & Schroeder, "The Protection of Information in Computer Systems" (1975)
- CompTIA Security+ SY0-701 objectives; (ISC)² CISSP CBK; NIST SP 800-12 Rev 1
- Related: `defensive-defense-in-depth`, `defensive-zero-trust-architecture`, `defensive-risk-threat-modeling`, `defensive-tls-pki`
