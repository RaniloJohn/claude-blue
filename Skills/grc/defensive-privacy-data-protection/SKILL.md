---
name: defensive-privacy-data-protection
description: "Privacy and data protection engineering for security teams: personal data inventory and records of processing, lawful bases and purpose limitation, data minimization and retention, privacy by design and default, DPIAs/PIAs, data subject rights handling, cross-border transfers, processor contracts, pseudonymization vs anonymization, encryption and access controls for personal data, privacy in security monitoring (UEBA, DLP, insider programs, email review), breach assessment and notification linkage, and major regimes overview (GDPR, Philippines Data Privacy Act RA 10173, CCPA/CPRA, PDPA Singapore, others). Use when security work touches personal data or when building privacy controls."
---

# Privacy & Data Protection

Security protects data from attackers; privacy governs **whether and how the organization itself may use personal data**. Security tooling (logs, DLP, UEBA, email scanning) processes lots of personal data — it must itself be privacy-compliant.

## Quick Workflow

1. Inventory personal data (what, where, why, who, how long)
2. Establish lawful basis and purpose per processing activity
3. Minimize, set retention, protect (encryption, access control, pseudonymization)
4. Run DPIA for high-risk processing (monitoring, large-scale sensitive data, new tech/AI)
5. Prepare rights handling and breach response
6. Contract processors; manage transfers

---

## 1. Inventory & Records

| Field | Example |
|---|---|
| Processing activity | Security monitoring (SIEM, EDR) |
| Data categories | Usernames, IPs, device IDs, emails, web history, possibly sensitive content |
| Data subjects | Employees, contractors, customers (via app logs) |
| Purpose | Detect and respond to security incidents |
| Lawful basis | Legitimate interest / legal obligation (document balancing test) |
| Recipients | SOC, MDR provider (processor) |
| Transfers | MDR in another country → transfer mechanism |
| Retention | Hot 90 days, archive 1 year, then delete |
| Security measures | RBAC, encryption, audit logging of analyst access |

---

## 2. Principles in Practice

| Principle | Security-team practice |
|---|---|
| Purpose limitation | Security logs used for security, not performance management, unless policy/law allows and staff informed |
| Minimization | Don't collect full content when metadata suffices; mask sensitive fields in SIEM (e.g., hash or tokenize) |
| Storage limitation | Enforce retention in SIEM/data lake lifecycle policies |
| Integrity & confidentiality | Encrypt, restrict, log access to sensitive datasets (including security data) |
| Transparency | Monitoring notices in AUP/privacy notices |
| Accountability | DPIAs, records, training, DPO involvement |

---

## 3. DPIA Triggers & Content

Triggers: systematic monitoring of employees (UEBA, DLP, keystroke/screen recording — avoid unless justified), large-scale sensitive data, new technologies (AI analytics on user behavior), biometrics, combining datasets.

Content: description of processing, necessity and proportionality, risks to individuals, mitigations (minimization, access controls, retention, human review of automated decisions), residual risk, DPO opinion, sign-off.

---

## 4. Techniques

| Technique | Note |
|---|---|
| Pseudonymization | Replace identifiers with tokens; still personal data if re-identifiable |
| Anonymization | Irreversible; hard to achieve with rich logs |
| Field-level encryption / tokenization | Protect specific fields (national IDs, card numbers) |
| Role-based and just-in-time access to raw data | Analysts see masked data by default; unmask with justification |
| Data retention automation | ILM/lifecycle policies; deletion verification |
| Privacy-preserving analytics | Aggregates, differential privacy for reporting |

---

## 5. Regimes (overview — verify current law)

| Regime | Highlights |
|---|---|
| EU/UK GDPR | Lawful bases, DPIAs, DPO, 72 h breach notification to authority, rights (access, erasure, portability), transfer mechanisms (SCCs, adequacy) |
| Philippines Data Privacy Act (RA 10173) + NPC issuances | Personal information controllers/processors, DPO registration, security measures, breach notification to NPC and data subjects within 72 h of knowledge (NPC Circular 16-03) — see `defensive-privacy-data-protection` for current circulars |
| California CCPA/CPRA | Consumer rights, sensitive PI, contracts with service providers |
| Singapore PDPA | Mandatory breach notification (3 calendar days to PDPC after assessment) |
| Sector laws | HIPAA (health), GLBA (finance), PCI DSS (contractual for card data) |

---

## 6. Breach Linkage

Security incident involving personal data → assess likelihood of harm (type of data, volume, encryption, who has it) → notify authority/data subjects within legal deadlines → document even if not notifiable. See `defensive-incident-response`.

---

## Engagement Cheatsheet

```text
inventory + records of processing (incl. security tooling) → lawful basis + purpose → minimize/mask/retain/encrypt/RBAC → DPIA for monitoring/AI/sensitive
→ rights handling → processor contracts + transfers → breach assessment & notification (GDPR 72h, PH NPC 72h) → DPO involvement
```

---

## Key References

- GDPR (EU 2016/679) & EDPB guidelines; Philippines RA 10173 and NPC circulars; ISO/IEC 27701; NIST Privacy Framework 1.0 (and updates)
- Related: `defensive-policy-standards`, `defensive-incident-response`, `defensive-ueba`, `defensive-detect-exfiltration`
