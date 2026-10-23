---
name: defensive-alert-triage
description: "SOC L1/L2 alert triage methodology. Use when an analyst pastes an alert, raw log, EDR/SIEM detection, phishing report, or asks 'is this malicious', 'true positive or false positive', 'should I escalate'. Covers entity extraction, IOC vs IOA, enrichment order (asset, identity, prevalence, reputation, process tree), TP/BTP/FP/Undetermined verdicts, confidence levels, severity assignment, escalation criteria, ticket notes, alert fatigue and suppression hygiene, SLA mapping, and handoff to incident response. Applies to Splunk, Sentinel/Defender XDR, Elastic, Wazuh, QRadar, CrowdStrike, SentinelOne, Security Onion alerts."
---

# Alert Triage (L1/L2)

Triage converts an alert into a defensible decision in minutes: close, tune, or escalate. Speed comes from a fixed sequence, not intuition. Every closed alert must survive review by another analyst.

## Quick Workflow

1. Read the rule logic — know *why* it fired before judging *what* fired
2. Extract entities
3. Enrich (internal → external)
4. Reconstruct the 3-level process tree / auth chain
5. Check prevalence and related alerts (±24 h, same entities)
6. Assign verdict + confidence
7. Assign severity, escalate or close with notes
8. File tuning ticket if FP/BTP recurs

---

## 1. Understand the Rule

| Question | Why |
|---|---|
| What behavior is the rule designed to catch? | Defines what "true positive" means |
| Which field(s) matched? | Separates the trigger from the noise |
| Is it signature, behavioral, anomaly, or correlation? | Anomaly/UEBA alerts need baselines, not reputation |
| Known FP list in rule metadata? | Fast close path |
| ATT&CK mapping? | Frames next pivots |

If rule logic is unavailable, say so in notes — verdict confidence drops one level.

---

## 2. Entity Extraction

| Entity | Fields to capture |
|---|---|
| Host | hostname, IP, OS, asset tag, criticality tier, owner, EDR status |
| User | UPN/SAM, SID, department, privilege tier, MFA state, last password change |
| Process | image path, `OriginalFileName`, PID, GUID, parent, command line, hash (SHA-256), signer, integrity level |
| Network | src/dst IP:port, protocol, domain, SNI, JA4, bytes in/out, ASN, geo |
| File | path, hash, size, creation time, Zone.Identifier (`HostUrl`) |
| Cloud | principal ARN/UPN/SA, source IP, user agent, region, API call, resource |
| Email | sender, envelope-from, Reply-To, Return-Path, SPF/DKIM/DMARC results, URLs, attachments |

**IOC** = static artifact (hash, IP, domain). **IOA** = behavior (Office spawning PowerShell, LSASS read). IOAs survive attacker infrastructure rotation; weight them higher.

---

## 3. Enrichment Order

1. **Asset context** — criticality (Tier 0: DC, ADCS, ADFS, Entra Connect, backup, hypervisor), internet exposure, owner, maintenance window
2. **Identity context** — role, privileges, recent auth anomalies, travel, HR status (leaver/joiner)
3. **Prevalence** — how many hosts/users had this hash / cmdline / domain in 30 days. 1 host = rare, investigate; 5,000 hosts = software rollout
4. **Process tree** — 3 levels up, all children, sibling processes in same window
5. **Change context** — CAB tickets, deployments, admin activity
6. **Reputation** — VirusTotal, AbuseIPDB, GreyNoise (benign scanner vs targeted), URLhaus, ThreatFox, MISP/OpenCTI, internal blocklists
7. **Related alerts** — same host/user/hash/IP ±24 h

External lookups: hashes and domains only. Never upload internal files to public sandboxes without data-classification approval.

---

## 4. Verdicts

| Verdict | Definition | Action |
|---|---|---|
| True Positive (TP) | Malicious or unauthorized activity confirmed | Escalate / respond |
| Benign True Positive (BTP) | Rule worked; activity authorized (pentest, admin, scanner) | Close; document authorization evidence; consider allowlist |
| False Positive (FP) | Rule matched behavior it was not meant to catch | Close; tuning ticket with sample |
| Undetermined | Evidence insufficient | Escalate with explicit data gaps |

### Confidence

| Level | Standard |
|---|---|
| High | ≥2 independent sources corroborate |
| Medium | One strong source, no contradiction |
| Low | Plausible, unverified |

Never close a Low-confidence BTP. "User said it was them" is one source.

---

## 5. Severity

| Sev | Criteria | Ack SLA (default) |
|---|---|---|
| SEV1 | Tier 0 compromise, ransomware execution, confirmed regulated-data exfil | 15 min |
| SEV2 | Confirmed host/account compromise, lateral movement, active C2 | 30 min |
| SEV3 | Contained single-host malicious activity; suspicious unconfirmed | 4 h |
| SEV4 | Policy violation, recon, commodity blocked | 24 h |

Raise one level if: Tier 0 asset, privileged identity, internet-facing, regulated data in scope.

---

## 6. Escalate to L2/IR When Any

- Credential access: LSASS read, SAM/NTDS access, DCSync, Kerberoasting, browser credential theft
- Execution on Tier 0
- Lateral movement or new persistence
- C2 indicators: beaconing, rare domain + new process, known C2 named pipes
- Security tool tampering: EDR stopped, Sysmon config change (EID 16), log cleared (1102/104), Defender exclusions (5007), CloudTrail `StopLogging`
- Same IOC on ≥2 hosts
- Cloud: new admin role assignment, new access key on root/admin, OAuth consent to unknown app, inbox forwarding rule
- Data movement: large egress, archive creation + upload, cloud storage made public

---

## 7. Common Alert Classes — Fast Pivots

| Alert | First three pivots |
|---|---|
| Encoded PowerShell | Decode (`-enc` = Base64 UTF-16LE); parent process; network connections from same PID |
| Office spawning shell | Document source (email/URL), Zone.Identifier, child network activity |
| LSASS access | `SourceImage` signer + path, `GrantedAccess`, `CallTrace` (`UNKNOWN(` = unbacked memory) |
| Impossible travel | VPN/proxy egress, device ID consistency, token vs interactive sign-in |
| Brute force | Success after failures? Spray (many users, few attempts) vs brute (one user) |
| Malware detected & blocked | Was it the only copy? Origin vector? Execution before block? |
| Beaconing | Interval/jitter, process owning the socket, domain age, cert |
| New service installed | Binary path, service account, `ImagePath` with `cmd /c` or `%COMSPEC%` |

---

## 8. Closing Notes Standard

```text
Verdict: <TP|BTP|FP|Undetermined>  Confidence: <H|M|L>  Severity: <SEV>
Rule: <name/id> — fired on <field=value>
Summary: <one sentence: who did what on which asset when (UTC)>
Evidence: <bullet list of observed facts with source>
Enrichment: <prevalence, reputation, asset/user context>
Decision rationale: <why this verdict>
Actions: <taken / recommended>
Tuning: <ticket id or N/A>
```

---

## 9. Alert Fatigue Hygiene

- Suppress by **combination** (signer + path + parent + user), never single process name
- Every suppression has an owner, reason, and expiry date
- Track per rule: alerts/day, TP rate, median triage time. Rules <5% TP for 30 days → rework or demote to risk-based scoring
- Prefer risk-based alerting (RBA): weak signals add risk to entity; alert at threshold

---

## Engagement Cheatsheet

```text
1 rule logic → 2 entities → 3 asset/user → 4 prevalence → 5 tree → 6 related alerts
→ 7 reputation → 8 verdict+confidence → 9 severity → 10 notes → 11 escalate/close/tune
```

---

## Key References

- NIST SP 800-61r3 (2025) Incident Response Recommendations
- MITRE ATT&CK v18 Detection Strategies — https://attack.mitre.org
- Pyramid of Pain (David Bianco)
- Splunk Risk-Based Alerting documentation
- Related: `defensive-incident-response`, `defensive-soc-playbooks`, `defensive-quick-checks`
