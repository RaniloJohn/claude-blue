---
name: defensive-incident-response
description: "Incident response lifecycle and incident command for SOC L2/IR leads, aligned to NIST SP 800-61r3 (2025) and CSF 2.0. Use when an incident is declared or suspected: scoping and blast-radius mapping, evidence preservation and chain of custody, containment strategy selection (and tipping-off risk), eradication, recovery, root cause analysis, dwell time, incident command roles, war-room cadence, stakeholder updates, and lessons learned. Covers host, identity, network, cloud, and email containment options with blast radius and reversibility."
---

# Incident Response

IR is decision-making under uncertainty. Scope before you swing: premature containment on partial scope tips off the adversary and leaves footholds behind.

## Quick Workflow

1. Declare, assign incident commander (IC), open war room + case
2. Preserve volatile evidence on known-affected systems
3. Scope: all affected hosts, identities, data, time range
4. Choose containment strategy; execute in a coordinated window
5. Eradicate every persistence mechanism and exposed credential
6. Recover with heightened monitoring
7. Root cause + lessons learned + detection gaps

---

## 1. Roles

| Role | Responsibility |
|---|---|
| Incident Commander | Decisions, priorities, cadence; not hands-on-keyboard |
| Lead Investigator | Technical analysis direction |
| Scribe | Timeline of actions and decisions (UTC) |
| Comms lead | Internal/external updates |
| Legal / Privacy | Privilege, notification obligations |
| Business owner | Approves business-impacting actions |
| Liaisons | IT ops, cloud, identity, vendors, IR retainer, law enforcement |

War-room cadence: SEV1 hourly sitreps; SEV2 every 4 h. Use out-of-band comms if email/chat may be compromised.

---

## 2. Scoping

Pivot on every confirmed indicator, repeatedly, until no new entities appear:

| Pivot | Question |
|---|---|
| Account | Where else did it log on? What tokens/sessions exist? |
| Host | What logged on to it, what did it connect to? |
| Hash / filename | Where else does it exist? |
| C2 domain/IP | Which hosts resolved/connected? |
| Persistence artifact | Same task/service/key elsewhere? |
| Tool / technique | Same cmdline pattern elsewhere? |
| Time | What else happened in the same window? |

Output: entity list (hosts, accounts, cloud principals, mailboxes, data stores), first/last malicious activity, privilege level reached, data accessed/staged/exfiltrated.

---

## 3. Evidence Preservation (before containment where safe)

Order of volatility (RFC 3227): memory → network state → running processes → disk → logs → backups.

```text
[ ] Memory image (EDR live response, WinPmem, avml)
[ ] EDR triage package / KAPE / Velociraptor collection
[ ] Relevant logs exported to case storage (SIEM, cloud audit, M365 UAL)
[ ] Cloud: snapshot volumes, preserve instance (do not terminate)
[ ] Hash every artifact (SHA-256); record collector, time, method
[ ] Chain-of-custody record per item
```

Exception: active encryption, destruction, or ongoing exfiltration → contain first, document why.

---

## 4. Containment Strategy

| Strategy | When | Risk |
|---|---|---|
| Immediate | Ransomware running, active exfil, destructive actor | Tips off adversary; may miss footholds |
| Coordinated (simultaneous) | Hands-on-keyboard actor with multiple footholds | Requires full scope; delay risk |
| Monitor (delayed) | Need intel on actor objectives; legal/LE direction | Ongoing damage risk; needs explicit approval |

### Containment Library

| Scope | Action | Blast radius | Reversible |
|---|---|---|---|
| Host | EDR network isolation | Host offline | Yes |
| Host | Kill process / quarantine file | Process | Partly |
| Fleet | Block hash/domain/IP in EDR/proxy/firewall | All hosts | Yes |
| AD account | Disable; reset password twice for privileged | User | Yes |
| AD Tier 0 | `krbtgt` reset twice (≥10 h apart, after replication) | Domain-wide ticket reissue | No |
| Entra | Revoke sessions (`Revoke-MgUserSignInSession`), disable, reset MFA methods | User | Yes |
| Entra app | Remove consent grant / disable SP / remove added creds | App integrations | Yes |
| M365 | Remove inbox rules, block external forwarding, purge messages | Mailboxes | Mostly |
| AWS | Deactivate keys; attach `AWSDenyAll`; revoke role sessions; isolation SG | Principal / instance | Yes |
| GCP | Disable SA keys; remove IAM bindings | Workloads | Yes |
| K8s | Deny-all NetworkPolicy on pod labels; cordon node | Pod/node | Yes |
| Network | Segment/VLAN quarantine; DNS sinkhole | Segment | Yes |

Tipping-off check: does the adversary have other footholds we haven't found? If yes and not urgent → coordinate.

---

## 5. Eradication

```text
[ ] All persistence removed (every mechanism found, across all hosts)
[ ] All exposed credentials rotated: users, service accounts, API keys, secrets, certificates
[ ] Kerberos: krbtgt double reset if domain compromise suspected
[ ] Cloud: remove attacker-created principals, keys, roles, policies, OAuth apps, federation changes
[ ] Initial access vector closed (patch, config, MFA)
[ ] Rebuild hosts where integrity is uncertain (prefer rebuild over clean for servers with admin compromise)
[ ] Targeted hunt confirms no residual activity
```

---

## 6. Recovery

- Restore from known-good backups (verify backup predates compromise; scan restored data)
- Staged return to production; heightened monitoring ≥14–30 days
- Watchlist entities: affected accounts, hosts, C2 infrastructure
- Validate business functions with owners

---

## 7. Root Cause & Metrics

| Item | Example |
|---|---|
| Initial access | Phishing → credential harvest → VPN without MFA |
| Exploited weakness | Missing MFA on VPN; local admin reuse |
| Failed/absent control | No alert on impossible travel; EDR not on server |
| Detection gap | No rule for `ntdsutil ifm` |
| Dwell time | First malicious event → eradication |
| MTTD / MTTC / MTTR | Per `defensive-soc-playbooks` |

5 Whys on each failed control; output owners and deadlines.

---

## 8. Sitrep Template

```text
INCIDENT <id> — SEV<x> — <title> — Sitrep #<n> — <UTC time>
Status: Investigating | Contained | Eradicated | Recovering | Closed
What we know: <facts, with confidence>
What we don't know: <open questions>
Scope: hosts <n>, accounts <n>, data <classification>
Actions since last update: <list>
Next actions (owner, ETA): <list>
Decisions needed: <from whom, by when>
```

---

## Engagement Cheatsheet

```text
Declare → roles → preserve → scope (iterate pivots) → strategy → coordinated contain
→ eradicate (persistence + creds + vector) → recover + monitor → RCA → lessons → detections
```

---

## Key References

- NIST SP 800-61r3 (April 2025); NIST CSF 2.0
- RFC 3227 — Guidelines for Evidence Collection and Archiving
- CISA Federal IR Playbooks
- Microsoft: AD Forest Recovery; krbtgt reset guidance
- Related: `defensive-live-response`, `defensive-ir-reporting`, `defensive-cloud-ir`, `defensive-ransomware-response`
