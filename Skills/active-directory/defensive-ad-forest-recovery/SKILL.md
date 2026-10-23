---
name: defensive-ad-forest-recovery
description: "Active Directory forest recovery after ransomware or full domain compromise: deciding between cleanup and recovery, Microsoft AD Forest Recovery Guide sequence, backup requirements (system state, tombstone lifetime, offline/immutable copies, known-good backup selection), isolated recovery environment, restoring the first DC per domain with authoritative SYSVOL, seizing FSMO roles, metadata cleanup of other DCs, raising RID pool and invalidating current pool, double krbtgt reset, resetting trust, DSRM, computer, and Tier 0 passwords, DNS/GC considerations, reconnecting and redeploying DCs, post-recovery hardening, and rehearsal. Use when planning, rehearsing, or executing an AD forest recovery."
---

# AD Forest Recovery

When attackers own Domain Admin (or ransomware hits every DC), the forest may not be trustworthy. Recovery restores **one clean DC per domain from a known-good backup** in isolation, eliminates attacker persistence in AD, then rebuilds outward. Plan and rehearse it before you need it.

## Quick Workflow

1. Decide: targeted cleanup vs full forest recovery (§1)
2. Build isolated recovery environment (no connection to compromised network)
3. Select known-good backups (pre-compromise, within tombstone lifetime)
4. Restore first DC per domain (forest root first) → authoritative SYSVOL
5. Clean metadata, seize FSMO, raise/invalidate RID pool, reset secrets (§4)
6. Verify, harden, reconnect in controlled stages; redeploy additional DCs fresh

---

## 1. Cleanup vs Recovery

| Indicator | Lean toward |
|---|---|
| Limited, well-scoped compromise; no DC persistence evidence | Targeted cleanup (reset creds, remove persistence) |
| DCs encrypted/destroyed | Forest recovery |
| Attacker had DA for long dwell, unknown persistence (AdminSDHolder, SID history, shadow creds, GPO, DSRM, Skeleton key, DC implants) | Forest recovery (or clean rebuild + migration) |
| No trustworthy backup | Rebuild new forest and migrate (ADMT/third-party) |

---

## 2. Prerequisites (do now)

| Item | Detail |
|---|---|
| Backups | System state (or bare-metal) of ≥ 2 DCs per domain, daily; offline/immutable copy; retention beyond typical dwell time but **within tombstone lifetime** (default 180 days) for restore usability |
| Backup isolation | Backup system not domain-joined to the production domain; separate credentials + MFA (`defensive-cyber-resilience`) |
| Documentation | Forest/domain list, DC inventory, FSMO holders, sites, trusts, DNS zones, AD CS dependencies |
| Media | Clean OS ISOs, hypervisor for isolated network, offline admin workstation |
| Credentials | Offline-stored DSRM passwords and break-glass accounts (vault + sealed envelope) |
| Tooling | Microsoft forest recovery guide; optional commercial (Semperis ADFR, Quest Recovery Manager, Cohesity/Rubrik AD recovery) |
| Rehearsal | Annual timed recovery in isolated lab |

---

## 3. Recovery Sequence (Microsoft guide, condensed)

1. **Isolate**: recovery network with no route to compromised environment
2. **Restore first writable DC** of the forest root domain from known-good backup (non-authoritative restore of AD; **authoritative restore of SYSVOL** — e.g., DFSR authoritative flag `msDFSR-Options=1` on the restored DC)
3. Verify AD/SYSVOL/DNS working on that DC (`dcdiag`, `repadmin /showrepl`, SYSVOL shared)
4. **Remove all other DCs** of the domain from metadata (`ntdsutil metadata cleanup` / ADUC delete DC object)
5. **Seize FSMO roles** to the restored DC as needed (`ntdsutil roles` / `Move-ADDirectoryServerOperationMasterRole -Force`)
6. **Raise RID pool** by 100,000 (`rIDAvailablePool`) and **invalidate current RID pool** to prevent duplicate SIDs
7. **Reset secrets**: krbtgt **twice** (with replication/wait between in normal ops; in single-DC recovery reset twice), restored DC computer account, trust passwords (both sides), DSRM password, all Tier 0 accounts and service accounts
8. Configure as Global Catalog if needed; clean DNS records of removed DCs
9. Repeat for each child domain (restore one DC each), reestablish trusts
10. **Harden** before reconnect (§5); scan restored DC with current EDR
11. Reconnect in stages; promote **new** DCs (don't restore more backups); decommission/rebuild member servers and workstations per IR scope

```powershell
# Examples (run on restored DC in isolation)
repadmin /showrepl ; dcdiag /v
Get-ADDomainController -Filter * | Select Name, Site
# krbtgt reset (use Microsoft's New-KrbtgtKeys.ps1 for controlled resets in normal ops)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (Read-Host -AsSecureString)
```

---

## 4. Persistence to Eliminate

| Persistence | Check/clean |
|---|---|
| Golden/diamond tickets | Double krbtgt reset |
| AdminSDHolder ACL edits | Compare ACL to default; reset |
| SID History on accounts | Remove unexpected `sIDHistory` |
| Shadow credentials | Review `msDS-KeyCredentialLink` on privileged/computer objects |
| Malicious GPOs / scheduled tasks via GPO | Diff GPOs vs baseline |
| DSRM logon enabled (`DsrmAdminLogonBehavior=2`) | Reset to 0; new DSRM password |
| Rogue certificates / AD CS persistence | Revoke; review templates; rotate CA if CA compromised (`defensive-ad-hardening`) |
| Delegation abuse (RBCD, unconstrained) | Review delegation attributes |
| Privileged group nesting | Rebuild Tier 0 membership from documented list |
| Entra Connect / sync server | Rebuild; rotate sync accounts |

---

## 5. Post-Recovery Hardening

Tiered admin + PAWs, Protected Users for admins, LAPS everywhere, disable NTLM where possible, LDAP signing/channel binding, RC4 removal (enforced since 2026), Credential Guard, MDI sensors on new DCs, monitoring for re-entry (`defensive-ad-detection`), backups validated again.

---

## Engagement Cheatsheet

```text
cleanup vs recovery decision → isolated network → known-good system-state backup (< tombstone, pre-compromise) → restore 1 DC/domain (root first, authoritative SYSVOL)
→ metadata cleanup + seize FSMO → RID pool +100k + invalidate → krbtgt ×2, trusts, DSRM, DC computer, Tier 0 resets → hunt persistence list → harden → staged reconnect + fresh DCs
```

---

## Key References

- Microsoft "Active Directory Forest Recovery Guide" (learn.microsoft.com); Microsoft New-KrbtgtKeys.ps1
- Related: `defensive-ransomware-response`, `defensive-ad-hardening`, `defensive-cyber-resilience`
