---
name: defensive-d3fend-countermeasures
description: "MITRE D3FEND countermeasure knowledge graph: tactics (Model, Harden, Detect, Isolate, Deceive, Evict, Restore), techniques and digital artifacts, mapping ATT&CK offensive techniques to D3FEND defensive techniques through shared artifacts, using D3FEND to justify controls, compare vendor capabilities, build countermeasure plans for an incident or threat profile, and D3FEND CAD (countermeasure architecture diagrams). Includes worked mappings for credential dumping, phishing execution, lateral movement, C2, and ransomware. Use when selecting countermeasures for specific techniques or explaining coverage in D3FEND terms."
---

# MITRE D3FEND Countermeasures

ATT&CK describes what attackers do; D3FEND describes what defenders can do about it. They connect through **digital artifacts** — the things both sides touch (process, file, network traffic, credential, registry key).

## Quick Workflow

1. Start from the ATT&CK technique(s) observed or prioritized
2. Identify the digital artifacts the technique produces or uses
3. Look up D3FEND techniques that act on those artifacts, grouped by tactic
4. Select countermeasures you can implement; map to products/configurations
5. Record the plan in Navigator-style or CAD diagrams

---

## 1. Tactics (D3FEND 1.x)

| Tactic | Intent | Example techniques |
|---|---|---|
| Model | Understand the environment | Asset inventory, network mapping, operational activity mapping, system dependency mapping |
| Harden | Make exploitation harder | Application hardening, credential hardening (MFA, rotation), message hardening, platform hardening (secure boot, disk encryption), source code hardening |
| Detect | Identify adversary activity | File analysis, identifier analysis (URL/domain reputation), message analysis, network traffic analysis, platform monitoring, process analysis, user behavior analysis |
| Isolate | Create barriers | Execution isolation (sandbox, app allowlisting), network isolation (filtering, segmentation, DNS denylisting) |
| Deceive | Mislead | Decoy environment, decoy object (honey files, credentials) |
| Evict | Remove adversary | Credential eviction (revocation, account locking), file eviction (quarantine), process eviction (termination) |
| Restore | Return to known-good | Restore access, restore object (backup restore), restore configuration |

---

## 2. Worked Mappings

### T1003.001 LSASS Memory

| D3FEND tactic | Countermeasure | Implementation |
|---|---|---|
| Harden | Credential hardening; process (LSA) protection | Credential Guard, RunAsPPL, disable WDigest |
| Detect | Process access analysis / system call analysis | Sysmon 10, EDR LSASS access alerts |
| Isolate | Execution isolation | ASR "Block credential stealing from LSASS", app control |
| Evict | Credential eviction, process termination | Reset exposed creds, kill dumper process |
| Restore | Restore access | Re-enable affected accounts with new credentials |

### T1566.001 + T1204.002 Phishing attachment execution

| Tactic | Countermeasure | Implementation |
|---|---|---|
| Harden | Message hardening | DMARC/DKIM/SPF, macro blocking from internet (MOTW) |
| Detect | Message analysis, file analysis, process lineage analysis | Gateway sandboxing, EDR Office child rules |
| Isolate | Execution isolation | Protected View, Application Guard alternatives, app control |
| Evict | File eviction | Purge emails tenant-wide (ZAP / search-and-purge) |

### T1021 Remote Services (lateral movement)

| Tactic | Countermeasure | Implementation |
|---|---|---|
| Model | Network mapping, access modeling | BloodHound attack-path analysis (defensive use) |
| Harden | Credential hardening, local admin uniqueness | LAPS, tiering, disable NTLM where possible |
| Detect | Network traffic analysis, authentication event analysis | Zeek DCE-RPC/SMB, 4624 analytics |
| Isolate | Network isolation | Host firewall blocking SMB/WinRM/RDP between workstations |
| Deceive | Decoy credentials/hosts | Breadcrumbs to decoy servers |

### T1071 Application Layer Protocol (C2)

| Tactic | Countermeasure | Implementation |
|---|---|---|
| Detect | Network traffic analysis (beaconing, protocol metadata), identifier reputation | RITA, JA4, domain age enrichment |
| Isolate | Outbound traffic filtering, DNS denylisting | Egress proxy, protective DNS, sinkhole |
| Evict | Process termination | EDR kill + isolate |

### T1486 Data Encrypted for Impact

| Tactic | Countermeasure | Implementation |
|---|---|---|
| Harden | Platform hardening, file permissions | Least privilege on shares, controlled folder access |
| Detect | File content/behavior analysis | Mass rename/entropy analytics, canary files |
| Isolate | Network isolation | Auto-isolate host, block SMB at file servers |
| Restore | Restore object/configuration | Immutable backups, golden images |

---

## 3. Using D3FEND in Practice

| Use case | How |
|---|---|
| Justify a control | "Credential Guard implements D3FEND Credential Hardening against T1003.001" |
| Vendor comparison | Map each product's claimed features to D3FEND techniques; compare coverage on your prioritized ATT&CK set |
| Incident countermeasure plan | For each technique in the incident timeline, list Harden/Detect/Isolate/Evict/Restore actions |
| Gap analysis | Techniques with only Detect and no Harden/Isolate = over-reliance on SOC |
| Architecture diagrams | D3FEND CAD tool to draw countermeasure architecture with artifacts |

Lookup: d3fend.mitre.org → search ATT&CK ID → "Related countermeasures" via shared digital artifacts. Programmatic: D3FEND ontology (OWL/JSON-LD) and SPARQL endpoint.

---

## Engagement Cheatsheet

```text
ATT&CK technique → digital artifacts → D3FEND techniques by tactic (Model/Harden/Detect/Isolate/Deceive/Evict/Restore)
→ pick implementable → map to product config → avoid Detect-only coverage → CAD diagram / plan table
```

---

## Key References

- MITRE D3FEND (d3fend.mitre.org) — 1.0 released 2025; D3FEND CAD
- Related: `defensive-attack-mapping`, `defensive-threat-informed-defense`, `defensive-kill-chain-defense`, `defensive-defense-in-depth`
