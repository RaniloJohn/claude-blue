---
name: defensive-crowdstrike-falcon
description: "CrowdStrike Falcon operations for defenders: sensor deployment and health, prevention policy tuning (ML levels, behavior-based prevention, exploit mitigation), sensor update and content update policies after the July 2024 channel file incident, Next-Gen SIEM / Advanced Event Search with CrowdStrike Query Language (CQL) over events such as ProcessRollup2, DnsRequest, NetworkConnectIP4, UserLogon, custom IOA rules, Real Time Response (RTR) commands for live triage and remediation, network containment, Falcon Fusion SOAR workflows, Identity Protection, exclusions governance, and API automation with FalconPy. Use when hunting, triaging, or responding with CrowdStrike Falcon."
---

# CrowdStrike Falcon

Falcon combines EDR telemetry, prevention, and response. Most defender work: **hunting in Advanced Event Search (CQL)**, **triaging detections**, **live response via RTR**, and **policy/exclusion hygiene**.

## Quick Workflow

1. Verify sensor coverage and health (RFM — reduced functionality mode — hosts are blind spots)
2. Triage detections: process tree, related events, IOA/ML reason
3. Hunt with CQL; save useful queries as scheduled searches/custom IOAs
4. Respond: network contain → RTR collect/remediate → lift containment
5. Govern exclusions and policies; automate with Fusion SOAR

---

## 1. Policies

| Policy | Guidance |
|---|---|
| Prevention | Cloud/sensor ML at Moderate/Aggressive per group; enable behavior-based prevention, exploit mitigation, script-based execution monitoring, ransomware protections, suspicious process blocking |
| Sensor update | N-1/N-2 for production; early ring for test group |
| Content updates (Rapid Response Content) | Since the July 19, 2024 channel file 291 outage, customers can control content deployment cadence — use staged rings (early adopter → general) |
| Device control / firewall | Enable USB device control and host firewall where licensed |
| Tamper protection | Uninstall protection on all groups; maintenance tokens stored in vault |

---

## 2. CQL (Advanced Event Search / Next-Gen SIEM)

```text
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(powershell|pwsh)\.exe$/i
| CommandLine=/(-enc|-encodedcommand|frombase64string|downloadstring)/i
| groupBy([ComputerName, UserName, CommandLine], limit=max)
```

```text
// Office spawning script hosts (parent via ParentBaseFileName)
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(winword|excel|powerpnt|outlook)\.exe$/i
| FileName=/^(powershell|cmd|wscript|cscript|mshta|rundll32)\.exe$/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

```text
// DNS to tunneling services
#event_simpleName=DnsRequest
| DomainName=/(ngrok|trycloudflare|tailscale)\./i
| groupBy([ComputerName, DomainName])
```

```text
// Rare processes fleet-wide (prevalence)
#event_simpleName=ProcessRollup2 event_platform=Win
| groupBy([SHA256HashData, FileName], function=[count(aid, distinct=true, as=hosts)])
| hosts < 3
```

```text
// Join process with network connection by TargetProcessId/ContextProcessId
#event_simpleName=NetworkConnectIP4 RemotePort=4444
| join(query={#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine])
```

Common events: `ProcessRollup2`, `SyntheticProcessRollup2`, `NetworkConnectIP4/6`, `NetworkListenIP4`, `DnsRequest`, `UserLogon`, `UserLogonFailed2`, `NewExecutableWritten`, `AsepValueUpdate` (autostart registry), `ScheduledTaskRegistered`, `ServiceStarted`, `DriverLoad`. (Legacy SPL-based Event Search was replaced by LogScale/CQL — translate old queries.)

---

## 3. Custom IOAs

Rule groups per platform with process creation/file/network/domain rule types matching image filename, command line, parent — action: monitor → detect → block. Test in monitor mode on a pilot host group first.

---

## 4. Real Time Response (RTR)

| Command | Use |
|---|---|
| `ps`, `netstat`, `ls`, `cd`, `cat`, `filehash`, `reg query` | Triage |
| `get <file>` | Collect file (downloads 7z, password `infected`) |
| `memdump <pid>` | Process memory |
| `runscript -CloudFile="Collect-Triage"` / `-Raw=` | PowerShell/bash scripts |
| `put <file>` then `run` | Deploy tools (KAPE, Velociraptor offline collector) |
| `kill <pid>`, `rm`, `reg delete` | Remediate |
| `xmemdump`, `eventlog view/export` | Admin-level collection |

Roles: Read-only / Active Responder / Administrator — limit admin RTR to IR staff; audit RTR sessions.

**Network containment:** isolates host except Falcon cloud and configured allowlist (e.g., IR tool servers) — contain first, investigate second for high-severity detections.

---

## 5. Fusion SOAR (examples)

- Detection severity ≥ High on server → notify on-call + create ticket + auto-contain non-critical workstations
- New detection → enrich hash with threat intel → add to case
- Identity Protection alert (e.g., suspicious Kerberos) → force MFA / disable account via IdP integration

---

## 6. Exclusions Governance

| Type | Risk |
|---|---|
| ML exclusions | Skips ML scanning for path |
| Sensor visibility exclusions | Removes telemetry entirely — highest risk |
| IOA exclusions | Suppresses specific behavior detection |

Rules: narrowest scope (path + host group), ticket + owner + expiry, quarterly review, never exclude user-writable paths broadly.

---

## 7. API (FalconPy)

```python
from falconpy import Hosts, RealTimeResponse
hosts = Hosts(client_id=CID, client_secret=SECRET)
aids = hosts.query_devices_by_filter(filter="hostname:'ws-042'")["body"]["resources"]
hosts.perform_action(action_name="contain", ids=aids)
```

Scope API clients minimally; store secrets in a vault; log API usage.

---

## Engagement Cheatsheet

```text
coverage + RFM check → prevention/sensor/content-update rings → CQL hunts (#event_simpleName, regex /…/i, groupBy, join)
→ custom IOAs monitor→detect→block → contain → RTR collect (get/memdump/runscript) → remediate → exclusion governance → Fusion SOAR + FalconPy
```

---

## Key References

- CrowdStrike Falcon docs (Advanced Event Search, CQL reference, RTR); FalconPy SDK; CrowdStrike July 2024 incident PIR/RCA
- Related: `defensive-edr-tuning`, `defensive-live-response`, `defensive-threat-hunting`, `defensive-soar-automation`
