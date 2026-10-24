---
name: defensive-asset-inventory
description: "Building and maintaining enterprise asset and software inventory for security (CIS Controls 1 and 2): data sources (AD/Entra, MDM/Intune/Jamf, EDR, cloud APIs, DHCP/DNS, NAC, network scans, NetFlow, CMDB, SaaS/IdP app catalogs, vulnerability scanners), reconciliation and unmanaged-asset detection, required attributes (owner, criticality, exposure, data classification, lifecycle/EoS), software inventory and allowlists, cloud and container asset tracking, CAASM tools, end-of-support tracking (CISA BOD 26-02 edge devices), and KPIs. Use when building an asset inventory, finding unmanaged devices, or feeding vulnerability and detection programs."
---

# Asset & Software Inventory

You can't defend, patch, monitor, or recover what you don't know exists. Inventory is a **reconciliation problem**: many partial sources, one trusted view.

## Quick Workflow

1. Enumerate all sources (§1); pull them on a schedule
2. Normalize and correlate (hostname, serial, MAC, cloud instance ID, EDR agent ID)
3. Compute gaps: assets missing EDR, MDM, vuln scanning, logging, owner
4. Enrich: owner, criticality, exposure, data classification, lifecycle
5. Feed vuln management, detection (asset context), IR, and DR
6. Measure coverage; chase unknowns

---

## 1. Sources

| Source | Gives |
|---|---|
| AD / Entra ID | Joined devices, last logon, OS |
| MDM (Intune, Jamf, Workspace ONE) | Managed endpoints, compliance, serials |
| EDR | Hosts with agent, last seen |
| Cloud APIs (AWS Config/Resource Explorer, Azure Resource Graph, GCP Asset Inventory) | Instances, storage, serverless, IPs |
| Kubernetes API | Clusters, nodes, workloads, images |
| DHCP / DNS logs | Devices on network (incl. unmanaged) |
| NAC / switch CAM/ARP tables | MAC-to-port mapping |
| Network scans (Nmap, vuln scanners) | Listening services, fingerprints |
| NetFlow / NDR passive discovery | Active hosts including IoT/OT |
| IdP / SaaS catalogs / CASB | SaaS applications in use |
| CMDB / procurement / finance | Purchased assets, owners, contracts |
| EASM | Internet-facing assets (`defensive-asset-inventory`) |

---

## 2. Attributes

| Attribute | Why |
|---|---|
| Unique ID(s) | Correlation across sources |
| Owner (person + team) | Remediation and IR contact |
| Business criticality (Tier 0–3) | Prioritization, detection severity |
| Exposure (internet-facing, DMZ, internal, isolated) | Vuln prioritization (BOD 26-04 "exposed") |
| Data classification handled | Breach impact |
| OS/firmware version, EoS date | Lifecycle risk (BOD 26-02 for edge devices) |
| Security coverage flags | EDR, MDM, logging, backup, vuln scan |
| Location / environment | Prod/dev, site, cloud account |

---

## 3. Gap Queries (examples)

```kql
// Entra-joined devices without Defender onboarding (Sentinel + Defender tables)
let edr = DeviceInfo | where Timestamp > ago(7d) | distinct DeviceName;
IntuneDevices
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by DeviceName
| where DeviceName !in (edr)
| project DeviceName, OS, UserName, LastContact
```

```bash
# DHCP leases vs EDR inventory (CSV exports)
comm -23 <(cut -d, -f2 dhcp_leases.csv | sort -u) <(cut -d, -f1 edr_hosts.csv | sort -u) > unmanaged_macs_or_hosts.txt
```

Cloud: Resource Graph query for VMs without required tags/agents; AWS Config rule for EC2 instances without SSM agent.

---

## 4. Software Inventory

- EDR/MDM/osquery software lists → normalize vendor/product/version
- Flag: unauthorized software (RMM tools, P2P, crypto miners), EoS versions, vulnerable versions (feed VM)
- Maintain allowlist/denylist; enforce with application control (`defensive-windows-hardening`)
- SBOMs for internally built software (`defensive-sbom-slsa`)

---

## 5. Tools

CAASM platforms (Axonius, runZero, Lansweeper, JupiterOne, Panaseer), open-source options (Snipe-IT for IT asset management, GLPI, osquery/Fleet for endpoint state, runZero Community), native cloud inventories. Choose based on connectors to your sources and API access for automation.

---

## 6. KPIs

| KPI | Target |
|---|---|
| Assets with owner | ≥ 98% |
| Servers with EDR | ≥ 99% |
| Endpoints managed (MDM) | ≥ 98% |
| Unknown devices on network (weekly) | Trending to 0 |
| Internet-facing assets with owner and scan coverage | 100% |
| EoS assets with approved exception or replacement plan | 100% |

---

## Engagement Cheatsheet

```text
pull all sources (directory, MDM, EDR, cloud APIs, K8s, DHCP/DNS, NAC, scans, NetFlow, IdP/CASB, CMDB, EASM) → correlate IDs
→ gaps (no EDR/MDM/logging/owner/scan) → enrich (owner, tier, exposure, data class, EoS) → software inventory + allow/deny → feed VM/detection/IR/DR → KPIs
```

---

## Key References

- CIS Controls v8.1 (Controls 1 & 2); NIST SP 1800-5 (IT Asset Management); CISA BOD 26-02 (end-of-support edge devices); BOD 23-01 (asset visibility, federal)
- Related: `defensive-vuln-management`, `defensive-tool-nmap`, `defensive-cspm`, `defensive-network-security-architecture`
