---
name: defensive-patch-management
description: "Patch and update operations: patch cadence (Microsoft Patch Tuesday, out-of-band, vendor PSIRT cycles), ring-based deployment (pilot, broad, critical), WSUS/Intune/Windows Autopatch, SCCM/ConfigMgr, Linux (unattended-upgrades, dnf-automatic, livepatch), macOS (MDM declarative updates), third-party apps, network/edge appliances and firmware, emergency patching for KEV/zero-days, verification and compliance reporting, rollback plans, and end-of-life tracking (e.g., Windows 10 end of support Oct 2025, ESU). Use when planning patch processes, responding to urgent vulnerabilities, or proving patch compliance."
---

# Patch Management

Patching is a logistics problem with a security deadline. Ring deployments give speed with safety; emergency lanes handle KEV/zero-days; verification proves the fix landed.

## Quick Workflow

1. Maintain inventory incl. firmware and appliances
2. Define rings and cadences per asset class
3. Intake advisories (vendor PSIRTs, KEV, Patch Tuesday)
4. Prioritize (see `defensive-vuln-management`)
5. Deploy by ring; monitor failures
6. Verify (scan/version check); report; handle exceptions
7. Track EOL and plan migrations

---

## 1. Rings

| Ring | Scope | Delay after release |
|---|---|---|
| 0 — Lab/IT | Test devices, IT staff | 0–1 day |
| 1 — Pilot | ~5–10% representative users/servers | 2–3 days |
| 2 — Broad | General population | 7 days |
| 3 — Critical/sensitive | Systems needing change windows | 14 days (or emergency lane) |

Emergency lane (KEV on exposed asset, active exploitation): compress to hours/days with abbreviated testing and a rollback plan.

---

## 2. Platform Tooling

| Platform | Tools |
|---|---|
| Windows | Windows Update for Business / Windows Autopatch (Intune), WSUS, ConfigMgr; hotpatch for supported Windows Server/Windows 11 Enterprise editions |
| Linux | `unattended-upgrades` (Debian/Ubuntu), `dnf-automatic` (RHEL family), Ubuntu Livepatch / kpatch for kernels, configuration management (Ansible) |
| macOS | MDM declarative software update enforcement (deadlines) |
| Third-party apps | Intune/ConfigMgr third-party catalogs, winget, Chocolatey, vendor auto-update |
| Network/edge | Vendor firmware via controllers (FMC, Panorama, FortiManager, Huawei iMaster NCE); maintenance windows; config backup first |
| Containers | Rebuild images on base updates; don't patch running containers |
| Cloud managed | Provider-managed patching (RDS, AKS/EKS/GKE node auto-upgrade); track versions |

```bash
# Debian/Ubuntu: security-only automatic updates
sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
# RHEL family
sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer
```

---

## 3. Edge Appliances (highest priority class)

VPNs, firewalls, load balancers, file-transfer appliances, and remote-access gateways dominate KEV additions and initial-access incidents.

```text
[ ] Subscribe to vendor PSIRT feeds (Fortinet, Palo Alto, Cisco, Citrix, Ivanti, F5, SonicWall, Huawei)
[ ] Inventory versions; map to advisories automatically
[ ] Emergency patch path with pre-approved change
[ ] After critical edge CVE: run vendor integrity/IOC checker; hunt for exploitation (patching doesn't remove implants)
[ ] Remove management interfaces from internet
```

---

## 4. Verification

- Rescan with vulnerability scanner (authenticated)
- Version queries: `Get-HotFix`, `Get-ComputerInfo | select OsBuildNumber`, `dpkg -l | grep <pkg>`, `rpm -q`, `uname -r`
- EDR/inventory software lists; Intune/ConfigMgr compliance reports
- Reboot pending? Many patches incomplete until reboot — track `RebootRequired` states

```powershell
Get-HotFix | Sort InstalledOn -Desc | Select -First 10
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR   # OS build revision
```

---

## 5. Rollback

- Snapshot VMs before patching critical servers
- Keep previous package versions available (apt pinning / dnf history undo)
- Windows: uninstall KB via `wusa /uninstall /kb:<id>` (where supported) or ConfigMgr; Autopatch pause/rollback for feature updates
- Network devices: backup config + previous image on flash

---

## 6. End-of-Life

| Product | Status (verify current dates) |
|---|---|
| Windows 10 | End of support 14 Oct 2025; ESU available (paid for organizations; consumer options vary) |
| Windows Server 2016 | Extended support ends Jan 2027 |
| Windows Server 2012/2012 R2 | Ended Oct 2023 (ESU via Azure/Arc) |
| Office 2016/2019 | Ended Oct 2025 |
| Ubuntu 20.04 LTS | Standard support ended May 2025 (ESM available) |
| CentOS 7 | EOL June 2024 |

EOL systems: isolate, compensating controls, migration plan with deadline.

---

## 7. Metrics & Reporting

- % devices compliant per ring within SLA
- Median patch latency by severity tier
- Emergency patches: time from advisory to 95% coverage
- Failed installs and reboot-pending counts
- EOL asset count

---

## Engagement Cheatsheet

```text
inventory (incl. firmware/edge) → rings + emergency lane → PSIRT/KEV intake → prioritized deploy
→ verify (rescan + versions + reboot) → rollback ready → EOL tracking → compliance metrics
```

---

## Key References

- Microsoft: Windows Autopatch, Windows Update for Business, hotpatch docs; Microsoft Lifecycle Policy
- NIST SP 800-40r4 Guide to Enterprise Patch Management Planning
- CISA KEV and edge-device guidance
- Related: `defensive-vuln-management`, `defensive-firewall-analysis`
