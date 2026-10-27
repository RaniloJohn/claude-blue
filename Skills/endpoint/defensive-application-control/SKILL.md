---
name: defensive-application-control
description: "Application allowlisting end to end: App Control for Business (formerly WDAC) policy design (base vs supplemental, Multiple Policy Format, rule levels, rule options 3/13/14/17), managed installer (Intune Management Extension, ConfigMgr) and ISG, Microsoft recommended block rules for LOLBins (mshta, msbuild, wmic, WSL, debuggers), vulnerable driver blocklist, deployment via Intune ApplicationControl CSP, CiTool and Group Policy limits, AppLocker as complement (not an MSRC security boundary), Smart App Control, PowerShell Constrained Language Mode, CodeIntegrity events 3076/3077/3089/3090-3092 and AppLocker 8028/8029, KQL hunting, audit-to-enforce rollout, Linux fapolicyd and macOS Santa. Use when designing, rolling out, tuning, or troubleshooting application control."
---

# Application Control

Allowlisting stops most commodity malware, ransomware droppers, and unapproved tools before they execute. The work is getting it enforced without breaking the business. Go audit → tune → enforce, ring by ring, and treat policy as code.

## Quick Workflow

1. Inventory software and how it arrives (Intune, ConfigMgr, user installs, self-updaters)
2. Pick a base: `DefaultWindows` or `AllowMicrosoft` example policy + managed installer + (optionally) ISG
3. Add signer rules for line-of-business apps; merge the recommended block rules and driver blocklist
4. Deploy in **audit** to a pilot ring; collect 3076/3089 for 2–4 weeks
5. Fix gaps with supplemental policies; remove audit option; enforce ring by ring
6. Monitor 3077 blocks, handle exceptions through a ticketed workflow, and review the policy quarterly

---

## 1. Choose the Control

| Platform | Control | Notes |
|---|---|---|
| Windows 10 1903+/11, Server 2016–2025 | **App Control for Business** | Kernel-enforced whole-device policy; covers EXE, DLL, drivers, MSI, scripts, and PowerShell CLM. Recommended. |
| Windows (complement) | AppLocker | Per-user/group rules, mixed fleets. Gets security fixes only, no new features, and is **not** an MSRC-serviced security boundary. |
| Windows 11 consumer/unmanaged | Smart App Control | Built on App Control + ISG. On managed devices it starts in evaluation and turns off within 48h unless enabled. |
| Linux (RHEL/Fedora/Debian) | fapolicyd | Trust DB (RPM/`debdb`) + first-match rules |
| macOS | Santa (North Pole Security fork) | Google archived the original in Feb 2025; use `northpolesec/santa` |

App Control complements AV/EDR; it doesn't replace it.

---

## 2. App Control Policy Design

### Rule levels (most to least preferred)

| Level | Use |
|---|---|
| `FilePublisher` / `SignedVersion` | Signed LOB/vendor apps: publisher + file name + minimum version |
| `Publisher` | Trusted vendor's whole catalog (broader) |
| `Hash` | Unsigned binaries; breaks on every update, so use sparingly |
| `FilePath` (1903+) | Only for admin-writable paths. Runtime check refuses user-writable paths unless option 18 is set (don't set it) |
| Managed installer / ISG | Origin- or reputation-based; heuristic, not a hard boundary |

### Key rule options

| # | Option | Guidance |
|---|---|---|
| 3 | Enabled:Audit Mode | Remove to enforce |
| 11 | Disabled:Script Enforcement | Leave unset so scripts/PowerShell get CLM |
| 13 | Enabled:Managed Installer | Trust software deployed by Intune IME/ConfigMgr |
| 14 | Enabled:Intelligent Security Graph Authorization | Reputation allow; acceptable for less strict tiers |
| 16 | Enabled:Update Policy No Reboot | Rebootless updates |
| 17 | Enabled:Allow Supplemental Policies | Required on base to accept supplementals |
| 20 | Enabled:Revoked Expired As Unsigned | Treat revoked/expired signatures as unsigned |

### Base + supplemental

- Use **Multiple Policy Format** (1903+). Since the 9 Apr 2024 security update, the number of active policies is unlimited. Before that update it was capped at 32, and Windows 11 21H2 still has the cap.
- Multiple **base** policies form an **intersection**: a file must be allowed by all of them. **Base + supplemental** form a **union**.
- Run an enforced base and an audit base side by side to test changes safely.

```powershell
# Base from example policy
Copy-Item C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml .\Base.xml
Set-CIPolicyIdInfo -FilePath .\Base.xml -PolicyName "Corp-Base" -ResetPolicyID
Set-RuleOption -FilePath .\Base.xml -Option 13   # managed installer
Set-RuleOption -FilePath .\Base.xml -Option 17   # allow supplementals
Set-RuleOption -FilePath .\Base.xml -Option 16   # no-reboot updates

# Supplemental for a LOB app
New-CIPolicy -MultiplePolicyFormat -ScanPath "C:\Program Files\LOBApp" -UserPEs `
  -Level FilePublisher -Fallback SignedVersion,Publisher,Hash -FilePath .\LOB.xml
Set-CIPolicyIdInfo -FilePath .\LOB.xml -BasePolicyToSupplementPath .\Base.xml -PolicyName "Supp-LOBApp"

# Compile and enforce
Set-RuleOption -FilePath .\Base.xml -Option 3 -Delete   # leave audit
ConvertFrom-CIPolicy -XmlFilePath .\Base.xml -BinaryFilePath .\Base.cip
CiTool --update-policy .\Base.cip
CiTool --list-policies
```

Keep XML in Git, review changes by PR, and bump `VersionEx` on every change.

### Signed policies

For high-value tiers (Tier 0, servers), sign the policy. An admin then can't remove it without a signed replacement. Test the removal procedure first: a broken signed policy plus Secure Boot can leave a machine unbootable.

---

## 3. Managed Installer & ISG

- An AppLocker `ManagedInstaller` rule collection designates the installer (e.g., `Microsoft.Management.Services.IntuneWindowsAgent.exe`). Files written by it and its child processes are tagged with the `$KERNEL.SMARTLOCKER.ORIGINCLAIM` extended attribute.
- ConfigMgr configures itself as a managed installer when you deploy its inbox App Control policies, or via `ccmsetup.exe` with the `ManagedInstaller` switch.
- Enable on the device: `Set-AppLockerPolicy -XmlPolicy MI.xml -Merge` then `appidtel.exe start [-mionly]` (`-mionly` = no ISG). Restart processes that are already running.
- **Limits:**
  - Self-updating apps (Chrome, Teams, Zoom per-user) lose the origin tag, so add signer rules for them.
  - Extract-and-run installers may fail.
  - Drivers are never authorized by managed installer.
  - Admins, or malware running as admin, can bypass it, so pair it with standard-user accounts.
  - Block apps from auto-launching at the end of install; otherwise trust extends to files that first run creates.

---

## 4. Block Rules (Always Merge)

- **Microsoft "applications that can bypass App Control" list:**
  - What it covers: `mshta.exe`, `msbuild.exe` (unless on build hosts), `wmic.exe`, WSL binaries (`bash`, `wsl`, `wslconfig`, `wslhost`, `lxrun`), debuggers (`cdb`, `windbg`, `kd`, `ntsd`), `dotnet`/`csi`/`fsi`, `aspnet_compiler`, `bginfo` < 4.22, and vulnerable `system.management.automation.dll` versions by hash.
  - How to merge it: remove its "Allow all" rules first, `Set-CiPolicyIdInfo -ResetPolicyId`, then `Merge-CIPolicy`.
- **Vulnerable driver blocklist:**
  - On by default with HVCI / memory integrity.
  - Also merge Microsoft's recommended driver block rules for BYOVD / EDR-killer defense.
- **Example deny rule:**

```xml
<Deny ID="ID_DENY_MSHTA" FriendlyName="mshta.exe" FileName="mshta.exe"
      MinimumFileVersion="0.0.0.0" MaximumFileVersion="65535.65535.65535.65535" />
```

---

## 5. Deployment

| Method | Multiple policies | Notes |
|---|---|---|
| Intune (ApplicationControl CSP) | Yes, rebootless | Preferred. **Unenrolling from MDM removes every policy not actively deployed**, not just the ones MDM added |
| ConfigMgr | Yes (inbox + custom) | Inbox policies make CM a managed installer |
| Local / script | Yes | Copy `{PolicyGUID}.cip` to `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`, or use `CiTool --update-policy` |
| Group Policy / WMI | **No**: single-policy format only | Use the MDM Bridge WMI Provider for multi-policy without MDM |

**Rings:** IT/pilot (audit) → early adopters (audit + review) → broad (enforce) → servers / Tier 0 (signed, strict, no ISG).

**Smart App Control fleet state:**
- Set DWORD `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState` (0 = off, 1 = enforce, 2 = evaluation), then run `CiTool.exe -r`.
- Example equivalent policy: `ExamplePolicies\SmartAppControl.xml`. Remove "Enabled:Conditional Windows Lockdown Policy" before using it as an App Control policy.

---

## 6. PowerShell & Scripts

- App Control script enforcement puts interactive PowerShell in **Constrained Language Mode**. Allowed (signed/allowlisted) scripts run in Full Language.
- Don't rely on `__PSLockdownPolicy`: it is trivially reversed.
- Remove PowerShell v2, which has no CLM and no AMSI.
- Sign admin scripts with an internal code-signing cert and add a signer rule.
- AppLocker event 8029 ("blocked") may still mean the script **ran in CLM**, not that it was stopped.
- Check the mode: `$ExecutionContext.SessionState.LanguageMode`.

---

## 7. Telemetry & Detection

### Events

| Channel | ID | Meaning |
|---|---|---|
| CodeIntegrity/Operational | 3076 | Audit: would have been blocked |
| | 3077 | Enforced block |
| | 3089 | Signature detail for 3076/3077 (`TotalSignatureCount` 0 = unsigned) |
| | 3033 / 3034 | Signature failure, enforced/audit (revoked, expired lifetime-signing EKU) |
| | 3004 | Invalid kernel driver signature |
| | 3099 | Policy loaded (watch for unexpected policy changes) |
| | 3090 / 3091 / 3092 | Allowed by ISG/MI (3090 needs `TestFlags 0x300`) / no ISG or MI authorization, audit/enforce. 3091 is very noisy, so filter before ingest |
| AppLocker MSI and Script | 8028 / 8029 | Script/MSI audit / enforce |
| | 8036 | COM object blocked |
| | 8039 / 8040 | Packaged app audit / block |
| AppLocker EXE and DLL | 8002 | Managed installer rule match (`PolicyName=MANAGEDINSTALLER`) |

### KQL (Defender for Endpoint)

```kql
// Top audit blocks to tune before enforcing
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "AppControlCodeIntegrityPolicyAudited"
| summarize Devices=dcount(DeviceId), Hits=count() by FileName, FolderPath, InitiatingProcessFileName
| order by Devices desc

// Enforced blocks of LOLBins = likely attack attempt, not a tuning gap
DeviceEvents
| where ActionType in ("AppControlCodeIntegrityPolicyBlocked","AppControlExecutableBlocked","AppControlScriptBlocked")
| where FileName in~ ("mshta.exe","msbuild.exe","wmic.exe","cdb.exe","regsvr32.exe","installutil.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```

### Alert on tampering

- Unexpected 3099 (policy load) outside change windows.
- Policy files dropped in `CiPolicies\Active` by non-management processes.
- `CiTool --remove-policy` or `appidtel stop` command lines.
- AppLocker policy cleared: `Set-AppLockerPolicy` with an empty policy.

---

## 8. Linux — fapolicyd

```bash
dnf install fapolicyd && systemctl enable --now fapolicyd
# rules in /etc/fapolicyd/rules.d/*.rules → compiled by fagenrules (first match wins)
fapolicyd-cli --check-rules && fapolicyd-cli --lint
fapolicyd-cli --file add /opt/app/bin/ --trust-file app   # trust non-RPM software
fapolicyd-cli --update                                    # reload trust DB
fapolicyd-cli --check-status; fapolicyd-cli --check-metrics
```

- Start with `permissive = 1` in `fapolicyd.conf` and review denials (`fapolicyd --debug-deny`). Then enforce.
- Policies: `known-libs` (default) or `restrictive`. The `dir=untrusted` macro is deprecated.
- Use `ignore_mounts` only on `noexec` mounts.
- Debian/Ubuntu use the `debdb` backend.

## 9. macOS — Santa

- Modes: Monitor → Lockdown.
- Rule types: `TEAMID` / `SIGNINGID` (preferred) → `CERTIFICATE` → `BINARY` hash.
- Manage rules via a sync server (e.g., Workshop/Rudolph-style servers) or MDM config profile.
- Track 2026 releases: Santa 2026.8 fixed race, caching, and universal-binary inspection gaps.

---

## 10. Exceptions & Operations

- Exception request: business owner + app + vendor signer + scope (device group) + expiry. Approve as a supplemental policy, never "disable policy on this box".
- Prefer signer rules over hashes; hash exceptions must expire.
- Developer machines: a separate ring with a dev-tools supplemental policy (msbuild, dotnet). Don't weaken the base.
- **KPIs:**
  - % devices enforced
  - weekly enforced blocks by category (malware / unapproved / false positive)
  - exception count and age
  - mean time to approve an exception
- Validate with emulation: drop an unsigned EXE in `%TEMP%`, run `mshta`, run an unsigned PS script → expect 3077/8029 and CLM.

---

## Engagement Cheatsheet

```text
inventory + delivery paths → base (DefaultWindows/AllowMicrosoft, MPF, opts 13/16/17[/14]) + block rules + driver blocklist
→ Intune ApplicationControl CSP, audit ring → KQL on AppControlCodeIntegrityPolicyAudited / 3076+3089 → supplementals (FilePublisher)
→ delete opt 3, enforce by ring, sign Tier 0 policy → monitor 3077/8029, alert on 3099/CiTool/appidtel tampering
→ Linux fapolicyd (permissive→enforce), macOS Santa (Monitor→Lockdown) → exceptions = expiring supplementals
```

---

## Key References

- Microsoft Learn: App Control for Business overview; App Control and AppLocker overview; Deploy multiple policies; Managed installer; Applications that can bypass App Control; Event ID explanations
- Microsoft Learn: Smart App Control overview; ApplicationControl CSP; CiTool
- fapolicyd: https://github.com/linux-application-whitelisting/fapolicyd · Santa: https://github.com/northpolesec/santa
- Related: `defensive-windows-hardening`, `defensive-edr-tuning`, `defensive-detect-defense-evasion`, `defensive-usb-device-control`, `defensive-macos-forensics`
