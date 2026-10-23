---
name: defensive-windows-hardening
description: "Windows endpoint and server hardening mapped to attacker techniques: Attack Surface Reduction (ASR) rules, Microsoft Defender configuration, App Control for Business (WDAC) and AppLocker, LSA protection (RunAsPPL), Credential Guard, HVCI/memory integrity and the Vulnerable Driver Blocklist, Windows LAPS, removing local admin, PowerShell Constrained Language Mode and logging, SMB signing/SMBv1 removal, LLMNR/NBT-NS/WPAD disablement, LDAP signing and channel binding, RDP hardening, BitLocker, Windows Firewall, and CIS/Microsoft security baselines. Use when hardening Windows fleets or recommending preventive controls after an incident."
---

# Windows Hardening

Harden against the techniques that actually show up in incidents: credential theft, script/LOLBin execution, lateral movement via SMB/WMI/RDP, and driver-based EDR killing.

## Quick Workflow

1. Apply Microsoft Security Baseline or CIS Benchmark (Level 1) via GPO/Intune
2. Deploy ASR rules: audit → block
3. Credential protections: LSA PPL, Credential Guard, LAPS, no local admin
4. Application control: WDAC (preferred) or AppLocker
5. Network hardening: SMB signing, disable LLMNR/NBT-NS, firewall
6. Validate with emulation and measure breakage

---

## 1. ASR Rules (verify GUIDs in Microsoft docs before deploying)

| Rule | GUID |
|---|---|
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block all Office applications from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block executable content from email client and webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` |
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |
| Block process creations originating from PSExec and WMI commands | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` |
| Block JavaScript or VBScript from launching downloaded executable content | `d3e037e1-3eb8-44c8-a917-57927947596d` |
| Block Office applications from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` |
| Block Office applications from injecting code into other processes | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` |
| Use advanced protection against ransomware | `c1db55ab-c21a-4637-bb3f-a12568109d35` |

```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions AuditMode
# Actions: Disabled | Enabled (block) | AuditMode | Warn
```

Audit events: Defender Operational 1121 (blocked), 1122 (audited). PSExec/WMI rule breaks SCCM — scope carefully.

---

## 2. Credential Protection

| Control | Setting | Defends |
|---|---|---|
| LSA protection | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` (or 2 for UEFI-lock-free on recent builds) | LSASS memory reads by non-PPL processes |
| Credential Guard | VBS-isolated LSAIso; enabled by default on eligible Windows 11 22H2+ enterprise devices | NTLM hash/TGT theft from LSASS |
| Windows LAPS | Built into Windows (April 2023+); store in Entra ID or AD; encrypted passwords | Local admin reuse → lateral movement |
| Remove local admin | Standard users; admin via PAW/JIT | Most credential theft needs admin |
| Protected Users group | Privileged accounts | NTLM, delegation, RC4, cached creds |
| WDigest off | `UseLogonCredential = 0` (default on modern) | Cleartext creds |
| Restricted Admin / Remote Credential Guard | RDP | Creds left on RDP target |
| Disable cached logons on servers | `CachedLogonsCount = 0` (where viable) | Offline cracking |

---

## 3. Application Control

| Option | Notes |
|---|---|
| App Control for Business (WDAC) | Kernel-enforced; managed installer + ISG; signer rules; supersedes AppLocker for security boundaries |
| AppLocker | Easier; user-mode enforcement; good for quick wins (block `%TEMP%`, `%APPDATA%` exe) |
| Microsoft recommended block rules | Block LOLBins (e.g., `mshta.exe`, `msbuild.exe`, `wmic.exe` where unused) |
| Smart App Control | Consumer/unmanaged devices |

Start in audit (CodeIntegrity 3076), review, then enforce (3077).

---

## 4. PowerShell

- Script Block Logging + Module Logging + Transcription (to protected share)
- Remove PowerShell v2 (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`) — prevents downgrade bypassing logging/AMSI
- Constrained Language Mode enforced via WDAC/AppLocker (not via `__PSLockdownPolicy` alone)
- JEA for delegated admin tasks

---

## 5. Kernel & Driver

- HVCI (Memory integrity) on; enables the Microsoft Vulnerable Driver Blocklist by default
- Secure Boot + TPM; BitLocker with TPM+PIN for laptops
- Block vulnerable drivers via ASR + WDAC driver block rules

---

## 6. Network & Protocols

| Control | Setting |
|---|---|
| SMBv1 | Removed |
| SMB signing | Required (default required on Windows 11 24H2 / Server 2025 for many scenarios — verify; enforce via GPO everywhere) |
| SMB encryption | For sensitive shares |
| LLMNR | `Turn off multicast name resolution` = Enabled |
| NBT-NS | Disable NetBIOS over TCP/IP (DHCP option or adapter setting) |
| WPAD | Disable auto-proxy discovery or define explicit DNS record |
| LDAP signing & channel binding | Require on DCs |
| NTLM | Audit → restrict; NTLMv1 off (LmCompatibilityLevel 5); prepare for NTLM-disabled-by-default future releases |
| Print Spooler | Disabled on DCs and servers that don't print |
| RDP | NLA required; restrict via firewall to jump hosts; no internet exposure |
| WinRM | Restrict to admin subnets; HTTPS |
| Windows Firewall | On all profiles; inbound default deny; block workstation-to-workstation SMB/RDP/WinRM |

---

## 7. Defender Baseline

```powershell
Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples
Set-MpPreference -CloudBlockLevel High -CloudExtendedTimeout 50
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -EnableControlledFolderAccess AuditMode
```

Tamper protection on (managed centrally).

---

## 8. Validation

| Control | Test |
|---|---|
| ASR LSASS | Atomic T1003.001 → blocked (1121) |
| LAPS | Unique local admin passwords per host; rotation |
| SMB signing | `Get-SmbServerConfiguration | Select RequireSecuritySignature` |
| LLMNR off | Responder in lab sees no LLMNR from hardened hosts |
| WDAC | Unsigned binary from `%TEMP%` blocked (3077) |

---

## Engagement Cheatsheet

```text
baseline (MS/CIS) → ASR audit→block → LSA PPL + Credential Guard + LAPS + no local admin
→ WDAC → PSv2 removed + logging → HVCI + driver blocklist → SMB signing + LLMNR/NBT-NS off
→ firewall east-west → validate with emulation
```

---

## Key References

- Microsoft Security Baselines (Security Compliance Toolkit); CIS Microsoft Windows Benchmarks
- Microsoft ASR rules reference; App Control for Business docs; Windows LAPS docs
- Related: `defensive-edr-tuning`, `defensive-ad-hardening`, `defensive-network-segmentation`
