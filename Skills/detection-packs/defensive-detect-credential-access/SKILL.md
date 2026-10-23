---
name: defensive-detect-credential-access
description: "Detection pack for MITRE ATT&CK Credential Access (TA0006): LSASS memory dumping, SAM/SECURITY/SYSTEM hive theft, NTDS.dit extraction, DCSync, Kerberoasting, AS-REP roasting, password spraying and brute force, credential stuffing, MFA fatigue and request generation, browser and password store theft, DPAPI abuse, keylogging, forced authentication and NTLM capture (LLMNR/NBT-NS poisoning, coercion), unsecured credentials in files/scripts/cloud metadata, steal web session cookies and application access tokens, and Linux /etc/shadow and SSH key theft. Detections, FPs, triage. Use when building credential access detections."
---

# Detection Pack — Credential Access (TA0006)

Credential theft turns a single compromised host into a domain or tenant compromise. Treat every confirmed credential access event as SEV2+ and assume the credentials are burned.

## Quick Workflow

1. Telemetry: Sysmon 10 (LSASS), 4688/Sysmon 1 cmdlines, DC Kerberos/NTLM events, IdP sign-ins, file access on credential stores
2. Deploy high-fidelity rules (LSASS, NTDS, DCSync) at high severity
3. Deploy volume/ratio rules (spray, Kerberoast) with thresholds
4. Response: reset/rotate affected credentials, revoke sessions, hunt reuse

---

## 1. Host Credential Theft (Windows)

| Behavior | Signal |
|---|---|
| LSASS dump (T1003.001) | Sysmon 10 `TargetImage=lsass.exe`, `GrantedAccess` 0x1010/0x1410/0x1438/0x143a/0x1fffff; `comsvcs.dll MiniDump`; `procdump -ma lsass`; `.dmp` files written (Sysmon 11) |
| SAM/SYSTEM/SECURITY hive (T1003.002/.004) | `reg save HKLM\SAM`, `HKLM\SECURITY`, `HKLM\SYSTEM`; shadow copy access to `\Windows\System32\config\` |
| NTDS.dit (T1003.003) | `ntdsutil "ac i ntds" "ifm"`, `vssadmin create shadow` on DC, `esentutl /y /vss`, Sysmon 9 raw read on DC |
| DCSync (T1003.006) | 4662 with replication GUIDs by non-DC; DRSUAPI from non-DC IP |
| Cached creds / LSA secrets | Reads of `HKLM\SECURITY\Cache`, `Policy\Secrets` |
| DPAPI / browser stores (T1555.003/.004) | Non-browser processes reading `Login Data`, `Cookies`, `Local State`, `key4.db`; `vaultcmd /list`; DPAPI master key access |
| Credential Manager | `cmdkey /list`, `vaultcmd` |
| Keylogging (T1056.001) | `SetWindowsHookEx`-heavy unsigned processes; input capture API usage (EDR) |

```yaml
title: Credential Hive or NTDS Extraction Commands
logsource: { product: windows, category: process_creation }
detection:
  hive:
    CommandLine|contains|all: ['reg', 'save']
    CommandLine|contains: ['HKLM\SAM','HKLM\SECURITY','HKLM\SYSTEM','hklm\sam','hklm\security','hklm\system']
  ntds:
    CommandLine|contains: ['ntdsutil','ifm']
  shadow:
    CommandLine|contains: ['\GLOBALROOT\Device\HarddiskVolumeShadowCopy']
  condition: hive or ntds or shadow
level: high
tags: [attack.credential-access, attack.t1003.002, attack.t1003.003]
```

---

## 2. Kerberos & NTLM

| Attack | Detection |
|---|---|
| Kerberoasting | 4769 RC4 (0x17) to user SPNs; ≥3 distinct SPNs per requester per hour; honey SPN |
| AS-REP roasting | 4768 `PreAuthType=0` |
| Password spray | 4771 (0x18) / 4625 / 4776 failures: many users, few attempts each, one source |
| Brute force | Many failures for one account; 4740 lockouts |
| Forced auth / NTLM capture (T1187, T1557.001) | LLMNR/NBT-NS responses from non-DNS hosts; outbound SMB (445) to internet; `.url/.scf/.library-ms` files with UNC paths on shares; coercion RPC (`efsrpc`, `spoolss`) to DCs |

```spl
index=wineventlog (EventCode=4771 Failure_Code=0x18) OR (EventCode=4625) OR (EventCode=4776 Status=0xC000006A)
| eval src=coalesce(Client_Address, Source_Network_Address, Workstation)
| bin _time span=30m
| stats dc(user) as users count by src _time
| where users >= 15 AND count/users < 3
```

---

## 3. Identity Provider / Cloud

| Attack | Detection |
|---|---|
| Password spray (Entra/Okta) | `SigninLogs` `ResultType 50126` across many users from one IP/ASN; Okta `user.session.start` FAILURE spikes |
| MFA fatigue (T1621) | ≥5 MFA denials/timeouts (`500121`) then success; Okta push denials |
| Token theft / replay (T1528, T1539, T1550.001) | Same `SessionId` from different IPs/ASNs; sign-in from hosting ASN right after user sign-in; Identity Protection "anomalous token" |
| Device code phishing | `AuthenticationProtocol == "deviceCode"` for users who don't use it |
| Cloud metadata credential theft (T1552.005) | GuardDuty `InstanceCredentialExfiltration`; IMDS requests from unexpected processes |
| Secrets in code/config (T1552.001) | Secret scanning hits; reads of `.env`, `credentials`, `kubeconfig` by unusual processes |

```kql
let fails = SigninLogs | where TimeGenerated > ago(1h) and ResultType in ("500121","50074")
  | summarize Fails=count() by UserPrincipalName;
SigninLogs | where TimeGenerated > ago(1h) and ResultType == "0"
| join kind=inner fails on UserPrincipalName | where Fails >= 5
```

---

## 4. Linux / macOS

- Reads of `/etc/shadow` by non-root-tooling processes (auditd watch `-r`), `unshadow`, `john`, `hashcat` execution
- Access to `~/.ssh/id_*`, `~/.aws/credentials`, `~/.kube/config`, browser profiles
- `/proc/<pid>/mem` reads of sshd/sudo (ptrace)
- macOS: `security find-generic-password`/`dump-keychain`, `osascript` password dialogs, keychain DB reads

---

## 5. False Positives

| Detection | FP | Tune |
|---|---|---|
| LSASS access | AV/EDR, backup, crash reporters | Signer + full path + access mask |
| Spray | Misconfigured service with old password, VPN concentrators NATing many users | Source IP context, service accounts |
| Kerberoast | Legacy apps requesting RC4 (should be gone post-2026) | Remediate app; temporary allowlist with expiry |
| Browser store reads | Password managers, backup/sync tools | Signer allowlist |

---

## 6. Response

1. Contain host; capture memory if LSASS dumped
2. Determine credential exposure scope (who was logged on — `query user`, 4624 within window)
3. Reset passwords (privileged first), rotate service account secrets, krbtgt double reset if DC credentials exposed
4. Revoke sessions/tokens (Entra/Okta/cloud)
5. Hunt credential reuse from new sources

---

## Engagement Cheatsheet

```text
LSASS/hives/NTDS/DCSync rules (high) → Kerberos & spray thresholds → IdP spray/MFA fatigue/token replay
→ cloud metadata & secret reads → Linux/macOS stores → contain + rotate + revoke + hunt reuse
```

---

## Key References

- MITRE ATT&CK TA0006; Microsoft credential theft mitigation guidance
- Related: `defensive-ad-detection`, `defensive-entra-id`, `defensive-windows-hardening`, `defensive-auth-implementation`
