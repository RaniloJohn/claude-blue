---
name: defensive-sysmon
description: "Sysmon deployment, configuration, and detection engineering on Windows and Linux: event IDs 1–29 and their detection value, schema versions, config design (include/exclude, RuleGroup, condition operators), SwiftOnSecurity and olafhartong sysmon-modular baselines, high-value event 10 (ProcessAccess) and 7 (ImageLoad) targeting, DNS (22), named pipes (17/18), WMI (19–21), file delete archiving (23), FileExecutableDetected (29), native built-in Sysmon on Windows 11, Sysmon for Linux, deployment at scale, tamper monitoring, and volume control. Use when configuring Sysmon or writing detections on Sysmon data."
---

# Sysmon

Sysmon turns Windows into a high-fidelity sensor for free. Value comes entirely from configuration — default config logs little; a careless config floods your SIEM.

## Quick Workflow

1. Start from a maintained baseline (SwiftOnSecurity or sysmon-modular)
2. Add targeted includes for 7, 8, 10, 17/18, 25, 29
3. Exclude known noise by combination (image + signer + path)
4. Test volume on pilot group (EPS per host)
5. Deploy at scale; forward `Microsoft-Windows-Sysmon/Operational`
6. Monitor 4/16 and volume for tamper

---

## 1. Event IDs

| ID | Event | Detection value |
|---|---|---|
| 1 | ProcessCreate | CommandLine, Hashes, OriginalFileName, ParentImage, IntegrityLevel, ProcessGuid |
| 2 | File creation time changed | Timestomping |
| 3 | NetworkConnect | Process → IP:port (include-only for volume) |
| 4 | Sysmon service state changed | Tamper (not filterable) |
| 5 | ProcessTerminate | Lifetime |
| 6 | DriverLoad | BYOVD, unsigned drivers |
| 7 | ImageLoad | Sideloading, `clr.dll` in odd processes, unsigned DLLs |
| 8 | CreateRemoteThread | Injection |
| 9 | RawAccessRead | Raw disk read (NTDS/SAM theft) |
| 10 | ProcessAccess | LSASS access; GrantedAccess; CallTrace |
| 11 | FileCreate | Drops, staging, startup folder |
| 12 / 13 / 14 | Registry object create-delete / value set / rename | Persistence |
| 15 | FileCreateStreamHash | ADS incl. Zone.Identifier contents |
| 16 | Sysmon config change | Tamper |
| 17 / 18 | Pipe created / connected | C2 pipes, PsExec |
| 19 / 20 / 21 | WMI filter / consumer / binding | WMI persistence |
| 22 | DNSEvent | Process → domain |
| 23 | FileDelete (archived) | Recover deleted tools (needs ArchiveDirectory) |
| 24 | ClipboardChange | |
| 25 | ProcessTampering | Hollowing, herpaderping |
| 26 | FileDeleteDetected | Delete logged without archiving |
| 27 | FileBlockExecutable | Block PE writes (prevention) |
| 28 | FileBlockShredding | Block shredding tools |
| 29 | FileExecutableDetected | New PE written (Sysmon 15+) |

---

## 2. Config Skeleton

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <ArchiveDirectory>SysmonArchive</ArchiveDirectory>
  <EventFiltering>

    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <RuleGroup name="LSASS" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="LSASS-exclude" groupRelation="and">
      <ProcessAccess onmatch="exclude">
        <SourceImage condition="end with">\MsMpEng.exe</SourceImage>
        <GrantedAccess condition="is">0x1000</GrantedAccess>
      </ProcessAccess>
    </RuleGroup>

    <RuleGroup name="DotNetInOddHosts" groupRelation="and">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="end with">\clr.dll</ImageLoaded>
        <Image condition="is not">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe</Image>
      </ImageLoad>
    </RuleGroup>

    <RuleGroup name="Pipes" groupRelation="or">
      <PipeEvent onmatch="exclude">
        <PipeName condition="begin with">\mojo.</PipeName>
      </PipeEvent>
    </RuleGroup>

    <RuleGroup name="NewExecutables" groupRelation="or">
      <FileExecutableDetected onmatch="include">
        <TargetFilename condition="begin with">C:\Users\</TargetFilename>
        <TargetFilename condition="begin with">C:\ProgramData\</TargetFilename>
        <TargetFilename condition="begin with">C:\Windows\Temp\</TargetFilename>
      </FileExecutableDetected>
    </RuleGroup>

    <RuleGroup name="DeleteArchive" groupRelation="or">
      <FileDelete onmatch="include">
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
      </FileDelete>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

Schema version: match your Sysmon binary (`sysmon -s` prints schema). Conditions: `is`, `is not`, `is any`, `contains`, `contains any`, `contains all`, `excludes`, `begin with`, `end with`, `not begin with`, `not end with`, `less than`, `more than`, `image`.

Rule semantics: an event is logged if it matches an include and no exclude for that event type (exclude wins).

---

## 3. Install / Update

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml     # install
sysmon64.exe -c sysmonconfig.xml                 # update config
sysmon64.exe -c                                   # print current config
sysmon64.exe -u                                   # uninstall
```

**Native Sysmon (Windows 11)**: Sysmon ships as an optional Windows feature (Insider builds Feb 2026, GA via cumulative updates for 24H2+). Enable via Settings › System › Optional features › More Windows features, or `Dism /Online /Enable-Feature /FeatureName:Sysmon`, then `sysmon -i`. Remove the Sysinternals-installed Sysmon first. Updates arrive through Windows Update; configuration remains XML (`sysmon -c`) or management tooling. Verify availability on Windows Server per current Microsoft docs.

Deploy at scale: GPO startup script, Intune Win32 app, SCCM, or EDR script; store config in a version-controlled share.

---

## 4. Sysmon for Linux

```bash
sudo sysmon -accepteula -i linux-config.xml
journalctl -u sysmon   # events in syslog/journald (XML)
```

Supported: process create/terminate, network connect, file create/delete, raw access read, process access (ptrace). eBPF-based.

---

## 5. Volume Management

| Event | Typical risk | Control |
|---|---|---|
| 3 | Very high | Include-only: LOLBins, script hosts, Office, unusual ports |
| 7 | Very high | Include-only: specific DLLs (clr, vaultcli, dbghelp, comsvcs) or unsigned |
| 10 | High | Include LSASS (+ other sensitive targets); exclude known-good by source+access |
| 11 | High | Include sensitive dirs/extensions |
| 12/13 | High | Include persistence keys only |
| 22 | High | Exclude top domains; or rely on DNS server logs |

Target: < 1 EPS average per workstation, higher on servers; measure before rollout.

---

## 6. Tamper Monitoring

- EID 4 (service stopped), EID 16 (config changed) → alert unless change window
- Silent-host alert (no Sysmon events > N min)
- Driver unload (`fltmc unload SysmonDrv`) — watch 4688/1 for `fltmc`, `sc stop sysmon`

---

## 7. Detection Snippets

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1fffff")
| stats count by host SourceImage GrantedAccess CallTrace

index=sysmon EventCode=17 OR EventCode=18
| rex field=PipeName "^\\\\(?<pipe_prefix>[^_\-\d]+)"
| stats count dc(host) as hosts by pipe_prefix Image | where hosts < 3
```

---

## Engagement Cheatsheet

```text
baseline config → targeted includes (10/7/8/17/25/29) → combination excludes → pilot EPS
→ deploy → forward → alert on 4/16/silence → detections on 1/3/10/11/13/22
```

---

## Key References

- Microsoft Sysinternals Sysmon docs; native Sysmon announcement (Windows IT Pro blog, Nov 2025; Insider rollout Feb 2026)
- SwiftOnSecurity/sysmon-config; olafhartong/sysmon-modular; TrustedSec SysmonCommunityGuide
- Related: `defensive-windows-event-logs`, `defensive-hunt-windows`, `defensive-log-sources`
