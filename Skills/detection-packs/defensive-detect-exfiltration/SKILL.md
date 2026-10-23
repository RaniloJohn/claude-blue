---
name: defensive-detect-exfiltration
description: "Detection pack for MITRE ATT&CK Exfiltration (TA0010): exfiltration over C2 channel, over alternative protocols (FTP, SMTP, DNS, ICMP), over web services and cloud storage (MEGA, rclone to S3/Dropbox/Google Drive/OneDrive, file-sharing sites, Telegram), transfer to cloud accounts, scheduled and size-limited transfers, automated exfiltration, exfil over physical media and Bluetooth, and email exfiltration. Volume and ratio analytics (bytes out vs in), rclone/WinSCP/restic/MEGA tooling detections, cloud cross-account copies and snapshot sharing, DLP integration, FPs. Use when building exfiltration detections or scoping data theft."
---

# Detection Pack — Exfiltration (TA0010)

Modern extortion crews exfiltrate with legitimate tools (rclone, WinSCP, restic, MEGAsync, cloud CLIs) to legitimate services. Detect **tools**, **destinations**, and **volume asymmetry** (bytes out ≫ bytes in).

## Quick Workflow

1. Telemetry: firewall/NetFlow bytes, proxy upload sizes, EDR network + process, cloud audit (sharing, copies), DLP
2. Tool detections (rclone, etc.) at high severity on servers
3. Volume analytics per host/user vs 30-day baseline
4. Cloud-native exfil: snapshot/AMI sharing, cross-account copy, public links
5. Correlate with collection/staging events

---

## 1. Tooling

| Tool | Signal |
|---|---|
| rclone | `rclone.exe` (Go binary — often no PE version info, so rely on cmdline/hash/imphash, not `OriginalFileName`) or cmdline `copy`/`sync` with `--transfers`, `--multi-thread-streams`, remote names (`mega:`, `s3:`); `rclone.conf` file creation; renamed binary (`svchost.exe` with rclone args) |
| MEGAsync / megacmd | Process names, `*.mega.nz`, `*.mega.co.nz`, `*.megaupload` domains |
| WinSCP / pscp / FileZilla | `WinSCP.exe /command "put"`, SFTP to external IPs |
| restic / Rclone-like backup tools | Unexpected repos on external S3-compatible endpoints |
| curl/Invoke-WebRequest upload | `-T`, `--upload-file`, `-F file=@`, `-Method PUT/POST -InFile` |
| Cloud CLIs | `aws s3 cp/sync` to external bucket, `azcopy copy` to foreign account, `gsutil cp` |
| Exfil-as-a-service | StealBit (LockBit), ExMatter — hash/behavior from intel |

```yaml
title: Rclone Exfiltration Indicators
logsource: { product: windows, category: process_creation }
detection:
  name:
    Image|endswith: '\rclone.exe'
  args:
    CommandLine|contains|all: [' copy ', ':']
  args2:
    CommandLine|contains: ['--transfers','--multi-thread-streams','--ignore-existing','--auto-confirm','--no-check-certificate','mega','pcloud','ftp','sftp']
  condition: name or (args and args2)
level: high
tags: [attack.exfiltration, attack.t1567.002]
```

---

## 2. Volume & Ratio Analytics

```spl
index=firewall action=allowed dest_zone=untrust
| bin _time span=1h
| stats sum(bytes_out) as out sum(bytes_in) as in dc(dest_ip) as dests by src_ip _time
| eval ratio=round(out/(in+1),2), out_mb=round(out/1048576,1)
| where out_mb > 500 AND ratio > 5
| lookup asset_inventory ip as src_ip OUTPUT role owner
```

```kql
DeviceNetworkEvents   // where EDR exposes bytes, otherwise use firewall/NetFlow tables
| where RemoteIPType == "Public"
| summarize Conns = count() by DeviceName, RemoteUrl, InitiatingProcessFileName, bin(Timestamp, 1h)
| join kind=inner (DeviceInfo | where DeviceType == "Server" | distinct DeviceName) on DeviceName
| where InitiatingProcessFileName !in~ ("MsSense.exe","svchost.exe")
```

Baseline approach: per-host 30-day p95 of outbound bytes/hour; alert at > 3× p95 for servers, > 5× for workstations. Server-to-internet uploads to never-before-seen destinations are the highest-yield signal.

---

## 3. Alternative Protocols (T1048)

| Protocol | Signal |
|---|---|
| DNS | Large total query bytes per host per parent domain; see C2 pack |
| ICMP | Echo payloads > 64 bytes, high ICMP volume to one external host |
| FTP/SFTP | Outbound 21/22 from servers to non-partner IPs; Zeek `ftp.log` STOR |
| SMTP | Large attachments to personal webmail/external domains; auto-forward; unusual SMTP from non-mail servers (port 25/587 egress) |
| HTTP PUT/POST large bodies | Proxy `request_body_len` (Zeek `http.log`) > 10 MB to rare domains |

```bash
zeek-cut ts id.orig_h id.resp_h host method request_body_len < http.log | awk '$5 ~ /POST|PUT/ && $6 > 10000000'
```

---

## 4. Cloud-Native Exfiltration (T1537, T1567)

| Platform | Signal |
|---|---|
| AWS | `ModifySnapshotAttribute`/`ModifyDBSnapshotAttribute` adding external account or `all`; `ModifyImageAttribute`; `PutBucketPolicy`/`PutBucketAcl` granting public/external; S3 replication to foreign account (`PutBucketReplication`); `CreateExportTask` (CW logs), `StartExportTask` (RDS) |
| Azure | Disk `beginGetAccess` (SAS export), storage account SAS generation, `listKeys`, public blob access enable, AzCopy to external |
| GCP | `storage.setIamPermissions` with `allUsers`, snapshot/image sharing to external projects, BigQuery `extract` jobs to external buckets |
| M365/Workspace | Anonymous sharing links (`AnonymousLinkCreated`), sharing to external domains, mass downloads to unmanaged devices, Google Takeout |
| SaaS (Snowflake, Salesforce) | Large query exports / `COPY INTO @external_stage`, Data Loader exports, report exports |

---

## 5. Physical & Other

USB mass storage writes (Defender `UsbDriveMounted` + file copies), Bluetooth file transfer (`fsquirt.exe`), printing volume, personal email uploads, AirDrop (macOS), screenshots to personal cloud — see `defensive-detect-exfiltration`, `defensive-windows-hardening`.

---

## 6. False Positives

Backups (Veeam, Commvault, cloud backup agents), sanctioned sync clients, software distribution, video conferencing, developers pushing large artifacts, log shipping. Maintain an approved-egress list (destination + process + host group).

---

## 7. Response

1. Block destination (firewall, proxy, DNS) and kill process
2. Identify data volume and content (proxy logs, rclone logs/config `rclone.conf` remotes, staging archives)
3. Preserve evidence for breach notification analysis → `defensive-incident-response`
4. Revoke the attacker's cloud destination (abuse reports to provider)

---

## Engagement Cheatsheet

```text
tool rules (rclone/MEGA/WinSCP/restic/cloud CLIs) → bytes out vs in ratio + 3×p95 baseline → server→new destination uploads
→ DNS/ICMP/FTP/SMTP/large POST → cloud snapshot/AMI/bucket policy/SAS/anon links → USB/print → block + quantify + breach assessment
```

---

## Key References

- MITRE ATT&CK TA0010; CISA #StopRansomware advisories (rclone/MEGA patterns)
- Related: `defensive-detect-collection`, `defensive-ransomware-response`, `defensive-incident-response`, `defensive-netflow-ndr`
