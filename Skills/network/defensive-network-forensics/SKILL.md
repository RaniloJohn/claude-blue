---
name: defensive-network-forensics
description: "Network forensics and full packet capture operations: capture architecture (Arkime, Stenographer, tcpdump/dumpcap ring buffers, Security Onion), evidence handling and hashing of PCAPs, session reconstruction, file carving (NetworkMiner, Zeek file extraction, tshark export-objects), protocol forensics (HTTP, DNS, SMB, Kerberos, TLS metadata, SMTP), decrypting TLS with key logs, reconstructing attacker activity and exfil volumes, timeline correlation with Zeek/flow/EDR, Zui/Brim, and reporting findings. Use when investigating an incident with packet captures or setting up a PCAP retention capability."
---

# Network Forensics

Packets are the ground truth of what crossed the wire. Use them to confirm exploitation, recover payloads and exfiltrated files, and quantify data loss. Interactive Wireshark technique is in `defensive-pcap-analysis`; this skill covers **capture capability, evidence handling, and investigation workflow**.

## Quick Workflow

1. Preserve: copy relevant PCAP ranges, hash, record chain of custody
2. Index: Zeek logs + Suricata alerts over the PCAP for fast triage
3. Scope: identify hosts, sessions, and time windows of interest
4. Reconstruct: sessions, files, credentials, commands
5. Quantify: bytes and objects transferred
6. Correlate with endpoint and log timelines; report

---

## 1. Capture Capability

| Tool | Use |
|---|---|
| Arkime (formerly Moloch) | Indexed full PCAP with web UI, session search, PCAP export |
| Stenographer | High-speed PCAP to disk with time/BPF retrieval (removed from Security Onion 3.x, which uses Suricata PCAP) |
| Suricata PCAP logging | `pcap-log` output with conditional/ring capture (Security Onion 3.x default) |
| dumpcap / tcpdump ring buffer | Ad hoc or small sites |
| Packet broker + slicing | Keep headers + first N bytes to extend retention |
| Cloud | VPC Traffic Mirroring / Azure vTAP / GCP Packet Mirroring to capture instances |

```bash
# Ring buffer: 100 files × 1 GB, rotate
dumpcap -i ens1f0 -b filesize:1000000 -b files:100 -w /pcap/edge.pcapng
# Targeted capture during incident
tcpdump -i ens1f0 -s 0 -w /evidence/case42_host10.pcap 'host 10.1.1.10'
```

Retention planning: TB/day ≈ average Gbps × 10.8 (1 Gbps = 125 MB/s × 86,400 s). Size for average, not peak, then add 20% headroom.

---

## 2. Evidence Handling

```bash
sha256sum case42_host10.pcap > case42_host10.pcap.sha256
capinfos case42_host10.pcap            # time range, packet count, drops
editcap -A "2026-10-20 13:00:00" -B "2026-10-20 15:00:00" big.pcap window.pcap   # extract window
mergecap -w merged.pcapng sensor1.pcap sensor2.pcap
```

Record: sensor, interface, capture filter, time source (NTP), drops, who collected, hashes. Work only on copies.

---

## 3. Triage Indexing

```bash
zeek -C -r window.pcap local "Site::local_nets += { 10.0.0.0/8 }"      # conn, dns, http, ssl, files, smb, kerberos, ...
suricata -r window.pcap -k none -l ./suri/                             # alerts against current rules (retro-detection)
```

Load into Zui (Brim) or Security Onion for searching; pivot with Community ID.

---

## 4. Reconstruction

| Task | Command |
|---|---|
| Follow a TCP stream | `tshark -r window.pcap -q -z follow,tcp,ascii,12` |
| Export HTTP/SMB/IMF/TFTP objects | `tshark -r window.pcap --export-objects http,./http_objs` (also `smb`, `imf`, `tftp`, `dicom`) |
| Zeek file extraction | `zeek -r window.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek` |
| Carve with NetworkMiner | Files, images, credentials, hosts view (GUI) |
| DNS queries by host | `tshark -r window.pcap -Y "dns.flags.response==0 && ip.src==10.1.1.10" -T fields -e frame.time -e dns.qry.name` |
| Kerberos principals | `tshark -r window.pcap -Y kerberos -T fields -e kerberos.CNameString -e kerberos.SNameString -e kerberos.etype` |
| SMB file operations | Zeek `smb_files.log`; `tshark -Y "smb2.cmd==5" -T fields -e smb2.filename` |
| Credentials in clear text | `tshark -r window.pcap -Y "http.authorization || ftp.request.command==\"PASS\" || pop.request.command==\"PASS\""` |
| TLS metadata | `tshark -Y "tls.handshake.type==1" -T fields -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja4` (field availability depends on Wireshark version) |

### Decrypting TLS

Only possible with session keys: `SSLKEYLOGFILE` from a controlled client, server private key for non-PFS RSA key exchange (legacy), or keys exported from a TLS-inspection proxy.

```bash
tshark -r window.pcap -o tls.keylog_file:sslkeys.log -Y http2 -T fields -e http2.header.value
```

---

## 5. Quantifying Exfiltration

```bash
# Bytes from internal host to a destination
tshark -r window.pcap -q -z conv,ip | grep 203.0.113.50
zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes < conn.log | awk '$2=="203.0.113.50"{o+=$3} END{print o/1048576 " MB out"}'
```

Report bytes **sent by the victim** (orig_bytes when the victim initiated), protocol, destination, time range, and any recovered file names — evidence for breach notification decisions.

---

## 6. Correlation

| Source | Join key |
|---|---|
| EDR network events | Community ID, or 5-tuple ± few seconds |
| Firewall/NAT logs | Translate public ↔ private IP:port |
| Proxy logs | User identity for web sessions |
| DHCP logs | IP → MAC → hostname at that time |
| Zeek | uid / Community ID |

---

## Engagement Cheatsheet

```text
preserve copy + sha256 + capinfos + custody → editcap time window → Zeek + Suricata retro index → scope hosts/sessions
→ follow streams / export-objects / Zeek extract / NetworkMiner → DNS/Kerberos/SMB/creds/TLS metadata → keylog decrypt if possible
→ quantify orig_bytes → correlate (Community ID, NAT, DHCP, proxy) → report
```

---

## Key References

- Arkime; Stenographer; Wireshark/tshark docs; Zeek; NetworkMiner; Zui
- SANS FOR572 (Advanced Network Forensics) topics
- Related: `defensive-pcap-analysis`, `defensive-zeek`, `defensive-netflow-ndr`, `defensive-timeline-analysis`, `defensive-incident-response`
