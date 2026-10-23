---
name: defensive-pcap-analysis
description: "Packet capture and analysis for incident response and network forensics: capture strategy (tcpdump, dumpcap, Arkime/full PCAP, ring buffers, BPF filters), Wireshark/tshark display filters and statistics (Conversations, Endpoints, Protocol Hierarchy, IO graphs), following streams, exporting objects, TLS decryption with SSLKEYLOGFILE, analyzing DNS, HTTP, TLS, SMB2, Kerberos, NTLM, LDAP, RDP, and ICMP; carving files; NetworkMiner; Zeek/Suricata replay of PCAP; and identifying C2, exfiltration, scanning, and lateral movement in captures. Use when given a PCAP or deciding how to capture traffic."
---

# PCAP Analysis

Start wide (statistics), then narrow (filters), then deep (streams). Let Zeek/Suricata summarize large captures before opening Wireshark.

## Quick Workflow

1. Hash the PCAP; record capture point and time zone
2. `capinfos` → size, duration, link type
3. Summarize: Zeek + Suricata replay; Wireshark Statistics
4. Filter to suspects (hosts, protocols, time)
5. Follow streams; export objects; carve files
6. Extract IOCs; build timeline

---

## 1. Capture

```bash
tcpdump -i eth1 -nn -s 0 -w /cap/edge-%Y%m%d%H%M.pcap -G 3600 -W 48 'not port 22'   # hourly rotation, 48 files
dumpcap -i eth1 -b filesize:1000000 -b files:100 -w /cap/ring.pcapng                 # ring buffer
tcpdump -i eth1 -nn 'host 10.1.2.3 and (port 443 or port 53)' -w host.pcap
```

Full PCAP at scale: Arkime (indexed session search), Security Onion (Suricata PCAP). Capture on SPAN/TAP; check drops (`tcpdump` summary, `ifconfig` RX dropped).

---

## 2. Triage Commands

```bash
capinfos case.pcap
tshark -r case.pcap -q -z io,phs                         # protocol hierarchy
tshark -r case.pcap -q -z conv,ip | head -40              # conversations
tshark -r case.pcap -q -z endpoints,ip | head -40
tshark -r case.pcap -Y dns.flags.response==0 -T fields -e frame.time_utc -e ip.src -e dns.qry.name | sort -k3 | uniq -c -f2 | sort -nr | head
tshark -r case.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.uri -e http.user_agent
tshark -r case.pcap -Y "tls.handshake.type==1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
zeek -Cr case.pcap local                                  # Zeek logs from PCAP
suricata -r case.pcap -l ./suri -S /etc/suricata/rules/suricata.rules
```

---

## 3. Display Filters

| Purpose | Filter |
|---|---|
| Host | `ip.addr == 10.1.2.3` |
| Exclude noise | `!(arp || mdns || ssdp || llmnr || nbns)` |
| HTTP requests / POSTs | `http.request` / `http.request.method == "POST"` |
| HTTP to raw IP | `http.request && http.host matches "^[0-9.]+(:[0-9]+)?$"` |
| DNS query name | `dns.qry.name contains "example"` |
| Long DNS names | `len(dns.qry.name) > 50` |
| NXDOMAIN | `dns.flags.rcode == 3` |
| TLS Client Hello / SNI | `tls.handshake.type == 1` / `tls.handshake.extensions_server_name` |
| TLS without SNI | `tls.handshake.type == 1 && !tls.handshake.extensions_server_name` |
| Certificates | `tls.handshake.type == 11` |
| SYN only (scan) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Resets | `tcp.flags.reset == 1` |
| Retransmissions | `tcp.analysis.retransmission` |
| SMB2 tree connect / create | `smb2.cmd == 3` / `smb2.cmd == 5` |
| ADMIN$ / C$ | `smb2.tree contains "ADMIN$" || smb2.tree contains "C$"` |
| Kerberos TGS-REQ / AS-REQ | `kerberos.msg_type == 12` / `kerberos.msg_type == 10` |
| Kerberos RC4 | `kerberos.etype == 23` |
| NTLM auth | `ntlmssp.messagetype == 0x00000003` |
| LDAP searches | `ldap.protocolOp == 3` |
| DCE/RPC DRSUAPI | `drsuapi` |
| RDP | `rdp || tcp.port == 3389` |
| ICMP large payload | `icmp && data.len > 64` |
| Cleartext creds | `ftp.request.command == "PASS" || pop.request.command == "PASS" || http.authorization` |

---

## 4. Decrypting TLS

- Endpoint you control: set `SSLKEYLOGFILE=/path/keys.log` for browsers/curl; Wireshark → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
- Server RSA private keys decrypt only non-PFS ciphers (rare today)
- Enterprise TLS inspection logs (proxy) often more practical than decryption

---

## 5. Extraction

```bash
tshark -r case.pcap --export-objects http,./http_objs
tshark -r case.pcap --export-objects smb,./smb_objs
tshark -r case.pcap -qz follow,tcp,ascii,12          # stream 12
```

NetworkMiner: automatic host inventory, files, credentials, images. Hash every extracted file; treat as malware.

---

## 6. Pattern Recognition

| Activity | PCAP evidence |
|---|---|
| Beaconing | IO graph spikes at fixed intervals; repeated small TLS/HTTP to same host |
| DNS tunneling | Long high-entropy subdomains; TXT/NULL records; many unique queries to one domain |
| Exfil | Large outbound flows, asymmetric bytes, POST bodies, uploads to cloud storage |
| Port scan | Many SYNs to sequential ports; RST/no reply |
| Lateral SMB | SMB2 tree connect to ADMIN$, `svcctl` DCE/RPC CreateService |
| Kerberoasting | Burst of TGS-REQ for many SPNs with RC4 etype |
| Pass-the-hash / NTLM relay | NTLM AUTHENTICATE from unexpected source to multiple hosts |
| Web exploitation | Suspicious URIs/payloads followed by outbound connections from the server |

---

## 7. Reporting

Include: capture point, time range (UTC), hosts involved, sessions of interest (stream numbers, frame ranges), extracted file hashes, IOCs (defanged), screenshots of key streams, and Zeek/Suricata corroboration.

---

## Engagement Cheatsheet

```text
hash + capinfos → Zeek/Suricata replay → protocol hierarchy/conversations → filter suspects
→ follow streams → export objects → IOCs + timeline
```

---

## Key References

- Wireshark User's Guide & display filter reference; tshark man page
- Arkime — https://arkime.com ; NetworkMiner
- Malware-Traffic-Analysis.net (practice PCAPs)
- Related: `defensive-zeek`, `defensive-suricata-snort`, `defensive-hunt-network`
