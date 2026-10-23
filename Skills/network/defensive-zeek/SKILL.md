---
name: defensive-zeek
description: "Zeek network security monitoring (7.x/8.x): sensor deployment and cluster layout, log types and fields (conn, dns, http, ssl, x509, files, smb_files, smb_mapping, dce_rpc, kerberos, ntlm, rdp, ssh, notice, weird, software, known_*), conn_state and history interpretation, zeek-cut and jq analysis, Community ID, packages via zkg (JA4, HASSH, community-id, ja3), Intel framework for IOC matching, writing Zeek scripts for detections, file extraction, and RITA integration. Use when operating Zeek or hunting/investigating with Zeek logs."
---

# Zeek

Zeek turns packets into structured, protocol-aware logs. It answers "who talked to whom, how, and what did they exchange" for every connection — even encrypted ones (metadata, certificates, fingerprints).

## Quick Workflow

1. Deploy on SPAN/TAP; verify no packet loss
2. Enable JSON logs + Community ID + JA4/HASSH packages
3. Load Intel feeds
4. Ship to SIEM (or analyze with zeek-cut/jq)
5. Hunt by protocol log; pivot on `uid` and `community_id`

---

## 1. Deployment

```bash
zkg install zeek/corelight/zeek-community-id
zkg install zeek/foxio/ja4          # JA4+ (check license terms per method)
zkg install zeek/salesforce/hassh
# local.zeek
@load policy/tuning/json-logs.zeek
@load policy/protocols/conn/community-id-logging
@load frameworks/intel/seen
@load frameworks/files/hash-all-files
zeekctl deploy && zeekctl status && zeekctl netstats
```

Zeek 8.0 (Aug 2025) requires ZeroMQ for builds and moves clustering toward the ZeroMQ backend (8.1 completed the Broker transition for cluster comms); customizable connection tuples (e.g., VLAN-aware) are supported. Zeek **9.0** (LTS, Aug/Sep 2026; 9.0.0 observed 2026-10-23) completes the ZeroMQ cluster backend, adds WebSocket integration, a UDP packet source for encapsulated traffic, systemd management of cluster processes, and many security fixes from codebase scans — upgrade; 8.0.x is supported until 9.1. Check `capture_loss.log` and `stats.log` for drops.

---

## 2. Core Logs

| Log | Key fields | Use |
|---|---|---|
| conn.log | `uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, history, community_id` | Every flow |
| dns.log | `query, qtype_name, rcode_name, answers, TTLs` | DGA, tunneling, resolution history |
| http.log | `host, uri, method, user_agent, status_code, resp_mime_types, referrer` | Web C2, downloads |
| ssl.log | `server_name, version, cipher, validation_status, established, ja4` | TLS metadata |
| x509.log | `certificate.subject, issuer, not_valid_before/after, san.dns` | Cert anomalies |
| files.log | `fuid, mime_type, md5/sha1/sha256, source, filename` | File transfers |
| smb_files.log / smb_mapping.log | `path, name, action` / `share_type, path` | ADMIN$/C$ writes, lateral movement |
| dce_rpc.log | `endpoint, operation` | `svcctl CreateServiceW`, `drsuapi DRSGetNCChanges` (DCSync), `atsvc` |
| kerberos.log | `request_type, client, service, cipher, success, error_msg` | RC4 requests, AS-REP without preauth |
| ntlm.log | `username, domainname, hostname, success` | NTLM usage/relay |
| rdp.log, ssh.log | auth, client strings, HASSH | Remote access |
| notice.log | Zeek-generated detections | Scan, intel hits, cert issues |
| weird.log | Protocol anomalies | Evasion, broken stacks |
| software.log / known_*.log | Versions, hosts, services | Asset context |

---

## 3. conn_state & history

| conn_state | Meaning |
|---|---|
| S0 | SYN, no reply (scan / filtered) |
| S1 | Established, not terminated |
| SF | Normal establish + termination |
| REJ | Rejected (RST to SYN) |
| RSTO / RSTR | Reset by originator / responder |
| SH / SHR | Half-open from one side |
| OTH | Midstream, no SYN seen |

`history` letters: `S` SYN, `h` SYN-ACK, `A` ACK, `D` data, `F` FIN, `R` RST; uppercase = originator, lowercase = responder. `ShADadFf` = normal full session.

---

## 4. Analysis Snippets

```bash
# Top destinations by bytes out
zeek-cut id.orig_h id.resp_h orig_bytes < conn.log | awk '{b[$1" "$2]+=$3} END{for(k in b) print b[k],k}' | sort -nr | head
# Long connections
zeek-cut id.orig_h id.resp_h id.resp_p duration < conn.log | awk '$4>3600' | sort -k4 -nr | head
# Scanners (S0/REJ)
zeek-cut id.orig_h conn_state < conn.log | awk '$2=="S0"||$2=="REJ"{c[$1]++} END{for(h in c) print c[h],h}' | sort -nr | head
# Rare user agents
zeek-cut user_agent < http.log | sort | uniq -c | sort -n | head -30
# Self-signed / invalid certs
zeek-cut id.orig_h id.resp_h server_name validation_status < ssl.log | grep -v "ok" | sort | uniq -c | sort -nr | head
# DCSync over the wire
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -i "DRSGetNCChanges"
# Remote service creation
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -iE "svcctl.*(CreateService|StartService)"
# Kerberos RC4
zeek-cut ts id.orig_h client service cipher < kerberos.log | grep -i rc4
```

JSON logs: `jq -c 'select(.service=="ssl" and .duration>3600)' conn.log`.

---

## 5. Intel Framework

```text
#fields	indicator	indicator_type	meta.source	meta.desc
evil-c2.example	Intel::DOMAIN	cti-2026-114	loader C2
203.0.113.50	Intel::ADDR	cti-2026-114	staging server
```

```zeek
@load frameworks/intel/seen
redef Intel::read_files += { "/opt/zeek/share/intel/cti.dat" };
```

Hits appear in `intel.log` with `seen.where` (DNS request, HTTP host, SSL SNI, conn).

---

## 6. Scripted Detection Example

```zeek
@load base/frameworks/notice
module CB;
export { redef enum Notice::Type += { Long_TLS_To_Rare_Host }; }

event connection_state_remove(c: connection)
  {
  if ( c?$ssl && c$duration > 4hr && ! Site::is_local_addr(c$id$resp_h) )
    NOTICE([$note=Long_TLS_To_Rare_Host, $conn=c,
            $msg=fmt("TLS session %s lasted %s", c$id$resp_h, c$duration),
            $identifier=cat(c$id$orig_h, c$id$resp_h)]);
  }
```

Define `Site::local_nets` in `networks.cfg` / `local.zeek` for `is_local_addr` to work.

---

## 7. Pivots

- `uid` joins logs for one connection (conn ↔ http ↔ files ↔ ssl)
- `fuid` joins files.log to extracted files
- `community_id` joins to Suricata alerts and EDR network events

---

## Engagement Cheatsheet

```text
deploy + JSON + community-id + JA4/HASSH → intel feeds → conn (long/volume/S0) → dns → ssl/x509
→ smb/dce_rpc/kerberos/ntlm for lateral & AD → pivot uid/community_id → RITA for beacons
```

---

## Key References

- Zeek docs — https://docs.zeek.org ; Zeek 8.0 release notes (Aug 2025)
- zkg packages — https://packages.zeek.org
- Corelight Zeek cheatsheets; RITA (Active Countermeasures)
- Related: `defensive-hunt-network`, `defensive-security-onion`, `defensive-pcap-analysis`
