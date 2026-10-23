---
name: defensive-suricata-snort
description: "Network IDS/IPS signature engineering and operations for Suricata (7.x/8.x) and Snort 3. Use when writing or tuning Suricata/Snort rules, using sticky buffers (http.uri, http.host, http.user_agent, tls.sni, dns.query, ja4.hash), flow/flowbits/xbits, thresholds and suppress, datasets, transforms (from_base64, entropy), Lua; deploying ET Open / Talos rulesets with suricata-update; analyzing eve.json alerts; running IPS mode; Suricata 8 firewall mode; and validating rules with suricata -T."
---

# Suricata & Snort Signatures

Network signatures detect what crosses the wire. Encrypted traffic limits payload matching — lean on TLS metadata, DNS, and flow behavior.

## Quick Workflow

1. Identify protocol and the most specific buffer
2. Write rule with `flow` direction and a fast-pattern content
3. Add precision (pcre, byte tests) only after a content anchor
4. Threshold noisy rules
5. Validate (`suricata -T`) and replay PCAP
6. Tune with suppress, not by disabling

---

## 1. Rule Anatomy (Suricata)

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"CB MALWARE Possible Loader Check-in URI";
  flow:established,to_server;
  http.method; content:"POST";
  http.uri; content:"/gate.php"; endswith;
  http.user_agent; content:"Mozilla/4.0"; startswith;
  http.request_body; content:"id="; depth:3;
  classtype:trojan-activity;
  metadata:mitre_technique_id T1071.001, created_at 2026_10_23;
  reference:url,attack.mitre.org/techniques/T1071/001/;
  sid:9000101; rev:1;)
```

Action: `alert | pass | drop | reject | rejectsrc | rejectdst | rejectboth`. Header: `proto src_ip src_port -> dst_ip dst_port`.

---

## 2. Sticky Buffers (Suricata)

| Protocol | Buffers |
|---|---|
| HTTP | `http.method`, `http.uri`, `http.uri.raw`, `http.host`, `http.user_agent`, `http.request_header`, `http.request_body`, `http.stat_code`, `http.response_body`, `file.data` |
| TLS | `tls.sni`, `tls.cert_subject`, `tls.cert_issuer`, `tls.cert_serial`, `tls.cert_fingerprint`, `ja3.hash`, `ja4.hash` (build-dependent) |
| DNS | `dns.query`, `dns.opcode`, `dns.rrtype` (8.x adds more DNS keywords) |
| SMB | `smb.named_pipe`, `smb.share` |
| SSH | `ssh.software`, `ssh.proto`, `ssh.hassh` |
| Kerberos | `krb5.cname`, `krb5.sname`, `krb5_msg_type`, `krb5_err_code` |
| Others | `ldap.*` (8.x), `mqtt.*`, `snmp.*`, `quic.sni`, `websocket.*` (8.x), `pgsql.query` (8.x) |

Suricata 8.0 (July 2025) "log/detect parity": if a field is logged in EVE, a keyword exists to match it. New transforms/keywords include `from_base64`, `entropy`, `luaxform`, `requires`, and datasets with JSON enrichment (`datajson`).

---

## 3. Precision & Performance

- Every rule needs a `content` usable as fast pattern; set `fast_pattern` on the rarest
- Use `startswith`/`endswith`/`bsize` instead of pcre when possible
- `flow:established,to_server` on TCP application rules
- pcre last, anchored, after content
- Avoid `any any -> any any` rules without protocol keywords

---

## 4. State Tracking

```text
# Mark host that downloaded an EXE, alert if it then beacons
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"CB EXE download"; flow:established,to_client; file.data; content:"MZ"; depth:2; flowbits:noalert; xbits:set,cb.exe_dl,track ip_dst,expire 3600; sid:9000201; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"CB TLS to rare SNI after EXE download"; flow:established,to_server; xbits:isset,cb.exe_dl,track ip_src; tls.sni; dataset:isnotset,top_sni,type string,load top_sni.lst; sid:9000202; rev:1;)
```

---

## 5. Thresholds & Suppression

```text
# In rule
threshold:type both, track by_src, count 20, seconds 60;
detection_filter:track by_src, count 50, seconds 60;

# threshold.config
suppress gen_id 1, sig_id 2024897, track by_src, ip 10.20.0.0/16
threshold gen_id 1, sig_id 2010935, type limit, track by_src, count 1, seconds 3600
```

---

## 6. Operations

```bash
suricata-update                                   # fetch ET Open + enabled sources
suricata-update enable-source et/open
suricata -T -c /etc/suricata/suricata.yaml -v     # validate config + rules
suricata -r capture.pcap -S local.rules -l ./out  # replay PCAP
suricatasc -c reload-rules                        # live reload
```

EVE analysis:

```bash
jq -c 'select(.event_type=="alert") | {ts:.timestamp,src:.src_ip,dst:.dest_ip,sig:.alert.signature,sid:.alert.signature_id}' eve.json
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -nr | head
jq -r 'select(.event_type=="tls") | .tls.sni' eve.json | sort | uniq -c | sort -n | head   # rare SNI
jq -r 'select(.event_type=="dns" and .dns.type=="query") | .dns.rrname' eve.json | awk 'length>50' | head
```

IPS: `af-packet` inline or NFQUEUE; test `drop` rules in `alert` first. Suricata 8 firewall mode is experimental — not for production policy enforcement yet.

---

## 7. Snort 3 Differences

| Area | Snort 3 |
|---|---|
| Buffers | `http_uri;`, `http_header;`, `http_user_agent;` (sticky, Snort 3 syntax) |
| Config | Lua (`snort.lua`) |
| Service | `service:http;` to bind rule to app-layer regardless of port |
| Rulesets | Talos Community / Registered / Subscriber; `pulledpork3` |

```text
alert http (msg:"CB POLICY PowerShell UA"; flow:established,to_server; http_user_agent; content:"WindowsPowerShell",nocase; service:http; classtype:policy-violation; sid:9000301; rev:1;)
```

---

## 8. Starter Detections

```text
alert dns $HOME_NET any -> any any (msg:"CB DNS long label possible tunneling"; dns.query; pcre:"/^[a-z0-9]{50,}\./i"; threshold:type both,track by_src,count 20,seconds 60; classtype:bad-unknown; sid:9000401; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"CB TLS SNI on dynamic DNS"; tls.sni; pcre:"/\.(duckdns\.org|no-ip\.(com|org)|ddns\.net)$/i"; classtype:policy-violation; sid:9000402; rev:1;)
alert smb any any -> $HOME_NET 445 (msg:"CB SMB PSEXESVC pipe"; flow:established,to_server; smb.named_pipe; content:"PSEXESVC"; nocase; classtype:attempted-admin; sid:9000403; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CB HTTP request to raw IP with EXE"; flow:established,to_server; http.host; pcre:"/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/"; http.uri; content:".exe"; endswith; classtype:trojan-activity; sid:9000404; rev:1;)
```

Local SID range: use 9,000,000+ (or your allocated range); never collide with ET (2,000,000–2,999,999) or Talos ranges.

---

## Engagement Cheatsheet

```bash
vi local.rules && suricata -T -c suricata.yaml -S local.rules && \
suricata -r test.pcap -S local.rules -l out && jq 'select(.event_type=="alert")' out/eve.json
```

---

## Key References

- Suricata docs (8.0) — https://docs.suricata.io ; Suricata 8.0.0 release notes (July 2025)
- Emerging Threats Open ruleset — https://rules.emergingthreats.net
- Snort 3 docs — https://docs.snort.org
- JA4+ (FoxIO) — JA4 is BSD-licensed; other JA4+ methods carry FoxIO license terms
- Related: `defensive-zeek`, `defensive-pcap-analysis`, `defensive-hunt-network`
