---
name: defensive-detect-command-and-control
description: "Detection pack for MITRE ATT&CK Command and Control (TA0011): beaconing (interval/jitter analysis), web protocols HTTP/S C2 and malleable profiles, DNS C2 and tunneling, DoH, protocol tunneling (SSH, ngrok, Cloudflare Tunnel, Tailscale, chisel, frp), proxies and multi-hop, domain fronting and CDN abuse, web services C2 (Telegram, Discord, Slack, GitHub, Google, OneDrive, Pastebin), remote access software/RMM abuse, non-standard ports, encrypted channels, JA3/JA4/JA4S/JA4X fingerprinting, TLS certificate anomalies, newly registered and DGA domains, and ingress tool transfer. Zeek/Suricata/proxy/DNS/EDR detections, RITA, FPs. Use when building C2 detections."
---

# Detection Pack — Command and Control (TA0011)

C2 must talk regularly to something outside. Detect **regularity** (beaconing), **rarity** (few hosts contact the destination), **newness** (young domains, new certs), and **protocol misuse** (DNS carrying data, TLS fingerprints of known frameworks).

## Quick Workflow

1. Telemetry: DNS logs (resolver/Sysmon 22/Zeek dns), proxy/firewall/Zeek conn+ssl+http, EDR network events
2. Run beacon analytics daily (RITA or SIEM query)
3. Enrich destinations: domain age, prevalence, ASN, reputation, JA4/JA4S
4. Alert on RMM/tunnel tools not on allowlist

---

## 1. Beaconing

```kql
// Defender: periodic connections (low coefficient of variation in inter-arrival time)
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| serialize
| extend prevTs = prev(Timestamp), prevKey = prev(strcat(DeviceName, RemoteIP))
| where prevKey == strcat(DeviceName, RemoteIP)
| extend Delta = datetime_diff('second', Timestamp, prevTs)
| summarize Conns = count(), Avg = avg(Delta), Sd = stdev(Delta), Proc = any(InitiatingProcessFileName), Url = any(RemoteUrl) by DeviceName, RemoteIP
| where Conns > 50 and Avg > 10
| extend CV = Sd / Avg
| where CV < 0.2
| sort by CV asc
```

RITA (Zeek logs):

```bash
rita import --database=today --logs=/opt/zeek/logs/current
rita view today          # beacons, long connections, DNS tunneling, threat intel hits
```

Long-lived connections (> 1 h) to rare external IPs: Zeek `conn.log` `duration`.

---

## 2. DNS C2 / Tunneling (T1071.004, T1572)

| Signal | Threshold idea |
|---|---|
| Long query names | Subdomain label length > 50 or FQDN > 100 |
| High entropy labels | Shannon entropy > 4 on subdomain |
| Many unique subdomains per parent | > 200 unique subdomains / domain / host / hour |
| TXT/NULL/CNAME heavy | TXT ratio for a host far above baseline |
| NXDOMAIN storms | DGA: many NXDOMAIN for random-looking names |
| DoH to non-sanctioned resolvers | TLS SNI `dns.google`, `cloudflare-dns.com`, `mozilla.cloudflare-dns.com` from non-browser processes |

```spl
index=zeek sourcetype=zeek_dns
| rex field=query "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"
| eval sublen=len(sub)
| bin _time span=1h
| stats dc(sub) as uniq max(sublen) as maxlen count by id.orig_h parent _time
| where uniq > 200 OR maxlen > 50
```

---

## 3. TLS / HTTP Fingerprints

| Signal | Source |
|---|---|
| JA4 / JA4S / JA4X matching known C2 (Cobalt Strike, Sliver, Havoc, Mythic, Brute Ratel) | Zeek JA4 package, Suricata `ja4.hash`, NDR |
| Self-signed or default certs (e.g., Cobalt Strike default serial `8BB00EE`), short validity, mismatched CN | Zeek `x509.log` |
| Non-browser process with browser User-Agent | EDR network + proxy UA |
| Rare UA strings fleet-wide | Proxy logs, prevalence < 3 hosts |
| HTTP POST to same URI at intervals with small bodies | Proxy |
| Domain fronting: SNI ≠ HTTP Host | TLS inspection proxy |

```yaml
title: Non-Browser Process Contacting Newly Observed Domain
logsource: { product: windows, category: dns_query }
detection:
  sel:
    Image|endswith: ['\rundll32.exe','\regsvr32.exe','\mshta.exe','\powershell.exe','\certutil.exe','\msbuild.exe','\installutil.exe','\wscript.exe','\cscript.exe']
  filter_ms:
    QueryName|endswith: ['.microsoft.com','.windowsupdate.com','.office.com']
  condition: sel and not filter_ms
level: medium
tags: [attack.command-and-control, attack.t1071.001]
```

Join with domain age (WHOIS/RDAP or passive DNS) < 30 days → high.

---

## 4. Tunnels, Proxies, Web Services, RMM

| Category | Examples / signal |
|---|---|
| Reverse tunnels (T1572) | `ngrok`, `cloudflared tunnel`, `tailscale up`, `chisel`, `frpc`, `ligolo-ng`, `plink -R`, `ssh -R/-D` from servers |
| Proxies (T1090) | SOCKS on unusual ports, `netsh interface portproxy add`, Tor (`tor.exe`, known guard IPs) |
| Web services (T1102) | Process (non-browser) to `api.telegram.org`, `discord.com/api/webhooks`, `hooks.slack.com`, `raw.githubusercontent.com`, `pastebin.com`, `graph.microsoft.com` from scripts |
| RMM (T1219) | AnyDesk, ScreenConnect, TeamViewer, Atera, Splashtop, NetSupport, MeshCentral, SimpleHelp — allowlist only sanctioned; LOLRMM domains feed |
| Non-standard port (T1571) | HTTP/TLS on odd ports; Zeek `service` vs `id.resp_p` mismatch |

```spl
index=proxy OR index=dns (dest_host IN ("*.ngrok.io","*.ngrok-free.app","*.trycloudflare.com","*.tailscale.com","*.anydesk.com","*.screenconnect.com","*.teamviewer.com","api.telegram.org","discord.com"))
| lookup sanctioned_remote_tools host as src OUTPUT approved
| where isnull(approved)
| stats count values(dest_host) by src user
```

---

## 5. Ingress Tool Transfer (T1105)

`certutil -urlcache -f`, `bitsadmin /transfer`, `curl`/`wget` on Windows servers, `Invoke-WebRequest -OutFile`, `iwr | iex`, Linux `curl … | sh`, new executables written by browsers/Office/scripts then executed (Sysmon 11 → 1 same path). Suricata ET rules for EXE downloads over HTTP.

---

## 6. Suricata Examples

```text
alert dns $HOME_NET any -> any any (msg:"Possible DNS tunneling long label"; dns.query; pcre:"/^[a-z0-9]{50,}\./i"; threshold:type both, track by_src, count 20, seconds 60; sid:9100001; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"TLS to ngrok tunnel"; tls.sni; dotprefix; content:".ngrok-free.app"; endswith; sid:9100002; rev:1;)
```

---

## 7. False Positives

Telemetry agents, update checkers, NTP, AV cloud lookups, Teams/Zoom keepalives, CDNs, monitoring probes all beacon. Tune with fleet prevalence (destinations seen on > 20% of hosts are rarely C2), known-good process+destination pairs, and vendor domain lists.

---

## Engagement Cheatsheet

```text
beacon CV < 0.2 + long conns (RITA) → DNS len/entropy/unique-subs/NXDOMAIN/DoH → JA4/JA4S/x509 anomalies → rare UA/non-browser procs
→ domain age < 30d → tunnels/RMM/web-service C2 vs allowlist → ingress transfer → prevalence-based tuning
```

---

## Key References

- MITRE ATT&CK TA0011; Active Countermeasures RITA; FoxIO JA4+; LOLRMM; abuse.ch ThreatFox
- Related: `defensive-hunt-network`, `defensive-zeek`, `defensive-dns-security`, `defensive-netflow-ndr`, `defensive-proxy-tls-inspection`
