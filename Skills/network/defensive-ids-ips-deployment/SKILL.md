---
name: defensive-ids-ips-deployment
description: "Network IDS/IPS deployment and operations: sensor placement (edge inside/outside, DMZ, data center core, IT/OT boundary, cloud), passive (TAP/SPAN) vs inline (af-packet IPS, NFQ, bridged) modes, fail-open vs fail-closed bypass, sizing and packet drop monitoring, Suricata 8 and Snort 3 configuration, ruleset management (ET Open/Pro, Talos, custom) with suricata-update and PulledPork3, rule tuning and suppression/threshold, HOME_NET accuracy, TLS-encrypted traffic limits, EVE JSON to SIEM, NIST SP 800-94 guidance, and health metrics. Use when deploying, sizing, tuning, or troubleshooting a network IDS/IPS."
---

# IDS/IPS Deployment & Operations

Signature writing lives in `defensive-suricata-snort`. This skill is about **getting packets to the sensor, keeping it healthy, and keeping alerts useful**.

## Quick Workflow

1. Choose placement and mode per chokepoint (§1–2)
2. Size hardware for peak throughput; plan capture method
3. Configure HOME_NET/EXTERNAL_NET, outputs (EVE JSON), and rulesets
4. Run IDS mode → baseline → tune → selectively enable IPS drop
5. Monitor drops, rule load, and alert volume continuously

---

## 1. Placement

| Location | Sees | Value |
|---|---|---|
| Outside edge firewall | All internet noise | Low (mostly scans); useful for edge exploit attempts |
| Inside edge firewall | Allowed traffic in/out | High — C2, exploitation of exposed services, egress |
| DMZ | Traffic to public services | High for web/mail exploitation |
| Data center core / east-west | Lateral movement | High (SMB, RPC, Kerberos anomalies) |
| IT/OT boundary | OT conduit traffic | Critical for ICS |
| Cloud | Mirrored VPC traffic / AWS Network Firewall / Azure Firewall IDPS | Workload protection |

---

## 2. Modes

| Mode | Pros | Cons |
|---|---|---|
| Passive IDS via TAP | No impact on traffic; full-duplex copy | Can't block |
| Passive via SPAN | Cheap | Drops under load, may miss errors/VLAN tags |
| Inline IPS (af-packet copy-mode ips, bridge) | Blocks in real time | Latency, failure risk — needs bypass |
| Inline NFQ (Linux netfilter) | Integrates with iptables/nftables | Lower throughput |
| Firewall-integrated IPS | Single box | Vendor rule control limits |

**Bypass:** hardware bypass NICs or bypass TAPs for fail-open; decide fail-open (availability) vs fail-closed (security) per segment and document it.

---

## 3. Suricata Configuration Essentials

```yaml
# suricata.yaml (excerpts)
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
af-packet:
  - interface: ens1f0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 200000
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types: [alert, anomaly, http, dns, tls, files, smtp, flow, stats]
```

Inline IPS with af-packet: pair interfaces with `copy-mode: ips` and `copy-iface:` on each side.

```bash
suricata -T -c /etc/suricata/suricata.yaml -v        # test config
suricata-update update-sources && suricata-update enable-source et/open && suricata-update
suricatasc -c "ruleset-reload-nonblocking"
suricatasc -c "dump-counters" | jq '.message.capture'  # kernel_packets / kernel_drops
```

Snort 3:

```bash
snort -c /usr/local/etc/snort/snort.lua -T
snort -c snort.lua -i ens1f0 -A alert_json -l /var/log/snort -k none
pulledpork3 -c pulledpork.conf    # ruleset management
```

---

## 4. Tuning

| Technique | Use |
|---|---|
| Disable irrelevant categories | e.g., games, chat, policy rules not applicable |
| `threshold.config` suppress | `suppress gen_id 1, sig_id 2013028, track by_src, ip 10.1.5.20` for known scanners |
| `disable.conf`/`modify.conf` (suricata-update) | Persist tuning across updates |
| Accurate HOME_NET | Wrong HOME_NET inverts direction-based rules |
| Policy-based drop | Only switch high-confidence rules to `drop` in IPS (e.g., ET EXPLOIT with low FP history) |
| Feedback loop | Each FP closed in SIEM produces a tuning entry with ticket |

---

## 5. Health Metrics

| Metric | Target |
|---|---|
| Capture drop rate (`capture.kernel_drops / kernel_packets`) | < 0.1% |
| Rules loaded / failed | 0 failed after updates |
| Alert volume per day per sensor | Stable; spikes investigated |
| Sensor uptime / EVE output lag | Alert if no events for 15 min |
| Decoder anomalies | Indicate SPAN issues, asymmetric routing, MTU problems |

---

## 6. Encrypted Traffic

Signatures can't see inside TLS 1.3 payloads. Compensate with: TLS metadata rules (SNI, JA3/JA4 hashes, certificate fields), DNS rules, flow analytics, selective decryption at proxy/NGFW, and endpoint telemetry.

---

## 7. Cloud Options

AWS VPC Traffic Mirroring → Suricata on EC2/NLB, AWS Network Firewall (Suricata rule syntax), Azure Firewall Premium IDPS, GCP Cloud IDS / Cloud NGFW Enterprise.

---

## Engagement Cheatsheet

```text
placement (inside edge, DMZ, DC core, IT/OT, cloud) → TAP vs SPAN vs inline + bypass decision → size for peak
→ HOME_NET + EVE JSON + community-id → ET/Talos rules via suricata-update/PulledPork3 → IDS baseline → tune → selective drop
→ monitor drops < 0.1%, rule load, EVE lag → TLS metadata compensations
```

---

## Key References

- NIST SP 800-94 (Guide to IDPS); Suricata 8.0 docs; Snort 3 docs; Emerging Threats; Talos rules
- Related: `defensive-suricata-snort`, `defensive-security-onion`, `defensive-network-security-architecture`, `defensive-netflow-ndr`
