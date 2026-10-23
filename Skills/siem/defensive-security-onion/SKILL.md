---
name: defensive-security-onion
description: "Security Onion and open-source NSM/SIEM stack operations: deployment types (import, eval, standalone, distributed), sensor placement and SPAN/TAP, Suricata + Zeek + Strelka + Elastic stack, SOC UI (Alerts, Dashboards, Hunt, Cases, PCAP, Detections module for Sigma/Suricata/YARA), full packet capture retrieval, Elastic Agent endpoint ingest, Graylog as alternative log platform, and building low-cost SOC labs. Use for Security Onion builds, NSM sensor design, PCAP-backed investigations, and student/home SOC labs."
---

# Security Onion & Open-Source NSM

Security Onion packages network security monitoring (Suricata alerts, Zeek metadata, full PCAP, Strelka file analysis) with Elastic storage and an analyst SOC UI. Its strength is pivoting from alert → metadata → packets in one place.

## Quick Workflow

1. Choose deployment type and size sensor for link speed
2. Place sensors on SPAN/TAP with full visibility (pre-NAT where possible)
3. Define HOME_NET; tune Suricata rules
4. Ingest endpoint logs via Elastic Agent
5. Triage in Alerts → pivot to Hunt/Dashboards → PCAP
6. Track work in Cases

---

## 1. Deployment Types (2.4.x)

| Type | Use |
|---|---|
| Import | Analyze PCAP/EVTX offline — training, IR on captured data |
| Evaluation | Single box, quick trial |
| Standalone | Single box production for small sites |
| Distributed | Manager + search nodes + forward (sensor) nodes |

Sizing: memory and disk dominate — PCAP retention is a function of link utilization × disk. Use dedicated capture NIC(s) with no IP.

---

## 2. Sensor Placement

| Location | Sees |
|---|---|
| Internet egress (inside firewall) | Outbound C2, exfil — internal IPs preserved |
| DMZ | Attacks on exposed services |
| Core / data center | East-west lateral movement |
| Critical segment (OT, PCI) | Segment-specific threats |

Prefer TAPs over SPAN for fidelity at high load. Verify both directions are visible (asymmetric routing breaks Zeek/Suricata flow state).

---

## 3. Components

| Component | Output |
|---|---|
| Suricata | Alerts (ET Open default; ETPRO optional), protocol metadata, file extraction; also handles PCAP capture in 2.4 |
| Zeek | conn, dns, http, ssl, x509, files, smb, kerberos, notice logs |
| Strelka | Recursive file scanning (YARA, metadata) on extracted files |
| Elastic stack | Storage/search |
| SOC UI | Alerts, Dashboards, Hunt, Cases, PCAP, Grid, Detections |
| Elastic Agent | Endpoint and log ingest (Windows, Linux, Sysmon) |

---

## 4. SOC UI Workflow

1. **Alerts**: group by rule name → acknowledge/escalate
2. **Hunt**: OQL queries (Onion Query Language), pivot on `network.community_id` to join Suricata alert ↔ Zeek conn ↔ PCAP
3. **PCAP**: retrieve packets for the flow; download for Wireshark
4. **Cases**: attach observables, events, notes; export
5. **Detections**: manage Sigma (ElastAlert), Suricata, and YARA (Strelka) rules from the UI; tune/disable per rule

Community ID (`1:base64hash`) is the join key across Zeek, Suricata, and many EDRs — use it.

Example Hunt queries:

```text
event.dataset:zeek.dns AND dns.query.name:*.duckdns.org | groupby source.ip dns.query.name
event.dataset:zeek.conn AND connection.duration:>3600 | groupby source.ip destination.ip destination.port
event.dataset:zeek.ssl AND ssl.validation_status:"self signed certificate" | groupby destination.ip ssl.server_name
```

---

## 5. Tuning

- Set `HOME_NET`/`EXTERNAL_NET` accurately or directional rules misfire
- Disable rule categories irrelevant to environment; threshold noisy SIDs
- BPF filters to exclude backup/replication traffic from capture
- Monitor packet loss (Grid page / `so-status`); loss >1% invalidates conclusions

---

## 6. Import Mode for IR/Training

```bash
sudo so-import-pcap /path/capture.pcap
sudo so-import-evtx /path/Security.evtx
```

Imported data is searchable with original timestamps — set Hunt time range accordingly.

---

## 7. Graylog (Alternative Log Platform)

| Element | Notes |
|---|---|
| Inputs | Syslog, GELF, Beats, Raw/TCP |
| Streams | Route messages by rules |
| Pipelines | Rule language for parsing/enrichment |
| Search | Lucene-like syntax: `source:dc01 AND EventID:4625` |
| Alerts | Event definitions (filter + aggregation) |
| Storage | OpenSearch / Graylog Data Node |

Graylog fits log centralization; pair with Zeek/Suricata for NSM if not using Security Onion.

---

## 8. Lab Build Pattern (student/home SOC)

```text
Hypervisor (VMware/Proxmox)
├── Security Onion standalone (2 NICs: mgmt + promiscuous capture on internal vSwitch)
├── Windows Server DC + Win11 client (Sysmon + Elastic Agent)
├── Ubuntu server (auditd + Elastic Agent)
├── Attacker VM (isolated segment) for Atomic Red Team / emulation
└── pfSense/OPNsense between segments, mirror port → SO capture NIC
```

Promiscuous mode must be allowed on the capture vSwitch/port group.

---

## Engagement Cheatsheet

```text
Deploy → sensor placement → HOME_NET → verify zero packet loss → Alerts
→ Hunt pivot (community_id) → PCAP → Case → tune Detections
```

---

## Key References

- Security Onion docs — https://docs.securityonion.net
- Community ID spec — https://github.com/corelight/community-id-spec
- Graylog docs — https://go2docs.graylog.org
- Related: `defensive-zeek`, `defensive-suricata-snort`, `defensive-pcap-analysis`
