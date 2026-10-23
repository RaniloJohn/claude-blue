---
name: defensive-ics-security
description: "Industrial control system and operational technology (OT) defense: Purdue model and IEC 62443 zones and conduits, IT/OT DMZ design, asset inventory via passive monitoring, OT network security monitoring (Zeek ICS parsers, Suricata, Malcolm, commercial OT NDR), industrial protocols (Modbus/TCP, DNP3, IEC 61850/104, S7comm, EtherNet/IP-CIP, BACnet, OPC UA) and abnormal function codes, MITRE ATT&CK for ICS, safe vulnerability management in OT, remote access hardening, OT incident response with safety priorities, and building management/IoT segments. Use for OT security architecture, monitoring, and incident response."
---

# ICS / OT Security

In OT, availability and safety come first. Detection is mostly passive, changes require operations approval, and incident response must never create unsafe process conditions.

## Quick Workflow

1. Passive asset inventory and communication map
2. Zone/conduit model (Purdue / IEC 62443)
3. IT/OT DMZ; no direct IT→OT paths
4. Monitor OT protocols for unauthorized commands and new talkers
5. Harden remote access (jump host, MFA, session recording)
6. OT-specific IR plan with operations and safety engineering

---

## 1. Purdue Model

| Level | Contents |
|---|---|
| 5 | Enterprise network / internet |
| 4 | Business logistics (ERP, email) |
| 3.5 | IT/OT DMZ (historian replica, patch server, jump host, file transfer) |
| 3 | Site operations (historian, MES, engineering workstations, OT AD) |
| 2 | Supervisory (HMI, SCADA servers) |
| 1 | Basic control (PLCs, RTUs, controllers) |
| 0 | Physical process (sensors, actuators) |
| SIS | Safety Instrumented Systems — isolated |

Rules: traffic terminates in the DMZ (no direct L4 → L3); SIS separated; allowlisted protocols per conduit.

---

## 2. IEC 62443 Concepts

- **Zones**: groups of assets with common security requirements
- **Conduits**: controlled communication paths between zones
- **Security Levels (SL 1–4)**: target vs achieved per zone
- Roles: asset owner (62443-2-x), system integrator (3-x), product supplier (4-x)

---

## 3. Protocols & Abnormal Behavior

| Protocol | Port | Watch for |
|---|---|---|
| Modbus/TCP | 502 | Write function codes (5, 6, 15, 16) from non-engineering hosts; diagnostics (8); new masters |
| DNP3 | 20000 | Cold/warm restart (13/14), direct operate, file transfer, unsolicited from new sources |
| S7comm / S7comm-plus | 102 | PLC stop/start, program download/upload, CPU state changes |
| EtherNet/IP (CIP) | 44818 / 2222 | Program mode changes, firmware updates, writes to tags |
| IEC 60870-5-104 | 2404 | Control commands from unexpected stations |
| IEC 61850 (MMS/GOOSE) | 102 / L2 | GOOSE spoofing, unexpected MMS writes |
| BACnet | 47808/udp | Writes/reinitialize-device from non-BMS hosts |
| OPC UA | 4840 | Anonymous sessions, insecure security policy (None) |
| OPC DA (DCOM) | 135+dyn | Hard to firewall — prefer OPC UA |

Baseline: who talks to which PLC, with which function codes, at what times. Alert on new talkers, new function codes, program changes outside maintenance windows.

---

## 4. Monitoring Stack

| Tool | Notes |
|---|---|
| Zeek with ICS parsers (CISA ICSNPP: Modbus, DNP3, S7comm, ENIP/CIP, BACnet, OPC UA, Profinet…) | Protocol logs |
| Malcolm (CISA/INL) | Packaged Zeek+Suricata+Arkime+OpenSearch with ICS parsers |
| Suricata ICS rules | Modbus/DNP3 keywords |
| Commercial OT NDR | Nozomi, Claroty, Dragos, Microsoft Defender for IoT, Tenable OT |

Sensors on SPAN/TAP at L2/L3 switches and DMZ conduits; never inline without validation.

---

## 5. Vulnerability Management in OT

- Passive identification first; active scanning only with vendor/ops approval and in maintenance windows (can crash PLCs)
- Patching follows vendor qualification; compensating controls often primary (segmentation, allowlisting, monitoring)
- Track CISA ICS advisories; vendor PSIRTs (Siemens ProductCERT, Rockwell, Schneider, ABB, Honeywell)
- Application allowlisting on HMIs/engineering workstations; USB control and scanning kiosks

---

## 6. Remote Access

```text
[ ] Vendor access only via DMZ jump host with MFA, time-bound approval, session recording
[ ] No always-on VPNs/remote tools (TeamViewer/AnyDesk) on HMIs or EWS
[ ] Separate OT identity domain or tightly scoped accounts; no shared admin
[ ] Outbound internet from OT denied
```

---

## 7. OT Incident Response

1. Safety first — engage operations/process engineering immediately
2. Prefer isolation at IT/OT boundary (DMZ) over shutting down controllers
3. Preserve: PLC program/logic snapshots, HMI/EWS images, network captures, historian data
4. Compare running PLC logic with known-good baselines (detect logic tampering)
5. Plan recovery with manual operations fallback
6. Coordinate with regulators/sector ISACs (e.g., E-ISAC, WaterISAC) and CISA where applicable

ATT&CK for ICS techniques to prioritize: Modify Controller Tasking, Program Download, Modify Parameter, Manipulation of Control, Loss of View, Denial of Control, Activate Firmware Update Mode, Spoof Reporting Message.

---

## Engagement Cheatsheet

```text
passive inventory + comms map → Purdue/62443 zones & conduits → DMZ-only IT↔OT → ICS protocol monitoring
(new talkers, write/program/stop codes) → safe vuln mgmt → hardened vendor access → safety-first OT IR
```

---

## Key References

- ISA/IEC 62443 series; NIST SP 800-82r3 (Guide to OT Security)
- MITRE ATT&CK for ICS; CISA ICS advisories; CISA ICSNPP; Malcolm
- Related: `defensive-network-segmentation`, `defensive-zeek`, `defensive-incident-response`
