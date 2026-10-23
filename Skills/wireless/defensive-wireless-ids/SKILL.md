---
name: defensive-wireless-ids
description: "Wireless intrusion detection and monitoring: WIDS/WIPS on enterprise controllers (Cisco, Aruba, Huawei, Ubiquiti, Meraki), Kismet sensors, detecting rogue APs, evil twins and KARMA/MANA attacks, deauthentication/disassociation floods, PMKID/handshake capture attempts, WPS brute force, WPA3 transition-mode downgrade, Bluetooth/BLE and other RF anomalies, correlating wireless events with wired/NAC data, and responding to wireless incidents including locating devices. Use when monitoring Wi-Fi airspace or investigating wireless attacks."
---

# Wireless Intrusion Detection

Wi-Fi attacks happen in the air, outside wired sensors. Detection needs RF visibility (AP radios in monitor/scanning mode or dedicated sensors) plus correlation with wired-side evidence.

## Quick Workflow

1. Inventory authorized SSIDs, BSSIDs, channels, security modes
2. Enable WIDS on controller/APs or deploy Kismet sensors
3. Classify detected APs: authorized / neighbor / rogue-on-wire
4. Alert on deauth floods, evil twins, downgrade attempts
5. Correlate with NAC/RADIUS and switch MAC tables
6. Locate and contain rogue devices

---

## 1. Threat → Signal

| Attack | Signal |
|---|---|
| Rogue AP on wired network | Unknown BSSID whose wired MAC (or MAC ±1 offset) appears in switch CAM tables |
| Evil twin | Authorized SSID broadcast from unknown BSSID; different security mode (open vs WPA2/3); stronger signal in unusual location |
| KARMA / MANA | AP responding to many different probe SSIDs |
| Deauth/disassoc flood | High rate of deauth/disassoc frames to clients or broadcast (PMF prevents forged mgmt frames for protected clients) |
| PMKID / handshake capture | Bursts of association attempts without completion; deauth followed by reconnection storms |
| WPS brute force | Repeated WPS M1–M7 exchanges; AP WPS lockouts |
| WPA3 transition downgrade | Clients associating via WPA2 to an AP impersonating a WPA3-transition SSID |
| EAP credential harvest | Rogue AP advertising enterprise SSID; clients presenting identities to unknown RADIUS (client side: cert validation failure events) |
| Jamming | Channel utilization/noise spikes, mass disconnections |
| Ad-hoc / Wi-Fi Direct / hotspots | Corporate devices hosting networks |

---

## 2. Platform WIDS

| Vendor | Feature |
|---|---|
| Cisco (Catalyst 9800 / Meraki) | Rogue detection, rogue containment (legal caution), WIPS signatures, Meraki Air Marshal |
| Aruba (HPE) | RFProtect / WIP: rogue classification, wired-side correlation |
| Huawei | WLAN WIDS/WIPS: rogue device detection, spoofing/flood attack detection, containment |
| Ubiquiti | Rogue AP detection (basic) |
| Open source | Kismet (multi-sensor, alerts, REST API), nzyme |

Containment (deauthing clients off a rogue) may be restricted by law/regulation outside your premises — use only on rogues confirmed connected to your network and with legal approval; prefer wired-port shutdown.

---

## 3. Kismet

```bash
kismet -c wlan1 --override wardrive            # quick survey
kismet -c wlan1:hop=true -c wlan2:hop=true      # multi-radio sensor
# Web UI :2501 ; alerts: APSPOOF, DEAUTHFLOOD, DISASSOCTRAFFIC, KARMAOUI, BCASTDISCON, CHANCHANGE, NOPROBERESP, WPSBRUTE (alert set varies by version)
```

APSPOOF config: list authorized MACs per SSID so any other BSSID advertising that SSID alerts:

```text
apspoof=CorpSSID:ssid="Corp-WiFi",validmacs="AA:BB:CC:11:22:33,AA:BB:CC:11:22:34"
```

---

## 4. Wired Correlation

```text
1. Rogue BSSID 12:34:56:78:9A:BC detected
2. Check switch CAM: show mac address-table | include 1234.5678.9a  (Cisco)
                     display mac-address | include 1234-5678-9a  (Huawei)
   (try BSSID, BSSID±1, and OUI-related wired MACs)
3. Found on Gi1/0/22 → physical location from port map
4. NAC/RADIUS: was the port authenticated? which device?
5. Shut port; retrieve device; investigate owner
```

---

## 5. Client-Side Indicators

- Windows WLAN-AutoConfig Operational log: 8001 connect, 8002 failure, 11004/11005 security failures, 12013 (802.1X failures)
- Certificate validation failures on enterprise Wi-Fi (evil-twin RADIUS)
- MDM/EDR: device connecting to unexpected SSID/BSSID

---

## 6. Response

| Scenario | Actions |
|---|---|
| Rogue on wire | Shut switch port; locate; preserve device; check what it bridged |
| Evil twin harvesting creds | Notify users; reset passwords of users who connected; verify 802.1X server cert validation is enforced on clients |
| Deauth flood | Confirm PMF (802.11w) required; locate transmitter (signal strength triangulation) |
| Leaked PSK | Rotate PSK; move to 802.1X or WPA3-SAE per-user/identity PSK |

---

## Engagement Cheatsheet

```text
authorized inventory → WIDS/Kismet → classify rogues → alerts (spoof, deauth, KARMA, WPS)
→ wired correlation (CAM/NAC) → locate → contain via switch port → fix root cause (PMF, 802.1X, cert validation)
```

---

## Key References

- Kismet docs — https://www.kismetwireless.net/docs/
- Vendor WIPS guides (Cisco, Aruba, Huawei WLAN security)
- IEEE 802.11w (PMF); Wi-Fi Alliance WPA3 specification
- Related: `defensive-wireless-design`, `defensive-l2-security`
