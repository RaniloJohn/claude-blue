---
name: defensive-usb-device-control
description: "Removable media and peripheral device control: risks (data exfiltration, malware introduction, BadUSB/HID injection, rogue network adapters), Windows controls (Group Policy removable storage access, Defender for Endpoint Device Control policies by device ID/vendor/serial, Intune device restrictions, BitLocker To Go enforcement), Windows events (6416 PnP, Device Setup Manager, Defender RemovableStorage events), macOS (MDM restrictions, Jamf), Linux USBGuard rules, monitoring queries, approved encrypted USB devices, exception workflow, and air-gapped/OT media handling (kiosk scanning). Use when restricting or monitoring USB and removable devices."
---

# USB & Device Control

Removable devices are both an exfiltration path and a malware entry point (OT/air-gapped environments especially). Default-deny writable storage, allow approved encrypted devices, and monitor everything.

## Quick Workflow

1. Define policy: deny by default, read-only option, approved device list, exceptions process
2. Implement per OS (§2–4)
3. Block HID injection risks where feasible; monitor new keyboards
4. Log device connections and file copies; alert on anomalies
5. For OT/air-gapped: media scanning kiosks and dedicated transfer devices

---

## 1. Risks

| Risk | Example |
|---|---|
| Data exfiltration | Copying customer data to personal USB |
| Malware introduction | Infected USB in OT network; autorun-style lures |
| BadUSB / HID injection | Device emulating keyboard typing commands in seconds |
| Rogue network adapters | USB Ethernet/LTE dongles bypassing network controls |
| Lost devices | Unencrypted data on lost drive |

---

## 2. Windows

| Control | Implementation |
|---|---|
| GPO | Computer Configuration → Administrative Templates → System → Removable Storage Access (deny read/write per class); Device Installation Restrictions (prevent installation of devices not described by other policy settings, allow by device ID) |
| Defender for Endpoint Device Control | Policies with groups (vendor ID, product ID, serial, BusType) and entries (allow/deny/audit read/write/execute); deploy via Intune or GPO; supports printers and Bluetooth classes |
| Intune | Device restrictions / Endpoint security → Attack surface reduction → Device control profiles |
| BitLocker To Go | Deny write access to removable drives not protected by BitLocker |
| ASR rule | "Block untrusted and unsigned processes that run from USB" |
| Autorun | Disabled (default on modern Windows; enforce via GPO) |

Events: Security **6416** (new external device recognized; Audit PNP Activity), `Microsoft-Windows-DeviceSetupManager`, `Microsoft-Windows-Partition/Diagnostic` (1006, volume details incl. serial), Defender `DeviceEvents` ActionTypes such as `UsbDriveMounted`, `RemovableStoragePolicyTriggered`, `PnpDeviceConnected`.

```kql
DeviceEvents
| where ActionType in ("UsbDriveMounted","PnpDeviceConnected","RemovableStoragePolicyTriggered")
| extend f = parse_json(AdditionalFields)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, f.DriveLetter, f.ProductName, f.SerialNumber, f.VendorId
```

File copies to removable media: Defender `DeviceFileEvents` where `FolderPath` starts with removable drive letters (correlate with mount events), Purview endpoint DLP (`defensive-detect-exfiltration`).

---

## 3. macOS

MDM restrictions (e.g., Jamf/Intune configuration profiles for external media: read-only, deny, allow encrypted), EDR device control features, FileVault for internal disk; log via ESF mount events (`es_event_mount`) in EDR.

---

## 4. Linux (USBGuard)

```bash
sudo usbguard generate-policy > /etc/usbguard/rules.conf   # allow currently attached devices
sudo systemctl enable --now usbguard
usbguard list-devices
usbguard allow-device <id> -p      # permanently allow
```

Rules example: `allow with-interface equals { 08:*:* } id 0951:1666 serial "ABC123"` (specific Kingston drive), `block with-interface equals { 03:*:* }` for unexpected HID (careful: keyboards/mice). Log to journald; alert on blocked insertions.

---

## 5. BadUSB / HID

- Alert when a new keyboard-class device connects and a shell (PowerShell/cmd) launches within seconds from `explorer.exe`
- Lock screens when unattended; physical port controls in kiosks/public areas
- USBGuard/Device Control rules for HID allowlists on high-security hosts

---

## 6. OT / Air-Gapped Media

Dedicated, inventoried transfer media; multi-engine scanning kiosk before entry; one-way transfer procedures; logging of every transfer; never personal devices (see `defensive-ics-security`).

---

## Engagement Cheatsheet

```text
policy (deny writable by default, approved encrypted devices, exceptions) → Windows: GPO + Defender Device Control + BitLocker To Go + ASR USB rule
→ macOS MDM profiles → Linux USBGuard → events (6416, Partition 1006, DeviceEvents UsbDriveMounted) + file copy monitoring/DLP
→ HID injection alert (new keyboard → shell) → OT kiosk scanning
```

---

## Key References

- Microsoft Defender for Endpoint Device Control docs; Microsoft removable storage GPO docs; USBGuard project
- Related: `defensive-detect-exfiltration`, `defensive-windows-hardening`, `defensive-ics-security`
