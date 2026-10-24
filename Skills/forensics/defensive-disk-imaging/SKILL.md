---
name: defensive-disk-imaging
description: "Forensic acquisition of disks, volumes, VMs, and cloud storage: order of volatility, write blocking (hardware and software), live vs dead acquisition, BitLocker/FileVault/LUKS considerations (capture keys or live image before shutdown), formats (raw/dd, E01/EWF, AFF4), tools (FTK Imager, ewfacquire, dc3dd, dcfldd, Guymager, ddrescue for failing media), hashing and verification, SSD TRIM and wear-leveling caveats, triage vs full image decisions, VM disk and snapshot capture (VMDK, VHDX), cloud snapshots (AWS EBS, Azure managed disks, GCP persistent disks) with cross-account evidence copies, chain of custody, and NIST SP 800-86 / ISO 27037 practice. Use when acquiring disk evidence or planning forensic collection."
---

# Disk & Storage Imaging

A forensic image is only useful if it is complete, verified, and defensible. Decide **what** to capture (triage vs full), **how** (live vs dead, encryption state), and **document everything**.

## Quick Workflow

1. Assess: volatility (capture memory first if live), encryption, size, legal requirements
2. Choose: triage collection (KAPE/Velociraptor) vs full image
3. Acquire with write protection; hash source and image
4. Verify; record chain of custody
5. Store original read-only; analyze copies

---

## 1. Decisions

| Situation | Approach |
|---|---|
| Live system, encrypted disk | Capture memory, then **live logical/physical image while unlocked**, or recover recovery key (BitLocker key from AD/Entra/Intune escrow; FileVault institutional key) before shutdown |
| Powered-off system | Dead acquisition with hardware write blocker |
| Many hosts, quick scoping | Triage collection (`defensive-tool-kape-eztools`, `defensive-tool-velociraptor`), full image only for key hosts |
| Failing drive | `ddrescue` with map file; image first, analyze later |
| Server that can't go down | Live image or VM snapshot; document running state |
| Cloud VM | Provider snapshot (§4) |

---

## 2. Tools & Commands

```bash
# EWF (E01) with metadata and MD5+SHA256 (libewf)
ewfacquire -t /evidence/case42/host01 -C 42 -D "host01 system disk" -E HOST01-001 -e "analyst" -f encase6 -c best -d sha256 /dev/sdb
# dc3dd with hashing and logging
dc3dd if=/dev/sdb of=/evidence/case42/host01.dd hash=sha256 log=/evidence/case42/host01.dc3dd.log
# Failing media
ddrescue -d -r3 /dev/sdb /evidence/case42/host01.img /evidence/case42/host01.map
# Verify
ewfverify /evidence/case42/host01.E01
sha256sum /evidence/case42/host01.dd
# Mount read-only for analysis
ewfmount host01.E01 /mnt/ewf && mount -o ro,loop,noexec,show_sys_files /mnt/ewf/ewf1 /mnt/host01
```

Windows: FTK Imager (physical drive → E01, verify after creation), or `ftkimager` CLI. Linux live: Guymager (GUI), `dc3dd`. Use Linux forensic boot media (e.g., CAINE, Tsurugi, Paladin) for dead acquisition when hardware blockers aren't available — confirm the distro mounts nothing read-write automatically.

---

## 3. Caveats

| Issue | Impact |
|---|---|
| SSD TRIM / garbage collection | Deleted data may vanish even before imaging; image quickly; expect less unallocated recovery |
| Encryption (BitLocker, FileVault, LUKS, SED) | Dead image without key = ciphertext; escrow keys in advance |
| Host Protected Area / DCO | Check and capture hidden areas (`hdparm -N`, `hdparm --dco-identify`) |
| Large RAID / SAN | Image logical volumes; document RAID config |
| Live imaging | Not bit-for-bit consistent ("smear"); document it |
| Time | Record system clock vs reference time |

---

## 4. Virtual & Cloud

| Platform | Method |
|---|---|
| VMware | Snapshot with memory (`.vmem`/`.vmsn`), copy VMDK + snapshot files from datastore |
| Hyper-V | Checkpoint / export VHDX |
| AWS | `aws ec2 create-snapshot --volume-id vol-x --description "case42"` → share/copy to isolated forensic account (re-encrypt with forensic KMS key) → create volume → attach read-only to forensic instance |
| Azure | Snapshot managed disk → copy to forensic subscription (SAS export via `grant-access` with short expiry) |
| GCP | `gcloud compute snapshots create` → use in forensic project |

Tag evidence snapshots, restrict IAM, enable deletion protection, log all access (`defensive-cloud-ir`).

---

## 5. Chain of Custody Record

| Field | Example |
|---|---|
| Evidence ID | CASE42-HOST01-001 |
| Description | Samsung 512 GB NVMe, S/N … |
| Acquired by / date-time (UTC) | Name, 2026-10-24T03:15Z |
| Method / tool + version | ewfacquire 20231119, hardware blocker model |
| Hashes | Source SHA-256 / image SHA-256 |
| Transfers | Each handoff with date, reason, signatures |
| Storage | Location, access controls |

---

## Engagement Cheatsheet

```text
memory first if live → encryption keys (escrow) or live image → triage vs full → write-block → ewfacquire/dc3dd/FTK Imager with hashing
→ verify → chain of custody → read-only analysis copies → cloud: snapshot → isolated forensic account → read-only attach
```

---

## Key References

- NIST SP 800-86 (Integrating Forensic Techniques into Incident Response); ISO/IEC 27037; SWGDE best practices
- libewf, dc3dd, GNU ddrescue, FTK Imager documentation
- Related: `defensive-windows-forensics`, `defensive-linux-forensics`, `defensive-memory-forensics`, `defensive-cloud-ir`, `defensive-tool-kape-eztools`
