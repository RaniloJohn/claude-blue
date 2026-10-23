---
name: defensive-tool-nmap
description: "Using Nmap defensively and safely for asset discovery, exposure validation, and change detection: authorization and scheduling, host discovery, TCP SYN vs connect scans and required privileges, top-ports vs full-port scans, service/version detection intensity, NSE script categories (safe/default vs intrusive, vuln, exploit, brute, dos) and what to avoid in production, timing and rate limits (--max-rate, -T), output formats (-oA, XML) and ndiff for baseline drift, scanning IPv6, OT/ICS cautions (prefer passive discovery), detecting unauthorized scans, and NPSL licensing for redistribution. Use when inventorying networks, validating firewall rules, or monitoring exposure changes."
---

# Nmap (Defensive Use)

Nmap is the standard for verifying what's actually listening. Defensive goals: **inventory**, **validate segmentation/firewall rules**, and **detect drift** — with minimal disruption. Version line 7.9x (checked 2026-10-23).

## Quick Workflow

1. Authorization + scan window + notify SOC/NOC (add scanner IP to known-scanner context)
2. Discovery scan → port scan (top ports, then full on key subnets) → light version detection
3. Save XML; compare with previous baseline using `ndiff`
4. Investigate new hosts/ports; update inventory and firewall rules

---

## 1. Scans

```bash
sudo nmap -sn -PE -PS22,80,443,3389 -PA80,443 10.10.0.0/16 -oA disc_$(date +%F)          # host discovery
sudo nmap -sS --top-ports 1000 -T3 --max-rate 500 -iL live.txt -oA top1k_$(date +%F)    # SYN scan (root/admin)
nmap -sT -p 22,443,3389,5985 10.10.5.0/24 -oA mgmt                                        # connect scan (no root)
sudo nmap -sS -p- --min-rate 200 --max-rate 1000 10.10.5.10 -oA full_10.10.5.10           # all TCP ports, one host
sudo nmap -sU --top-ports 50 10.10.5.0/24 -oA udp50                                       # UDP (slow, lossy)
nmap -sV --version-light -p 22,80,443 10.10.5.0/24 -oA versions
nmap -6 -sS --top-ports 100 2001:db8:10::/120 -oA v6                                      # IPv6 (targets must be known/small)
ndiff top1k_2026-10-16.xml top1k_2026-10-23.xml > drift.txt                               # changes since last week
```

---

## 2. NSE Script Categories

| Category | Production use |
|---|---|
| `safe`, `default`, `discovery` | Generally OK (still review) |
| `version` | OK with light intensity |
| `vuln` | Some checks are intrusive — staging or with approval |
| `intrusive`, `brute`, `exploit`, `dos`, `fuzzer` | **Not** in production without explicit approval; can lock accounts, crash services |

```bash
nmap --script "safe and not broadcast" -p 443 10.10.5.0/24
nmap --script ssl-enum-ciphers,ssl-cert -p 443 web01                  # TLS audit
nmap --script smb-protocols,smb2-security-mode -p 445 10.10.0.0/24    # SMBv1 / signing check
nmap --script http-title,http-headers -p 80,443 10.10.5.0/24
nmap --script-help vuln                                               # read before running
```

---

## 3. Safety

| Rule | Detail |
|---|---|
| Authorization | Scope, window, contacts in writing; never scan third parties (cloud providers have policies — check before scanning cloud ranges you don't own) |
| Rate | `--max-rate`, `-T3` or lower for fragile networks; avoid `-T5` |
| OT/ICS | Active scans can crash PLCs/HMIs — use passive discovery (OT NDR, SPAN) or vendor-approved tools, only in maintenance windows |
| Printers/IoT/legacy | Fragile — exclude or slow down (`--exclude`, `--excludefile`) |
| Credentials | NSE brute/auth scripts can lock accounts |
| Results | Scan outputs map your attack surface — store securely |
| Root | SYN/UDP/OS detection need raw sockets; run in dedicated scanner host, not on admin workstations |

---

## 4. Use Cases

| Goal | Method |
|---|---|
| Firewall rule validation | Scan from each zone into others; compare to flow matrix (`defensive-network-security-architecture`) |
| Exposure check | External scan of your public ranges from an outside vantage point |
| Rogue services | Weekly top-ports scan + ndiff |
| Weak protocols | `ssl-enum-ciphers`, SMBv1, Telnet/FTP open |
| Asset inventory | Feed XML into CMDB/vuln management |

---

## 5. Detecting Unauthorized Scanning

Many SYN-only flows, REJ/S0 states (Zeek), firewall deny bursts, IDS scan signatures, `nmap.exe`/`nmap` process on non-scanner hosts, NSE user agent `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`.

---

## 6. Licensing

Nmap uses the Nmap Public Source License (NPSL) — internal use is fine; embedding/redistributing in commercial products requires an OEM license.

---

## Engagement Cheatsheet

```text
authorize + notify → -sn discovery → -sS --top-ports -T3 --max-rate → full ports on key hosts → -sV --version-light
→ NSE safe/default only in prod → -oA XML → ndiff weekly drift → OT passive only → detect rogue nmap use
```

---

## Key References

- nmap.org book & reference guide (NSE categories, timing); ndiff; NPSL
- Related: `defensive-vuln-management`, `defensive-ngfw-policy`, `defensive-detect-discovery`
