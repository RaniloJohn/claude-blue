---
name: defensive-tool-honeypots
description: "Honeypot and honeytoken tools deployed safely: OpenCanary (Thinkst) configuration, modules, and alert handlers; Thinkst Canarytokens (hosted vs self-hosted, token types such as AWS keys, DNS, documents, web bugs, Kubeconfig, Azure login certificate); T-Pot 24.04.x multi-honeypot platform (Hive vs Sensor requirements, management ports 64294/64295/64297, Sicherheitstacho data submission default and opt-out, blackhole mode, update.sh backups); Cowrie 3.x SSH/Telnet honeypot (non-root, port redirection via iptables/authbind, layered cowrie.cfg, backend pool); Conpot for ICS; internal vs internet-facing placement, isolation and egress filtering, banner customization against fingerprinting, alert routing, privacy and legal considerations, and maintenance. Use when deploying honeypots or honeytokens for detection or research."
---

# Honeypot Tools

Deception strategy is in `defensive-deception` / `defensive-active-defense`. This skill covers **deploying the tools safely**. Two very different goals:

| Goal | Placement | Signal |
|---|---|---|
| **Internal detection** (early warning) | Inside the network, looks like real assets | Any touch = high-fidelity alert |
| **Internet threat research** | Isolated, internet-facing | Volume data on scanners, credentials, malware |

Versions observed 2026-10-23: OpenCanary 0.9.10, Cowrie 3.1.x, T-Pot 24.04.x.

## Quick Workflow

1. Define goal, placement, legal/privacy approval
2. Isolate: dedicated VLAN/VPC, no route to production, egress default-deny (allow only log shipping/updates)
3. Customize personas/banners to blend in; never put real data on honeypots
4. Route alerts to SIEM/on-call with clear runbooks
5. Patch and monitor the honeypot host itself; review periodically

---

## 1. OpenCanary (internal detection)

```bash
python3 -m venv /opt/opencanary && . /opt/opencanary/bin/activate
pip install opencanary            # upgrades: pip install opencanary --upgrade (keeps config)
opencanaryd --copyconfig          # writes /etc/opencanaryd/opencanary.conf
opencanaryd --start
```

```json
{
  "device.node_id": "fileserver-finance-02",
  "ssh.enabled": true, "ssh.port": 22, "ssh.version": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
  "smb.enabled": true,
  "rdp.enabled": true, "rdp.port": 3389,
  "mssql.enabled": true, "mssql.port": 1433,
  "http.enabled": true, "http.port": 80, "http.skin": "nasLogin",
  "portscan.enabled": true,
  "logger": {
    "class": "PyLogger",
    "kwargs": { "handlers": {
      "file": { "class": "logging.FileHandler", "filename": "/var/log/opencanary.log" },
      "syslog-siem": { "class": "logging.handlers.SysLogHandler", "address": ["siem.example.local", 514] }
    } }
  }
}
```

Handlers: file, syslog, email (SMTP auth), HPFeeds, HTTP webhook; `opencanary-correlator` groups related events. SMB module relies on Samba audit logging — follow the project's Samba setup guide. Use realistic hostnames, banners, and skins matching your naming convention.

---

## 2. Canarytokens (honeytokens)

| Token | Plant where |
|---|---|
| AWS API key | Developer laptops, CI variables (unused), config repos |
| DNS / HTTP web bug | Internal docs, wikis |
| MS Word / PDF / Excel | File shares ("Passwords.xlsx", "Payroll 2026.docx") |
| Kubeconfig / SSH key / Azure login certificate | Jump hosts, backups |
| Windows folder (desktop.ini) | Sensitive shares — fires on browse |
| SQL Server / MySQL dump | Database backup locations |
| Cloned website | Detects phishing kits cloning your login page |
| Credit card / custom tokens | Data stores |

Hosted canarytokens.org is free; **self-host** (Thinkst `canarytokens-docker`) when alert data must stay internal. Tokens phone home with source IP/user agent — consider privacy notice for internal users (a curious employee can trigger them). Track every token's location in a register.

---

## 3. T-Pot (internet research platform)

| Item | Detail (official README) |
|---|---|
| Requirements | Hive: 16 GB RAM, 256 GB SSD; Sensor: 8 GB RAM, 128 GB SSD; IPv4, non-proxied internet; minimal OS, **no desktop** (port conflicts); single NIC |
| Management ports | 64295/tcp SSH, 64297/tcp web UI (NGINX → Kibana, CyberChef, Elasticvue, Attack Map, Spiderfoot), 64294/tcp sensor → hive data |
| Exposure | Firewall in front: forward 1–64000 to T-Pot; allow ports > 64000 **only from trusted IPs** |
| Data sharing | Submits to Sicherheitstacho **by default** — opt out: `systemctl stop tpot`, remove `ewsposter` service from `~/tpotce/docker-compose.yml`, `systemctl start tpot` (re-apply after updates) |
| Blackhole | `TPOT_BLACKHOLE=ENABLED` in `~/tpotce/.env` null-routes known mass scanners (less noise, not stealth) |
| Unattended install | Requires passwordless sudo — remove the sudoers file afterward |
| Updates | `~/tpotce/update.sh` (backs up to `~/tpot_backups/`, overwrites local changes; `.env` restored); `restore.sh` |
| Risk | Project warns compromise can't be ruled out — no sensitive data, separate infrastructure |

---

## 4. Cowrie (SSH/Telnet)

```bash
sudo adduser --disabled-password cowrie && sudo su - cowrie
python3 -m venv cowrie-env && . cowrie-env/bin/activate
python -m pip install cowrie
cowrie init                   # writes etc/cowrie.cfg (won't overwrite existing)
cowrie start                  # listens 2222; refuses to run as root
# Redirect 22 → 2222 (move real sshd to another port first; test from another host)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Config layering: defaults → `/etc/cowrie/cowrie.cfg` → `./etc/cowrie.cfg` → `./cowrie.cfg` (override only changed keys). Customize hostname, fake filesystem, `etc/userdb.txt` (first-match rules). Outputs: JSON log, Splunk, ELK, Graylog, Sentinel, databases. Proxy/backend-pool mode forwards to real VMs (high interaction) — strongest isolation required (libvirt user/group set to cowrie).

---

## 5. Other Tools

| Tool | Use | Caution |
|---|---|---|
| Conpot | ICS/SCADA protocol emulation (Modbus, S7, BACnet) | Never on real OT networks' safety segments; isolate |
| Dionaea | Malware capture (SMB, HTTP, FTP) | Captured samples are live malware — store safely |
| Honeytrap / glutton (in T-Pot) | Catch traffic on any port | High volume |
| AD deception | Honey users/SPNs/decoy creds in LSASS (`defensive-deception`) | Exclude from automated cleanup scripts; document |
| Commercial (Thinkst Canary, Attivo/SentinelOne, Acalvio, Zscaler Deception) | Managed, low-maintenance | Cost, vendor cloud alert data |

---

## 6. Safety Checklist

| # | Control |
|---|---|
| 1 | Isolated segment; no routes or trust to production; separate credentials |
| 2 | Egress default-deny (allow log shipping/updates only) so a compromised honeypot can't attack others |
| 3 | No real data, no domain join for internet honeypots |
| 4 | Host hardened and patched; honeypot software updated (they get exploited too) |
| 5 | Management interfaces restricted to trusted IPs/VPN |
| 6 | Banners/personas customized (default banners are fingerprinted by scanners) |
| 7 | Alert routing tested end-to-end; runbook: who responds, what to check |
| 8 | Data handling: attacker IPs/credentials/payloads may be personal data — retention limits, access control, privacy review (PH Data Privacy Act/GDPR) |
| 9 | Legal review for internet-facing research; honeypots aren't "entrapment" (a law-enforcement inducement concept), but hosting/ISP terms and data laws still apply |
| 10 | Register of every honeypot/token: location, owner, purpose, review date |

---

## Engagement Cheatsheet

```text
goal (internal detection vs internet research) → isolated segment + egress deny → OpenCanary personas → syslog/webhook to SIEM
→ Canarytokens (self-host if needed) with register → T-Pot: firewall 1–64000, mgmt >64000 trusted only, opt out of Sicherheitstacho if required
→ Cowrie non-root + redirect + custom persona → patch honeypots → privacy/legal review → test alerts
```

---

## Key References

- opencanary.readthedocs.io; github.com/thinkst/canarytokens (docs & docker); github.com/telekom-security/tpotce README; docs.cowrie.org (INSTALL, proxy, backend pool); Conpot docs
- Related: `defensive-deception`, `defensive-active-defense`, `defensive-detect-discovery`, `defensive-tool-safety`
