---
name: defensive-network-device-hardening
description: "Router, switch, and firewall management-plane and control-plane hardening on Cisco IOS/IOS-XE and Huawei VRP: AAA with TACACS+/RADIUS and local fallback, SSHv2 only with strong crypto, disabling Telnet/HTTP/unused services, management ACLs and VTY restrictions, SNMPv3 authPriv, NTP authentication, centralized logging with timestamps, login banners and lockouts, password encryption (type 8/9 secrets), Control Plane Policing (CoPP), routing protocol authentication (OSPF/BGP/EIGRP), uRPF, configuration archive and change detection, firmware integrity verification, and Cisco Smart Install/legacy exposure. Use when hardening network infrastructure or auditing device configs."
---

# Network Device Hardening

Network devices are high-value, low-visibility targets (state actors implant routers and edge appliances). Harden three planes: **management** (who can administer), **control** (protocols the device speaks), **data** (traffic it forwards).

## Quick Workflow

1. Inventory devices + firmware versions; map to PSIRT advisories
2. Management plane: AAA, SSH-only, mgmt ACLs, SNMPv3, logging, NTP
3. Control plane: CoPP, routing auth, disable unused protocols
4. Data plane: uRPF, ACLs, segmentation (see `defensive-network-segmentation`)
5. Config backups + change detection; firmware integrity checks
6. Audit against CIS/vendor baselines

---

## 1. Cisco IOS / IOS-XE

```text
! --- Identity & AAA ---
hostname R1
ip domain name corp.example
service password-encryption
enable algorithm-type scrypt secret <strong>              ! type 9
username netadmin privilege 15 algorithm-type scrypt secret <strong>
aaa new-model
tacacs server TAC1
 address ipv4 10.10.1.20
 key <secret>
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting commands 15 default start-stop group tacacs+
login block-for 120 attempts 5 within 60
login on-failure log
login on-success log
!
! --- SSH only ---
crypto key generate rsa modulus 3072
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
ip access-list standard MGMT
 permit 10.10.50.0 0.0.0.255
 deny any log
line vty 0 15
 transport input ssh
 access-class MGMT in
 exec-timeout 10 0
 login authentication default
line con 0
 exec-timeout 10 0
!
! --- Disable unneeded services ---
no ip http server
no ip http secure-server            ! unless required for management
no service pad
no ip bootp server
no ip source-route
no cdp run                          ! or disable per edge interface
no vstack                           ! Smart Install (legacy exploited)
no ip domain-lookup
interface Gi0/0
 no ip redirects
 no ip unreachables
 no ip proxy-arp
!
! --- SNMPv3 ---
snmp-server group NETOPS v3 priv read RO-VIEW access MGMT
snmp-server user nms NETOPS v3 auth sha <authkey> priv aes 256 <privkey>
snmp-server view RO-VIEW iso included
no snmp-server community public
!
! --- Logging & time ---
service timestamps log datetime msec localtime show-timezone
logging host 10.10.1.30 transport tcp port 6514     ! TLS-capable syslog where supported
logging trap informational
logging buffered 64000
archive
 log config
  logging enable
  notify syslog contenttype plaintext
 path flash:archive/$h-
 write-memory
ntp authentication-key 1 hmac-sha2-256 <key>        ! algorithm support varies by release (md5 on older)
ntp authenticate
ntp trusted-key 1
ntp server 10.10.1.10 key 1
!
banner login ^Authorized access only. Activity is monitored.^
```

uRPF and routing protocol auth:

```text
interface Gi0/1
 ip verify unicast source reachable-via rx      ! strict uRPF on single-homed edges
router ospf 1
 area 0 authentication message-digest
interface Gi0/2
 ip ospf message-digest-key 1 md5 <key>          ! prefer OSPF HMAC-SHA key chains where supported
router bgp 65001
 neighbor 203.0.113.1 password <key>             ! or TCP-AO where supported
```

CoPP (outline): classify management (SSH/SNMP/NTP from mgmt ACL), routing protocols, ICMP; police each; drop/limit the rest.

---

## 2. Huawei VRP

```text
sysname R1
#
aaa
 local-user netadmin password irreversible-cipher <strong>
 local-user netadmin privilege level 15
 local-user netadmin service-type ssh
 hwtacacs-scheme TAC
  hwtacacs-server authentication 10.10.1.20
  hwtacacs-server authorization 10.10.1.20
  hwtacacs-server accounting 10.10.1.20
  hwtacacs-server shared-key cipher <secret>
 authentication-scheme TACAUTH
  authentication-mode hwtacacs local
 domain default_admin
  authentication-scheme TACAUTH
  hwtacacs-server TAC
#
stelnet server enable
undo telnet server enable
undo http server enable              ! keep HTTPS only if web mgmt required
ssh user netadmin authentication-type password
ssh user netadmin service-type stelnet
ssh server cipher aes256_ctr aes128_ctr
#
acl number 2000
 rule 5 permit source 10.10.50.0 0.0.0.255
 rule 100 deny
#
user-interface vty 0 4
 authentication-mode aaa
 protocol inbound ssh
 acl 2000 inbound
 idle-timeout 10 0
#
snmp-agent sys-info version v3
snmp-agent group v3 NETOPS privacy
snmp-agent usm-user v3 nms group NETOPS
snmp-agent usm-user v3 nms authentication-mode sha
snmp-agent usm-user v3 nms privacy-mode aes256
undo snmp-agent sys-info version v1 v2c
#
info-center loghost 10.10.1.30
ntp-service authentication enable
ntp-service unicast-server 10.10.1.10 authentication-keyid 1
#
header login information "Authorized access only. Activity is monitored."
```

Syntax varies across VRP versions (V5 vs V8, AR vs S vs CE platforms) — validate with `display current-configuration` and the platform configuration guide.

---

## 3. Audit Checklist

```text
[ ] Firmware supported and patched; PSIRT subscription
[ ] No Telnet/HTTP; SSHv2 with ≥3072-bit RSA or ECDSA/Ed25519 keys
[ ] Mgmt ACL on VTY/SNMP/NTP/web; mgmt via OOB network or dedicated VRF
[ ] AAA with central auth + command accounting; local fallback account vaulted
[ ] Type 8/9 (Cisco) or irreversible-cipher (Huawei) secrets; no type 7 / cleartext
[ ] SNMPv3 authPriv only; no default communities
[ ] Syslog to SIEM with timestamps; NTP authenticated
[ ] Unused interfaces shutdown; CDP/LLDP off on edge/untrusted ports
[ ] CoPP configured; routing protocol authentication
[ ] Config archived; change alerts (diff on every commit)
[ ] Firmware integrity verified (hash/signature; Cisco `verify /md5` or image signing checks)
```

---

## 4. Detection

| Event | Signal |
|---|---|
| Config change | Cisco `%PARSER-5-CFGLOG_LOGGEDCMD`, `%SYS-5-CONFIG_I`; Huawei `CMDRECORD` / `CFG` logs |
| Login failures / brute force | `%SEC_LOGIN-4-LOGIN_FAILED`, Huawei SSH login fail logs |
| New local user created | Config diff / AAA accounting |
| Image/boot variable change | `boot system` changes; reload events |
| ACL removed from VTY | Config diff |
| Unexpected outbound connections from mgmt plane | NetFlow from device loopback/mgmt IP |

---

## Engagement Cheatsheet

```text
inventory + PSIRT → AAA (TACACS+ + accounting) → SSH-only + mgmt ACL → kill legacy services (Telnet/HTTP/Smart Install)
→ SNMPv3 → NTP auth + syslog → CoPP + routing auth + uRPF → archive/diff → firmware integrity → CIS audit
```

---

## Key References

- Cisco Guide to Harden Cisco IOS Devices; Cisco IOS XE hardening guide
- Huawei VRP security configuration guides; Huawei device hardening guide
- CIS Cisco IOS Benchmark; NSA Network Infrastructure Security Guide
- Related: `defensive-l2-security`, `defensive-network-segmentation`, `defensive-firewall-analysis`
