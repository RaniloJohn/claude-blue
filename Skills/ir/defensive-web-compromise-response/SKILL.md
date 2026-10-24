---
name: defensive-web-compromise-response
description: "Responding to compromised websites and web applications: detecting and triaging webshells, defacement, SEO spam injection, Magecart/e-commerce skimmers, malicious redirects, and CMS (WordPress, Joomla, Drupal) plugin compromise; evidence preservation (access/error logs, file timestamps, database dumps, WAF/CDN logs), log analysis for exploitation and webshell access, file integrity comparison against known-good releases, locating backdoors (eval/base64/gzinflate patterns, modified core files, rogue admin users, cron jobs), containment via WAF virtual patching and maintenance mode, credential and key rotation, clean rebuild, and post-incident hardening. Use when a website or web application is suspected compromised."
---

# Web Compromise Response

Web compromises usually involve **a vulnerable component** (plugin, framework, exposed admin), **a backdoor** (webshell), and **an objective** (skimming, spam, redirect, pivot to internal network). Remove all three, not just the visible symptom.

## Quick Workflow

1. Preserve: copy web root, configs, logs, database dump, WAF/CDN logs; snapshot VM
2. Contain: WAF block rules/virtual patch, maintenance mode, restrict admin access by IP
3. Find entry vector from logs; find all backdoors via integrity comparison
4. Rebuild from clean source; restore content data after inspection
5. Rotate every secret; harden; monitor for return

---

## 1. Symptoms → Type

| Symptom | Likely |
|---|---|
| Visitors redirected (mobile/referrer-based only) | Malicious redirect injection (`.htaccess`, JS, DB options) |
| Spam pages indexed in search ("pharma", "casino" in Japanese/Chinese) | SEO spam injection |
| Card data theft at checkout | Magecart skimmer (JS injected into checkout, or server-side) |
| Defaced homepage | Hacktivism/opportunistic |
| Outbound attacks or internal scanning from web server | Webshell used for pivot |
| New admin users, unknown plugins | CMS compromise |

---

## 2. Evidence

```bash
tar --xattrs -czpf /evidence/webroot_$(date +%F).tgz /var/www
cp -a /var/log/nginx /var/log/apache2 /evidence/ 2>/dev/null
mysqldump --single-transaction --routines --triggers wpdb > /evidence/wpdb.sql
find /var/www -type f -newermt "2026-10-01" -printf '%TY-%Tm-%Td %TT %p\n' | sort > /evidence/recent_files.txt
sha256sum $(find /var/www -type f -name "*.php") > /evidence/php_hashes.txt
```

Timestamps can be faked (`touch`) — rely on logs and ctime (`stat`) as well.

---

## 3. Log Analysis

```bash
# POSTs to rarely requested PHP files (webshell candidates)
awk '$6 ~ /POST/ {print $7}' access.log | sort | uniq -c | sort -n | head -30
# Requests to recently created files
grep -F -f <(sed 's#.*/var/www/html##' /evidence/recent_files.txt | awk '{print $3}') access.log | head
# Exploit attempts against plugins / known paths
grep -E "wp-admin/admin-ajax.php|/wp-content/plugins/.+\.php|\.\./|/etc/passwd|base64_decode|eval\(" access.log | head
# Webshell tool user agents or command params
grep -Ei "cmd=|exec=|shell|c99|r57|wso|b374k|antsword|behinder|godzilla" access.log | head
```

Correlate attacker IPs across logs and WAF; identify first successful exploit request → entry vector and timeline.

---

## 4. Finding Backdoors

| Method | Command / check |
|---|---|
| Integrity vs release | WordPress: `wp core verify-checksums`, `wp plugin verify-checksums --all` (WP-CLI); compare others to vendor archives (`diff -r`) |
| Suspicious functions | `grep -rlE "eval\(|base64_decode\(|gzinflate\(|str_rot13\(|assert\(|preg_replace\(.*/e|system\(|shell_exec\(|passthru\(" /var/www` |
| PHP in upload dirs | `find /var/www/*/wp-content/uploads -name "*.php"` |
| Hidden/odd files | `.ico`/`.png` containing PHP, `.user.ini` with `auto_prepend_file`, `.htaccess` rewrites |
| YARA | Webshell rule sets (e.g., Neo23x0 signature-base) with YARA-X |
| Database | Rogue admin users, injected `<script>` in posts/options, malicious `siteurl`/`home` |
| System | Cron jobs, new SSH keys, other sites on same server (cross-contamination) |

---

## 5. Containment & Eradication

1. WAF: block attacker IPs/patterns, virtual-patch the exploited endpoint, enable bot protection
2. Maintenance mode or take offline if skimming payment data (stop the harm)
3. Rebuild from clean sources (fresh CMS core + plugins from official sources, latest versions); re-import only content after inspection
4. Rotate: DB passwords, CMS admin passwords, API keys, SMTP creds, cloud keys in config files, salts/keys (`wp config shuffle-salts`), SSH keys, hosting panel credentials
5. Remove unused plugins/themes; disable PHP execution in upload dirs; least-privilege file permissions
6. Payment skimming: notify payment processor/acquirer; PCI forensic investigator (PFI) may be required; customer notification per law

---

## 6. Post-Incident

FIM on web roots, WAF in blocking mode, automated plugin updates or patch SLA, separate admin access (VPN/IP allowlist + MFA), CSP to limit script sources (skimmer mitigation, `defensive-web-server-hardening` → see `defensive-waf`), SRI for third-party scripts, monitoring for client-side changes (PCI DSS 4.0 requirements 6.4.3 and 11.6.1 for payment pages).

---

## Engagement Cheatsheet

```text
preserve (webroot, logs, DB, WAF/CDN, snapshot) → contain (WAF virtual patch, maintenance mode, admin IP restrict) → logs: rare POSTs, new files, exploit paths, attacker IP timeline
→ backdoors: checksums (wp-cli), eval/base64 grep, PHP in uploads, .user.ini/.htaccess, YARA, DB rogue admins/scripts, cron/keys
→ rebuild clean + rotate all secrets → harden (FIM, WAF, CSP/SRI, PCI 6.4.3/11.6.1) → monitor for return
```

---

## Key References

- OWASP; WP-CLI docs; PCI DSS v4.0.1 (req. 6.4.3, 11.6.1); Neo23x0 signature-base (webshell YARA)
- Related: `defensive-waf`, `defensive-incident-response`, `defensive-linux-forensics`, `defensive-web-server-hardening`
