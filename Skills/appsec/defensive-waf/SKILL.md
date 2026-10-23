---
name: defensive-waf
description: "Web Application Firewall operations: ModSecurity v3 / Coraza with OWASP Core Rule Set (CRS 4.x), paranoia levels, anomaly scoring and thresholds, false positive tuning with rule exclusions (ctl:ruleRemoveTargetById, SecRuleUpdateTargetById), virtual patching for CVEs, bot and rate limiting, cloud WAFs (AWS WAF managed rule groups, Azure Front Door/Application Gateway WAF, Cloudflare, Akamai), log analysis for attack detection, and common WAF bypass patterns defenders should test (encoding, chunking, JSON/multipart parsing gaps, request smuggling). Use when deploying, tuning, or investigating a WAF."
---

# Web Application Firewall

A WAF buys time and visibility; it does not fix vulnerable code. Tune it to block real attacks with minimal false positives, and use it for fast virtual patching while code fixes ship.

## Quick Workflow

1. Deploy in detection (log-only) mode
2. Start at Paranoia Level 1, anomaly threshold default
3. Tune false positives with narrow exclusions
4. Switch to blocking; lower thresholds gradually
5. Add virtual patches for known CVEs
6. Monitor logs; feed attacks to SIEM

---

## 1. OWASP CRS Essentials

| Concept | Meaning |
|---|---|
| Paranoia Level (PL1–PL4) | Higher = more rules, more FPs. PL1 baseline; PL2 for sensitive apps |
| Anomaly scoring | Rules add points; request blocked when total ≥ inbound threshold (default 5) |
| Executing PL | Run higher-PL rules in log-only to evaluate before enforcing |
| Rule ranges | 911xxx method, 913 scanners, 920 protocol, 921 protocol attack, 930 LFI, 931 RFI, 932 RCE, 933 PHP, 934 generic, 941 XSS, 942 SQLi, 943 session fixation, 944 Java, 949/959 blocking evaluation |
| Plugins | App-specific exclusions (WordPress, Drupal, Nextcloud) in CRS 4 plugin architecture |

```apache
# crs-setup.conf
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900001,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=2"
SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
SecRuleEngine DetectionOnly     # → On after tuning
```

---

## 2. False Positive Tuning (narrowest first)

```apache
# Exclude one argument from one rule on one path
SecRule REQUEST_URI "@beginsWith /api/comments" \
  "id:1000,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:body"

# Exclude a parameter from a rule globally (configure-time)
SecRuleUpdateTargetById 941160 "!ARGS:html_content"

# Remove rule only for an endpoint (last resort)
SecRule REQUEST_URI "@streq /admin/import" "id:1001,phase:1,pass,nolog,ctl:ruleRemoveById=920420"
```

Never disable whole categories (942xxx) globally to fix one form.

---

## 3. Virtual Patching

```apache
# Example: block exploitation pattern for a vulnerable endpoint until patched
SecRule REQUEST_URI "@beginsWith /vulnapp/upload" \
  "id:1100,phase:2,deny,status:403,log,msg:'Virtual patch CVE-XXXX-YYYY',chain"
  SecRule FILES_NAMES|ARGS:filename "@rx \.(jsp|jspx|php|phtml|aspx?)$" "t:lowercase"
```

Write patches against the vulnerable parameter/path specifically; validate with the PoC request in staging; record CVE + removal date.

---

## 4. Cloud WAFs

| Platform | Notes |
|---|---|
| AWS WAF | Managed rule groups: Core rule set (CRS), Known bad inputs (incl. Log4j patterns), SQL database, Linux/Windows/PHP, IP reputation, Anonymous IP, Bot Control, ATP/ACFP (account takeover/creation fraud); rate-based rules; count mode for testing |
| Azure WAF (Front Door / App Gateway) | Default Rule Set / Microsoft-managed DRS (CRS-derived), bot manager, custom rules, exclusions per rule |
| Cloudflare | Managed rulesets (Cloudflare + OWASP), rate limiting, bot management, WAF attack score |
| Akamai | Adaptive Security Engine, App & API Protector |

Origin protection: restrict origin to accept traffic only from the WAF/CDN (IP allowlist, mTLS, secret header) — otherwise attackers bypass via direct origin IP.

---

## 5. Rate Limiting & Bots

- Per-IP and per-session limits on login, password reset, OTP, search, checkout
- Credential stuffing signals: many usernames per IP, high failure ratio, residential proxy ASNs
- Challenge (JS/CAPTCHA/managed challenge) before block for ambiguous traffic

---

## 6. Bypass Classes to Test

| Class | Defense |
|---|---|
| Encoding (double URL, Unicode, overlong UTF-8, HTML entities) | Normalize (`t:urlDecodeUni`, `t:htmlEntityDecode`) before matching |
| JSON / XML / multipart bodies not parsed | Enable body processors (`requestBodyProcessor=JSON`) for API content types |
| Oversized bodies beyond inspection limit | Set `SecRequestBodyLimit`; block if over (`SecRequestBodyLimitAction Reject`) |
| Parameter pollution (dup params) | Inspect all values |
| HTTP request smuggling (CL.TE / TE.CL / H2 downgrade) | Normalize at edge; reject ambiguous requests; consistent parsing front/back |
| Case/whitespace/comment tricks in SQL | CRS handles many; PL2 catches more |
| Direct-to-origin | Origin lockdown |

---

## 7. Logging & Detection

```bash
# ModSecurity audit log (JSON) — top triggered rules
jq -r '.transaction.messages[]?.details.ruleId' audit.json | sort | uniq -c | sort -nr | head
# Top attacking IPs blocked
jq -r 'select(.transaction.response.http_code==403) | .transaction.client_ip' audit.json | sort | uniq -c | sort -nr | head
```

SIEM: alert on (a) anomaly score above threshold from same IP across many URIs (scanning), (b) blocked requests followed by 200s with similar payloads (bypass), (c) virtual patch hits.

---

## Engagement Cheatsheet

```text
DetectionOnly + PL1 → tune narrow exclusions → blocking → raise PL for sensitive apps
→ virtual patches per CVE → origin lockdown → rate limits → SIEM alerts on score/bypass patterns
```

---

## Key References

- OWASP CRS — https://coreruleset.org ; ModSecurity v3 / Coraza
- AWS WAF managed rules; Azure WAF DRS; Cloudflare WAF docs
- Related: `defensive-secure-code-review`, `defensive-api-security`
