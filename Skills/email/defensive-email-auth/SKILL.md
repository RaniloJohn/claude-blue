---
name: defensive-email-auth
description: "Email authentication and domain anti-spoofing: SPF (mechanisms, 10-lookup limit, ~all vs -all), DKIM (selectors, 2048-bit keys, rotation), DMARC per DMARCbis RFC 9989/9990/9991 (May 2026: p/sp/np, t= testing flag replacing pct, DNS tree walk replacing PSL, rua aggregate reports, adkim/aspf alignment), ARC, MTA-STS and TLS-RPT, DANE, BIMI, bulk sender requirements (Google, Yahoo, Microsoft), parked-domain protection, rollout from p=none to p=reject, and reading aggregate reports. Use when configuring email authentication, investigating spoofing, or interpreting DMARC/SPF/DKIM results in headers."
---

# Email Authentication (SPF, DKIM, DMARC)

SPF and DKIM authenticate infrastructure; DMARC ties them to the visible From domain and tells receivers what to do on failure. Goal: `p=reject` on every domain you own — including ones that never send mail.

## Quick Workflow

1. Inventory all senders (M365/Workspace, marketing, ticketing, HR, billing, on-prem relays)
2. Publish SPF and DKIM for each sender
3. Publish DMARC `p=none` with `rua` reporting
4. Analyze reports; fix alignment for legitimate senders
5. Move to `quarantine` → `reject`
6. Lock down parked domains; add MTA-STS/TLS-RPT

---

## 1. SPF

```dns
example.com.  TXT  "v=spf1 include:spf.protection.outlook.com include:_spf.google.com ip4:203.0.113.10 -all"
```

| Item | Rule |
|---|---|
| DNS lookup limit | Max 10 (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) — exceed → permerror |
| `-all` vs `~all` | `-all` hard fail; with DMARC enforcement `~all` is acceptable since DMARC decides |
| `ptr` | Deprecated — don't use |
| Checks | Envelope sender (`MAIL FROM`/Return-Path) — not the visible From; DMARCbis clarifies SPF alignment uses MAIL FROM, not HELO |

Parked domain: `"v=spf1 -all"`.

---

## 2. DKIM

```dns
s1._domainkey.example.com. TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."
```

- 2048-bit RSA (Ed25519 supported by some receivers as additional signature)
- Unique selector per sending service; rotate keys at least annually
- Sign with `d=` = your domain (or subdomain) for DMARC alignment

---

## 3. DMARC (RFC 9989 — DMARCbis)

DMARCbis was published in **May 2026** as RFC 9989 (protocol, Standards Track), RFC 9990 (aggregate reporting), RFC 9991 (failure reporting), obsoleting RFC 7489 and RFC 9091. Records still start with `v=DMARC1` — existing records keep working.

```dns
_dmarc.example.com. TXT "v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=r; rua=mailto:dmarc-rua@example.com; fo=1"
```

| Tag | Meaning |
|---|---|
| `p` | Policy for the domain: none / quarantine / reject |
| `sp` | Policy for existing subdomains |
| `np` | **New (RFC 9989)**: policy for non-existent subdomains |
| `t` | **New**: `t=y` testing mode (replaces `pct=0` style rollouts); `t=n` normal |
| `adkim` / `aspf` | Alignment strictness: r (relaxed, org domain) / s (strict, exact) |
| `rua` | Aggregate report destinations |
| `ruf` / `fo` | Failure reports (privacy-sensitive; many receivers don't send) |
| Removed | `pct`, `rf`, `ri` — drop them from records |

Policy discovery now uses a **DNS tree walk** instead of the Public Suffix List. DMARCbis discourages `p=reject` for domains whose users post to mailing lists unless risk is assessed.

DMARC passes if **SPF passes and aligns** OR **DKIM passes and aligns** with the From domain.

---

## 4. Rollout

| Phase | Record | Duration |
|---|---|---|
| Monitor | `p=none; rua=...` | 2–6 weeks, until all legit senders known |
| Test enforcement | `p=quarantine; t=y` (or staged `p=quarantine`) | 2–4 weeks |
| Quarantine | `p=quarantine` | 2–4 weeks |
| Reject | `p=reject; sp=reject; np=reject` | Permanent |

Aggregate report analysis: parse XML (dmarcian, Valimail, EasyDMARC, Postmark, parsedmarc + Elastic) — identify sources failing alignment; fix SPF includes/DKIM signing or move them to subdomains.

---

## 5. Transport Security

| Control | Record |
|---|---|
| MTA-STS (RFC 8461) | `_mta-sts.example.com TXT "v=STSv1; id=20261023"` + policy at `https://mta-sts.example.com/.well-known/mta-sts.txt` (`mode: enforce`, `mx:` entries, `max_age`) |
| TLS-RPT (RFC 8460) | `_smtp._tls.example.com TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"` |
| DANE (RFC 7672) | TLSA records; requires DNSSEC |
| BIMI | `default._bimi.example.com TXT "v=BIMI1; l=https://.../logo.svg; a=https://.../vmc.pem"`; requires DMARC enforcement (+ VMC/CMC for Gmail logo display) |

---

## 6. Bulk Sender Requirements

Google and Yahoo (Feb 2024) and Microsoft Outlook.com (May 2025) require for high-volume senders: SPF + DKIM, DMARC (at least `p=none`) aligned, one-click unsubscribe (RFC 8058) for marketing, low spam rates, valid forward/reverse DNS, TLS.

---

## 7. Reading Authentication Results

```text
Authentication-Results: mx.example.net;
  spf=pass smtp.mailfrom=bounce.vendor.com;
  dkim=pass header.d=vendor.com;
  dmarc=fail (p=REJECT) header.from=example.com
```

→ SPF/DKIM passed for `vendor.com` but neither aligns with `example.com` From → DMARC fail. Fix: vendor signs with `d=example.com` (custom DKIM) or uses `example.com` subdomain for bounce.

Spoof investigation: compare `From`, `Reply-To`, `Return-Path`, `Received` chain origin, ARC headers (forwarding), and DMARC result.

---

## Engagement Cheatsheet

```text
sender inventory → SPF (≤10 lookups) + DKIM 2048 per sender → DMARC p=none + rua → fix alignment
→ quarantine → reject (sp/np too) → parked domains locked → MTA-STS + TLS-RPT → BIMI optional
```

---

## Key References

- RFC 9989 (DMARC), RFC 9990 (aggregate reports), RFC 9991 (failure reports) — May 2026
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 8617 (ARC)
- Google/Yahoo/Microsoft sender requirements
- Related: `defensive-phishing-triage`, `defensive-bec-response`
