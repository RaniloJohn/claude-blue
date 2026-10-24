---
name: defensive-security-awareness
description: "Security awareness and culture program design: role-based training (general staff, executives, finance, help desk, developers, admins), behavior-focused topics (phishing and QR phishing, MFA fatigue, help-desk and vishing scams, deepfake payment fraud, ClickFix fake CAPTCHA paste-and-run lures, safe AI tool use, data handling), phishing simulations done ethically, reporting culture (report button, no-blame), metrics that matter (report rate and time-to-report over click rate), security champions, onboarding/offboarding, regulatory training requirements, and measuring program effectiveness. Use when building or improving a security awareness program."
---

# Security Awareness & Culture

Awareness programs succeed when they change **specific behaviors** — reporting suspicious messages fast, verifying payment changes, refusing MFA prompts — not when they maximize training completion.

## Quick Workflow

1. Identify top human-risk behaviors from incidents and threat intel
2. Build role-based modules (short, frequent, relevant)
3. Make reporting easy (one-click button) and rewarded
4. Run ethical simulations aligned to real threats
5. Measure behavior (report rate, time-to-report, verified callbacks); iterate quarterly

---

## 1. Behavior Targets

| Threat | Desired behavior |
|---|---|
| Phishing / QR phishing | Report via button; don't scan QR codes in unexpected emails |
| MFA fatigue / unexpected prompts | Deny and report any unexpected MFA prompt; number matching awareness |
| Help desk / vishing impersonation | Help desk verifies identity via callback to known number/manager approval; employees never read codes aloud |
| Deepfake voice/video payment fraud | Out-of-band verification for any payment/bank-detail change, regardless of seniority |
| ClickFix / fake CAPTCHA ("press Win+R, paste, Enter") | Never paste commands from websites into Run/terminal; report the page |
| Malicious attachments / downloads | Don't enable content/macros; download software only from approved portal |
| AI tool use | Only approved tools; no confidential data in public AI; verify AI output |
| Data handling | Classify, share via approved tools, no personal email/cloud for work data |
| Physical | Badge in individually, challenge tailgaters, lock screens |

---

## 2. Role-Based Content

| Role | Focus |
|---|---|
| All staff | Reporting, phishing, MFA, passwords/passkeys, data handling, AI use |
| Executives & assistants | Whaling, deepfake fraud, travel security, social media exposure |
| Finance / AP | Vendor bank change fraud (BEC), payment verification procedures |
| Help desk | Identity verification scripts, social engineering scenarios (Scattered Spider-style) |
| Developers | Secrets handling, dependency risks, secure coding |
| Admins | Privileged account hygiene, PAWs, phishing-resistant MFA, change control |
| HR / recruiters | Malicious résumés, fake candidates (including remote IT worker fraud) |

---

## 3. Phishing Simulations (ethical)

- Mirror real threats, not humiliation (avoid fake bonuses/layoffs/health scares that erode trust)
- Teach at the moment of failure (short landing page), never public shaming
- Vary difficulty; include QR codes, callback phishing, MFA prompts (where tooling supports)
- Coordinate with SOC; exclude during incidents; respect works councils/unions and local law
- Reward reporters; measure reports from real phish too

---

## 4. Metrics

| Metric | Why it matters |
|---|---|
| **Report rate** (simulations and real) | Primary indicator of a sensor-like workforce |
| **Time to first report** | Faster reports = faster SOC response and purge |
| Click/credential-submission rate | Secondary; trend only |
| Repeat clickers trend | Targeted coaching |
| Verified callbacks on payment changes (finance) | Process adherence |
| Training completion | Compliance only, not effectiveness |

---

## 5. Culture

- Security champions network per department
- No-blame reporting ("thank you for reporting, even if you clicked")
- Leadership participation and messaging
- Short monthly micro-learnings + timely threat bulletins (e.g., current scam waves)
- Feedback loop: tell reporters what happened to their report

---

## Engagement Cheatsheet

```text
top behaviors from incidents/intel → role-based micro-modules (exec, finance, help desk, devs, admins, HR) → one-click reporting + no-blame
→ ethical simulations incl. QR/vishing/ClickFix → metrics: report rate & time-to-report first → champions + leadership + feedback loop
```

---

## Key References

- NIST SP 800-50 Rev 1 (Building a Cybersecurity and Privacy Learning Program); SANS Security Awareness Report; CISA phishing guidance
- Related: `defensive-phishing-triage`, `defensive-bec-response`, `defensive-policy-standards`
