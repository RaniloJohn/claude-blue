---
name: defensive-mobile-app-security
description: "Securing mobile applications (Android and iOS) using OWASP MASVS and MASTG: secure data storage (Keychain, Android Keystore, EncryptedSharedPreferences/DataStore alternatives), authentication and session handling, network security (TLS, certificate pinning trade-offs, Android Network Security Config, iOS ATS), platform interaction (intents, deep links, WebViews, exported components), code protection and anti-tampering (Play Integrity API, App Attest), secrets in apps, third-party SDK risks, privacy requirements (permissions, App Store privacy labels, Play data safety), testing tools (MobSF, Frida, objection, jadx, apktool), and CI integration. Use when building, reviewing, or testing mobile apps."
---

# Mobile App Security

Mobile apps run on devices you don't control. Assume the attacker has the binary, can root/jailbreak the device, and can intercept traffic — then design so that compromise of one device doesn't compromise users or the backend.

## Quick Workflow

1. Threat model the app and its APIs (most real risk is in the backend API — `defensive-api-security`)
2. Apply OWASP MASVS controls by category (§1)
3. Test with MASTG techniques and tools (§3)
4. Automate SAST/DAST in CI; review SDKs
5. Monitor abuse (attestation, rate limits, fraud signals)

---

## 1. MASVS Categories → Practices

| Category | Key practices |
|---|---|
| MASVS-STORAGE | No sensitive data in plaintext files, logs, backups, clipboard; iOS Keychain with appropriate accessibility (`ThisDeviceOnly`); Android Keystore-backed keys; exclude sensitive files from backups |
| MASVS-CRYPTO | Platform crypto APIs; no hardcoded keys; AES-GCM; keys in hardware-backed keystores |
| MASVS-AUTH | Server-side session management; OAuth 2.0 with PKCE (AppAuth); biometrics bound to Keystore/Keychain keys (not just a boolean check); short-lived tokens, refresh token rotation |
| MASVS-NETWORK | TLS only (Android Network Security Config `cleartextTrafficPermitted="false"`; iOS ATS on); consider pinning for high-risk apps with rotation plan (backup pins) |
| MASVS-PLATFORM | Exported components minimized (`android:exported` explicit); validate intents and deep links/App Links/Universal Links; WebViews: disable JS/file access unless needed, no `addJavascriptInterface` with untrusted content |
| MASVS-CODE | Keep dependencies updated; input validation; minimum OS versions supported with security patches |
| MASVS-RESILIENCE | Root/jailbreak and tamper detection, obfuscation (R8/ProGuard, commercial), runtime integrity — defense-in-depth only, never the primary control |
| MASVS-PRIVACY | Minimal permissions, data minimization, accurate store privacy disclosures, user consent for tracking |

---

## 2. Backend & Abuse Protections

- **App attestation**: Google Play Integrity API (Android), App Attest / DeviceCheck (iOS) verified **server-side**
- Never trust client-side checks for authorization or pricing
- Rate limiting, bot detection, anomaly detection on API endpoints
- Secrets: no API keys with privileged scope in the app; use backend proxies, scoped and rotatable keys

---

## 3. Testing Tools

| Tool | Use |
|---|---|
| MobSF | Automated static/dynamic analysis for APK/IPA |
| jadx / apktool | Decompile Android, inspect manifest and code |
| Frida / objection | Runtime instrumentation (test pinning, storage, jailbreak detection) on test devices |
| Burp Suite / mitmproxy | Traffic interception (test device with user CA; Android 7+ apps ignore user CAs unless configured — use test builds) |
| `adb`, Android Studio emulator, Corellium (commercial) | Test environments |

```bash
apktool d app.apk -o app_src && grep -n 'exported="true"' app_src/AndroidManifest.xml
jadx -d app_java app.apk && grep -rnE "(api[_-]?key|secret|password)\s*=\s*\"" app_java | head
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Test only apps you own or are authorized to assess.

---

## 4. CI/CD

SAST for Kotlin/Java/Swift (Semgrep, CodeQL — `defensive-tool-sast`), dependency scanning (Gradle/CocoaPods/SPM), MobSF in pipeline, signing key protection (Play App Signing, keys in HSM/secure CI secrets), reproducible release process.

---

## 5. Third-Party SDKs

Inventory SDKs (analytics, ads, crash reporting); review data collection and permissions; keep updated; malicious or vulnerable SDKs have caused large-scale data leaks — vet before adding.

---

## Engagement Cheatsheet

```text
threat model app + API → MASVS: storage (Keychain/Keystore, no logs/backups), crypto, auth (PKCE, key-bound biometrics), network (ATS/NSC, pinning w/ backups),
platform (exported components, deep links, WebViews), code, resilience (secondary), privacy → server-side attestation (Play Integrity/App Attest) + rate limits
→ MASTG testing (MobSF, jadx, Frida, Burp) → CI SAST/SCA + signing key protection → SDK vetting
```

---

## Key References

- OWASP MASVS v2 and MASTG; Android security best practices; Apple Platform Security Guide; Play Integrity API & App Attest docs
- Related: `defensive-api-security`, `defensive-secure-code-review`, `defensive-tool-sast`, `defensive-auth-implementation`
