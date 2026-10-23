---
name: defensive-tool-container-scanners
description: "Vulnerability, misconfiguration, secret, and SBOM scanning with Trivy, Grype, and Syft: safe acquisition after the March 2026 Trivy supply chain compromise (CVE-2026-33634 — malicious v0.69.4 and force-pushed trivy-action/setup-trivy tags), pinning actions and images by SHA/digest, minimal CI tokens, vulnerability DB mirroring for air-gapped use, Trivy image/fs/config/k8s/sbom scanners, severity gating with ignore-unfixed and VEX, .trivyignore governance, Syft SBOM generation (CycloneDX/SPDX), Grype SBOM scanning with fail-on thresholds, CI integration patterns, and interpreting results. Use when scanning containers/IaC/repositories in CI or auditing scanner usage."
---

# Container & Dependency Scanners (Trivy, Grype, Syft)

Scanners sit inside CI with access to source, registries, and often cloud credentials — which is exactly why attackers compromised Trivy in 2026. Scan **and** protect the scanner. Versions observed 2026-10-23: Trivy 0.76.x, Syft 1.55.0, Grype 0.121.0.

## Quick Workflow

1. Acquire pinned, verified versions (digest/SHA pins, signature checks)
2. Give the scan job read-only, minimal credentials
3. Generate SBOM (Syft/Trivy) at build; scan SBOM + image (Grype/Trivy)
4. Gate on fixable HIGH/CRITICAL; track exceptions with expiry; use VEX
5. Store SBOMs and results with the artifact; rescan on new CVEs

---

## 1. Trivy Compromise (CVE-2026-33634 / GHSA-69fq-xp46-6x23)

| Item | Detail |
|---|---|
| Date | March 19, 2026 (continuation of a late-Feb 2026 attack; non-atomic credential rotation after March 1 disclosure let attacker retain access) |
| Malicious | Trivy binary/container **v0.69.4**; `trivy-action` tags 0.0.1–0.34.2 (76 of 77 force-pushed); `setup-trivy` 0.2.0–0.2.6 (all 7 replaced) |
| Payload | Credential stealer; fallback exfil created repos named `tpcp-docs` |
| Safe (per advisory) | Trivy 0.69.2/0.69.3, trivy-action 0.35.0, setup-trivy 0.2.6 (recreated); later releases from the official project |
| Response | Rotate all secrets reachable by affected runs; check logs of March 19–20, 2026 runs; search org for `tpcp-docs`; pin actions by full SHA |

```yaml
# Pin by commit SHA (example placeholder — use the verified SHA of the release you reviewed)
- uses: aquasecurity/trivy-action@<full-40-char-commit-sha>   # v0.35.0+
  with:
    image-ref: registry.example.local/app@sha256:<digest>
    severity: HIGH,CRITICAL
    ignore-unfixed: true
    exit-code: '1'
permissions:
  contents: read
```

---

## 2. Trivy Usage

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 registry.example.local/app@sha256:<digest>
trivy image --scanners vuln,secret,misconfig,license --format sarif -o trivy.sarif app:candidate
trivy fs --scanners vuln,secret,misconfig .
trivy config ./terraform ./k8s                       # IaC misconfiguration
trivy k8s --report summary cluster                   # in-cluster scan (needs kube RBAC read)
trivy image --format cyclonedx -o sbom.cdx.json app@sha256:<digest>
trivy sbom sbom.cdx.json
trivy image --vex vex.openvex.json app@sha256:<digest>   # suppress not-affected findings with VEX
```

Air-gapped/mirrored DB: host the vulnerability DB in an internal OCI registry (`--db-repository`, `--java-db-repository`) and use `--skip-db-update` on runners; refresh the mirror on a schedule.

`.trivyignore` entries must carry reason, owner, expiry (as comments) and be reviewed; prefer VEX statements for "not affected" justifications.

---

## 3. Syft & Grype

```bash
syft registry.example.local/app@sha256:<digest> -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
syft dir:. -o cyclonedx-json=src-sbom.json
grype sbom:./sbom.cdx.json --fail-on high --only-fixed -o sarif > grype.sarif
grype db status && grype db update
grype registry.example.local/app@sha256:<digest> --add-cpes-if-none
```

Attach SBOMs as attestations (`defensive-tool-sigstore-cosign`) so consumers can verify provenance.

---

## 4. Gating Policy

| Finding | Gate |
|---|---|
| CRITICAL/HIGH with fix available | Fail build (main branch); warn on feature branches |
| KEV-listed CVE in image | Fail regardless of severity |
| No fix available | Track; mitigate (minimal base image, distroless, remove package) |
| Secrets | Fail; rotate secret; never just delete from image |
| Misconfig (IaC/K8s) | Fail on high (privileged, hostPath, public buckets, 0.0.0.0/0 admin ports) |
| Licenses | Policy per legal (block AGPL/unknown where prohibited) |

---

## 5. Scanner Hygiene

- Run scanners in ephemeral runners; no long-lived cloud admin creds in the job
- Pull scanner images by digest from a trusted internal mirror
- Verify release signatures/attestations where published
- Monitor scanner projects' security advisories (subscribe to GitHub security advisories)
- Compare two scanners occasionally — different DBs and matchers produce different results

---

## Engagement Cheatsheet

```text
SHA-pinned actions + digest-pinned images + minimal permissions (Trivy 2026 lesson: rotate on exposure, hunt tpcp-docs)
→ Syft/Trivy SBOM (CycloneDX/SPDX) → Trivy/Grype scan with --ignore-unfixed / --only-fixed → gate fixable HIGH/CRIT + KEV
→ VEX/.trivyignore with owner+expiry → internal DB mirror → attest SBOM → rescan on new CVEs
```

---

## Key References

- GHSA-69fq-xp46-6x23 / CVE-2026-33634; trivy.dev docs; github.com/anchore/syft, github.com/anchore/grype
- CycloneDX 1.7; SPDX 3.0; OpenVEX
- Related: `defensive-cicd-hardening`, `defensive-sbom-slsa`, `defensive-container-hardening`, `defensive-tool-safety`
