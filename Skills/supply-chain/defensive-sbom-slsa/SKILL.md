---
name: defensive-sbom-slsa
description: "Software supply chain integrity: SBOM generation and consumption (CycloneDX 1.6/1.7 incl. CBOM, SPDX 2.3/3.0, Syft, cdxgen, Trivy), VEX for exploitability statements (OpenVEX, CSAF VEX, CycloneDX VEX), SLSA v1.x build provenance levels, in-toto attestations, Sigstore (cosign, Rekor, Fulcio) signing and verification, GitHub artifact attestations, dependency pinning and lockfiles, dependency confusion and typosquatting defenses (scoped packages, private registries, allowlists), malicious package detection, OpenSSF Scorecard, and responding to compromised upstream packages (npm worms, protestware). Use when securing dependencies, producing SBOMs, or responding to a supply chain incident."
---

# SBOM, SLSA & Dependency Integrity

Know what you ship (SBOM), prove how it was built (provenance), verify before you run it (signatures/policies), and respond fast when an upstream component turns malicious.

## Quick Workflow

1. Lockfiles + pinned versions/digests everywhere
2. Private registry/proxy with allowlists and scoped namespaces
3. Generate SBOM per build; store with artifact
4. Sign artifacts and attestations; verify at deploy
5. Monitor dependencies (vulns + malicious packages)
6. Incident playbook for compromised upstreams

---

## 1. SBOM Formats

| Format | Current | Notes |
|---|---|---|
| CycloneDX | 1.7 (Oct 2025; ECMA-424 2nd ed.), 1.6 widely supported | Security-oriented; VEX, CBOM (crypto), ML-BOM, services, attestations |
| SPDX | 2.3 (most tooling), 3.0 (graph model, profiles incl. security/build/AI) | ISO/IEC 5962 (2.2.1); license-oriented heritage |

```bash
syft dir:. -o cyclonedx-json=sbom.cdx.json
syft registry/app@sha256:<digest> -o spdx-json=sbom.spdx.json
cdxgen -r -o bom.json .
trivy image --format cyclonedx --output sbom.cdx.json registry/app@sha256:<digest>
grype sbom:./sbom.cdx.json                 # vuln scan from SBOM
```

Minimum elements (NTIA/CISA): supplier, component name, version, unique identifier (purl/CPE), dependency relationships, author, timestamp.

---

## 2. VEX

VEX states whether a vulnerability affects a product: `not_affected` (with justification), `affected`, `fixed`, `under_investigation`.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2026-001",
  "author": "Example Security",
  "timestamp": "2026-10-23T00:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": { "name": "CVE-2026-XXXX" },
    "products": [{ "@id": "pkg:oci/app@sha256:<digest>" }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path"
  }]
}
```

Consume VEX in scanners (Trivy `--vex`, Grype) to suppress non-exploitable findings with evidence.

---

## 3. SLSA (v1.x Build Track)

| Level | Requirement |
|---|---|
| Build L0 | No guarantees |
| Build L1 | Provenance exists (documents how it was built) |
| Build L2 | Hosted build platform; signed provenance |
| Build L3 | Hardened build platform: isolated builds, non-falsifiable provenance, secrets not accessible to user-defined steps |

Generate: GitHub artifact attestations (`actions/attest-build-provenance`), SLSA GitHub generator, GitLab provenance, Tekton Chains.

**Lesson (2026 cache-poisoning campaigns):** attackers poisoned CI caches so legitimate release workflows produced malicious packages with *valid* SLSA L3 provenance. Provenance attests the builder and source, not the cleanliness of inputs. Pair with: cache isolation for release builds, dependency pinning, reproducible builds where feasible, and review of build inputs.

---

## 4. Signing & Verification

```bash
cosign sign --yes registry/app@sha256:<digest>
cosign verify registry/app@sha256:<digest> \
  --certificate-identity "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://registry/app@sha256:<digest> --owner org
npm audit signatures                       # verify npm registry signatures/provenance
```

Enforce at admission (Kyverno `verifyImages`, Sigstore policy-controller) and in deploy pipelines.

---

## 5. Dependency Defenses

| Threat | Defense |
|---|---|
| Dependency confusion | Scoped/namespaced packages (`@org/`), private registry as single source, block public fallthrough for internal names, reserve internal names publicly |
| Typosquatting | Allowlisted dependencies; review new deps in PR; tools that flag new/low-reputation packages |
| Compromised maintainer / malicious version | Lockfiles; delayed adoption (e.g., minimum release age policies in npm/pnpm/Renovate); install with `--ignore-scripts` where possible; monitor malicious-package feeds (OSV `MAL-` advisories, Socket, GitHub) |
| Install-time scripts (postinstall/preinstall worms) | `npm ci --ignore-scripts`; pnpm `onlyBuiltDependencies`; sandboxed builds |
| Unmaintained deps | OpenSSF Scorecard, deps.dev |
| Protestware | Pin + review updates |

---

## 6. Compromised Upstream Playbook

```text
1. Identify affected package/versions and exposure window (install times in lockfiles, CI logs, artifact SBOMs)
2. Query SBOM inventory: which apps/images include the bad versions?
3. Treat build systems and dev machines that installed it as compromised: rotate tokens/secrets they could access (npm, GitHub, cloud, SSH)
4. Hunt for IOCs: worm-created repos/workflows, outbound to exfil hosts, new tokens/keys
5. Rebuild from clean dependencies; republish if you are a maintainer; notify consumers
6. Pin known-good versions; add malicious-package detection to CI
```

The Shai-Hulud worm family (npm, Sept 2025 → 2026 variants) stole npm/GitHub/cloud credentials via install scripts and republished itself — SBOM + lockfile inventory is what makes scoping possible.

---

## Engagement Cheatsheet

```text
lockfiles + pins → private registry + scopes → SBOM per build (CycloneDX/SPDX) → VEX for not_affected
→ provenance (SLSA) + signing (cosign/attestations) → verify at deploy → malicious-package monitoring
→ compromised-upstream playbook (inventory → rotate → hunt → rebuild)
```

---

## Key References

- CycloneDX — https://cyclonedx.org (v1.7) ; SPDX — https://spdx.dev (3.0)
- SLSA — https://slsa.dev ; in-toto ; Sigstore — https://sigstore.dev
- OpenVEX; CISA SBOM minimum elements; OpenSSF Scorecard
- Related: `defensive-cicd-hardening`, `defensive-vuln-management`, `defensive-container-hardening`
