---
name: defensive-tool-sigstore-cosign
description: "Signing and verifying software artifacts with Sigstore cosign: cosign v3 defaults (new bundle format, trusted root, signing config) and v4 deprecation plans, keyless signing with OIDC identities and Fulcio/Rekor transparency log, verifying with exact certificate identity and OIDC issuer, signing by digest not tag, attestations (SBOM, SLSA provenance, vulnerability scans), key-based signing with KMS/HSM, private Sigstore deployments, GitHub artifact attestations, admission control enforcement (Kyverno, Sigstore policy-controller), and common verification mistakes. Use when signing releases/images or enforcing signature verification in CI/CD and Kubernetes."
---

# Sigstore & Cosign

Signing proves **who built an artifact and that it hasn't changed**; verification only helps if it checks the **right identity**. Cosign 3.1.x observed 2026-10-23.

## Quick Workflow

1. Build → push image → capture **digest**
2. Sign by digest (keyless OIDC in CI, or KMS key)
3. Attach attestations: SBOM, SLSA provenance, scan results
4. Verify in deploy pipeline and at admission with exact identity + issuer
5. Monitor transparency log entries for your identities

---

## 1. Cosign v3 Changes

| Change | Detail |
|---|---|
| New bundle format on by default | Signature, certificate, and transparency proof stored together (offline verification) |
| Trusted root by default | Centralized verification material; supports key rotation without client updates |
| Signing config by default | Transparency log shard rotation without client updates |
| Opt-outs | Still available for private deployments/older formats during transition |
| Migration helpers | `cosign bundle create`, `cosign trusted-root create`, `cosign signing-config create` |
| v4 plan | Removes roughly half of legacy CLI flags — update scripts now |

---

## 2. Keyless Signing in CI (GitHub Actions)

```yaml
permissions:
  id-token: write      # OIDC token for Fulcio
  packages: write
  contents: read
steps:
  - uses: sigstore/cosign-installer@<full-commit-sha>
  - run: cosign sign --yes ghcr.io/org/app@${DIGEST}
  - run: cosign attest --yes --type cyclonedx --predicate sbom.cdx.json ghcr.io/org/app@${DIGEST}
```

---

## 3. Verification

```bash
cosign verify ghcr.io/org/app@sha256:<digest> \
  --certificate-identity 'https://github.com/org/app/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type cyclonedx ghcr.io/org/app@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/org/app/\.github/workflows/release\.yml@refs/(heads/main|tags/v.*)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob --bundle app.tar.gz.sigstore.json app.tar.gz \
  --certificate-identity-regexp '^https://github.com/org/app/' --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify app.tar.gz --repo org/app            # GitHub artifact attestations
```

Mistakes to avoid:
- `--certificate-identity-regexp '.*'` (accepts anyone with a Sigstore identity)
- Verifying tags (mutable) instead of digests
- Not pinning the workflow path/branch in the identity (any workflow in the repo could sign)
- Ignoring attestation predicate content (verify the SBOM/provenance says what you expect)

---

## 4. Key-Based Signing

```bash
cosign generate-key-pair --kms awskms:///alias/cosign-release     # or gcpkms://, azurekms://, hashivault://
cosign sign --key awskms:///alias/cosign-release registry/app@sha256:<digest>
cosign verify --key cosign.pub registry/app@sha256:<digest>
```

Use KMS/HSM keys with restricted IAM; never commit private keys; rotate with documented procedure. Private Sigstore (own Fulcio/Rekor/TUF root) for regulated or air-gapped environments.

---

## 5. Enforcement at Admission

Kyverno `verifyImages` example:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: verify-signed-images }
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  rules:
    - name: require-sigstore-signature
      match: { any: [ { resources: { kinds: [Pod] } } ] }
      verifyImages:
        - imageReferences: ["ghcr.io/org/*"]
          mutateDigest: true
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/org/*/.github/workflows/release.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
```

Alternatives: Sigstore policy-controller (`ClusterImagePolicy`), Connaisseur, Ratify (Notation + cosign). Start in audit mode; exempt system namespaces deliberately.

---

## 6. Monitoring

Search Rekor for unexpected signatures with your identities (`rekor-cli search --email`/identity monitors such as sigstore's rekor-monitor) — signatures you didn't produce indicate a compromised workflow or OIDC trust misconfiguration.

---

## Engagement Cheatsheet

```text
digest → keyless sign in CI (id-token: write, SHA-pinned installer) or KMS key → attest SBOM/provenance
→ verify with exact identity + issuer (no '.*'), by digest → admission enforcement (Kyverno/policy-controller, audit→enforce)
→ cosign v3 bundle/trusted-root defaults, prep for v4 flag removals → Rekor identity monitoring
```

---

## Key References

- docs.sigstore.dev; "Cosign v3 is now available" (Sigstore blog); Kyverno verifyImages docs; SLSA v1.x provenance
- Related: `defensive-sbom-slsa`, `defensive-cicd-hardening`, `defensive-tool-container-scanners`, `defensive-k8s-security`
