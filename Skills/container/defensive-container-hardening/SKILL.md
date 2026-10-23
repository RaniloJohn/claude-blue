---
name: defensive-container-hardening
description: "Container image and runtime hardening for Docker and OCI workloads: minimal/distroless base images, multi-stage builds, non-root users, read-only root filesystems, dropped Linux capabilities, seccomp and AppArmor/SELinux profiles, no privileged containers or host mounts (docker.sock, /, /proc), rootless Docker/Podman, user namespaces, image scanning (Trivy, Grype, Docker Scout), image signing and verification (Sigstore cosign), registry security, Docker daemon hardening (CIS Docker Benchmark, docker-bench-security), and runtime detection with Falco. Use when building images, reviewing Dockerfiles/compose files, or securing container hosts."
---

# Container Hardening

A container is a process with namespaces and cgroups — not a security boundary by default. Hardening removes privileges the process doesn't need so a compromise stays inside.

## Quick Workflow

1. Minimal base, multi-stage build, pinned digests
2. Non-root user; read-only FS; drop capabilities
3. Default seccomp + AppArmor/SELinux
4. Scan and sign images; verify at deploy
5. Harden daemon/host; never expose `docker.sock`
6. Runtime detection (Falco/EDR)

---

## 1. Dockerfile

```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.23@sha256:<digest> AS build
WORKDIR /src
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

Checklist:

```text
[ ] Base pinned by digest; minimal (distroless, Chainguard/Wolfi, alpine, scratch)
[ ] Multi-stage: no compilers/package managers in final image
[ ] USER non-root (numeric UID)
[ ] No secrets in layers (use BuildKit --secret; check `docker history`)
[ ] COPY specific files; .dockerignore excludes .git, .env, keys
[ ] HEALTHCHECK defined; no SSH daemon in image
[ ] Labels: source repo, commit, SBOM reference
```

---

## 2. Runtime Flags

```bash
docker run -d --name app \
  --user 65532:65532 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=default \
  --pids-limit 200 --memory 512m --cpus 1 \
  --network app-net \
  app@sha256:<digest>
```

Never: `--privileged`, `-v /var/run/docker.sock:/var/run/docker.sock`, `-v /:/host`, `--pid=host`, `--net=host` (unless justified), `--cap-add SYS_ADMIN`, `--security-opt seccomp=unconfined`, `apparmor=unconfined`.

---

## 3. Dangerous Capabilities

| Capability | Risk |
|---|---|
| `SYS_ADMIN` | Mounts, cgroups → escape vectors |
| `SYS_PTRACE` | Inspect/inject other processes |
| `SYS_MODULE` | Load kernel modules |
| `DAC_READ_SEARCH` | Bypass file read permission checks (shocker-style escapes) |
| `NET_ADMIN` / `NET_RAW` | Network manipulation, ARP spoofing in cluster networks |
| `SYS_RAWIO`, `MKNOD` | Raw device access |

---

## 4. Image Scanning & Signing

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed registry/app@sha256:<digest>
grype registry/app@sha256:<digest>
syft registry/app@sha256:<digest> -o cyclonedx-json > sbom.cdx.json
cosign sign --yes registry/app@sha256:<digest>                     # keyless (OIDC) signing
cosign verify registry/app@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/org/repo/.github/workflows/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign attest --yes --predicate sbom.cdx.json --type cyclonedx registry/app@sha256:<digest>
```

Enforce verification at admission (Kyverno `verifyImages`, Sigstore policy-controller) — see `defensive-k8s-security`.

Scanner supply chain: pin scanner versions/digests and verify releases — security tooling distributed via CI marketplaces has itself been targeted.

---

## 5. Daemon & Host

```text
[ ] Docker daemon not exposed on TCP without mTLS (2375 = unauthenticated RCE)
[ ] userns-remap or rootless mode where feasible
[ ] /etc/docker/daemon.json: "no-new-privileges": true, "live-restore": true, "userland-proxy": false, "icc": false (if not needed)
[ ] Audit Docker files with auditd (/usr/bin/dockerd, /var/lib/docker, /etc/docker, docker.sock)
[ ] Host OS minimal (Bottlerocket, Flatcar, Talos for K8s nodes), patched kernel
[ ] docker-bench-security / CIS Docker Benchmark
```

---

## 6. Runtime Detection

| Behavior | Falco/EDR signal |
|---|---|
| Shell in container | `spawned_process and container and shell_procs` |
| Package manager at runtime | `apt`, `apk`, `yum` exec in running container |
| Write to binary dirs | Writes under `/bin`, `/usr/bin` |
| Sensitive mounts | Container started with docker.sock / host `/` |
| Escape attempts | `nsenter`, `mount`, writes to `release_agent`, `core_pattern` |
| Crypto mining | Stratum connections, `xmrig` |
| Outbound to unexpected destinations | Egress policy violations |

---

## Engagement Cheatsheet

```text
distroless + digest pin + multi-stage → non-root + read-only + cap-drop ALL + no-new-privileges + seccomp
→ scan (Trivy/Grype) + SBOM (Syft) + sign (cosign) → admission verify → daemon hardening → Falco
```

---

## Key References

- CIS Docker Benchmark; NIST SP 800-190 Application Container Security Guide
- OWASP Docker Security Cheat Sheet
- Sigstore cosign docs; Trivy; Grype/Syft
- Related: `defensive-k8s-security`, `defensive-sbom-slsa`, `defensive-linux-telemetry`
