---
name: defensive-tool-falco
description: "Falco runtime security for Linux, containers, and Kubernetes from official docs: current release line (0.45.x), driver choice (modern eBPF, kernel module) after removal of the legacy eBPF probe, gVisor engine, and gRPC output in 0.44, Helm deployment, rules/macros/lists and exceptions, writing and testing custom rules, falcoctl for signed rules/plugin artifacts, plugins (k8saudit, cloudtrail, okta, github), outputs (JSON, HTTP, Falcosidekick fan-out), Falco Talon response, capture recording, tuning noisy defaults, protecting Falco itself (privileged DaemonSet, rule tampering), and performance. Use when deploying, tuning, or writing Falco detections."
---

# Falco

Falco watches syscalls (and plugin event sources like Kubernetes audit or CloudTrail) and alerts on rule matches. Version observed: 0.45.1 (2026-10-23).

## Quick Workflow

1. Choose driver: **modern eBPF** (recommended on supported kernels) or kernel module
2. Deploy via Helm with JSON output to Falcosidekick → SIEM/chat
3. Start with default rules; tune with exceptions; add custom rules for your workloads
4. Manage rules/plugins as signed artifacts with falcoctl
5. Protect the Falco namespace and rule configuration

---

## 1. Release Notes That Matter

| Version | Change |
|---|---|
| 0.42 (Oct 2025) | Capture recording feature, performance work |
| 0.43 (Jan 2026) | Stabilization |
| 0.44 (May 2026) | **Removed** legacy eBPF probe, gVisor engine, and gRPC output — migrate to modern eBPF/kmod and HTTP/Falcosidekick outputs |
| 0.45 (Sep 2026) | Raw byte matching in conditions, reload status/control endpoints, upgrade and container metadata fixes |

---

## 2. Deploy (Helm)

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set falco.json_output=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.webhook.address=https://soar.example.local/falco
```

Host install: packages from falco.org repo; `falco --version`; config `/etc/falco/falco.yaml`; rules in `/etc/falco/rules.d/`.

---

## 3. Rules

```yaml
- list: allowed_shell_images
  items: [registry.example.local/debug-tools]

- macro: in_allowed_debug_image
  condition: container.image.repository in (allowed_shell_images)

- rule: Shell Spawned In Production Container
  desc: Interactive shell started inside a container outside approved debug images
  condition: >
    spawned_process and container and proc.name in (shell_binaries)
    and proc.tty != 0 and not in_allowed_debug_image
    and k8s.ns.name in (prod, payments)
  output: >
    Shell in container (user=%user.name cmd=%proc.cmdline container=%container.name
    image=%container.image.repository ns=%k8s.ns.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [container, shell, mitre_execution, T1059]

- rule: Write Below Etc In Container
  desc: File opened for writing under /etc inside a container
  condition: open_write and container and fd.name startswith /etc/
  output: "Write below /etc (file=%fd.name cmd=%proc.cmdline image=%container.image.repository)"
  priority: ERROR
  exceptions:
    - name: known_writers
      fields: [proc.name, fd.name]
      comps: [=, =]
      values:
        - [nginx-reloader, /etc/nginx/nginx.conf]
```

Test rules: `falco -r my_rules.yaml --dry-run`/validate (`falco -V my_rules.yaml`), then trigger with event-generator (`falcosecurity/event-generator`) in a test cluster.

---

## 4. Artifacts, Plugins, Outputs

| Item | Notes |
|---|---|
| falcoctl | Install/update rules and plugins as OCI artifacts; enable signature verification; pin versions |
| Plugins | `k8saudit` (Kubernetes audit logs), `cloudtrail`, `okta`, `github`, `container` metadata — each adds an event source |
| Outputs | stdout/file/program/HTTP; JSON output; **Falcosidekick** fans out to 50+ targets (Slack, Elasticsearch, Loki, SIEM webhooks) |
| Falco Talon | Response engine (kill pod, label, network policy) — restrict to high-confidence rules |
| Capture | Record syscall captures around alerts for investigation (0.42+) |

---

## 5. Tuning

- Disable rules irrelevant to your environment via `rules.d` overrides (`enabled: false`) rather than editing defaults
- Use `exceptions` with specific fields (image, process, path) — avoid broad `not proc.name in (...)`
- Watch rule priority distribution; send DEBUG/INFO to cheap storage only
- Baseline new workloads in staging

---

## 6. Protecting Falco

| Risk | Control |
|---|---|
| Privileged DaemonSet | Dedicated namespace, RBAC limiting who can edit/delete, PodSecurity exceptions scoped to Falco only |
| Rule tampering | Rules from Git via CI/falcoctl; alert on ConfigMap changes in falco namespace (k8saudit) |
| Falco disabled/killed | Alert on DaemonSet pods not ready, no events from a node, Falcosidekick heartbeat |
| Output leakage | TLS to outputs; command lines may contain secrets — restrict access |

---

## Engagement Cheatsheet

```text
0.45.x + modern_ebpf (legacy eBPF/gVisor/gRPC gone since 0.44) → Helm + JSON + Falcosidekick → default rules → exceptions tuning
→ custom rules (lists/macros/rules, tags w/ ATT&CK) → dry-run + event-generator tests → falcoctl signed artifacts → plugins (k8saudit/cloudtrail)
→ Talon only for high-confidence → protect namespace + heartbeat alerts
```

---

## Key References

- falco.org docs (rules, drivers, outputs, plugins, falcoctl) and release blog posts (0.42–0.45)
- Related: `defensive-k8s-security`, `defensive-container-hardening`, `defensive-linux-telemetry`
