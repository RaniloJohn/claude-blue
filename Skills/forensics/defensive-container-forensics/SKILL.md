---
name: defensive-container-forensics
description: "Forensics and incident response for Docker containers and Kubernetes: preserving ephemeral evidence before pods are rescheduled, cordon/isolate with network policies instead of deleting, docker diff/export/inspect/logs, container checkpointing (CRIU, kubelet checkpoint API), collecting overlay filesystem layers, node-level collection (/var/lib/containerd, /var/log/pods, kubelet logs), crictl usage, Kubernetes audit log analysis (exec, secrets access, RBAC changes), Falco capture files, image provenance and digest pinning, cloud-managed clusters (EKS, AKS, GKE) evidence sources, and timeline building. Use when investigating a compromised container, pod, or Kubernetes cluster."
---

# Container & Kubernetes Forensics

Containers are ephemeral by design — the default response (delete the pod) destroys evidence. **Isolate, preserve, then rebuild.**

## Quick Workflow

1. Identify: pod, namespace, node, image digest, service account
2. Isolate: deny-all NetworkPolicy for the pod's labels; cordon the node
3. Preserve: logs, `inspect`, filesystem diff/export, checkpoint (memory), node artifacts
4. Collect control-plane evidence: K8s audit logs, cloud provider logs
5. Analyze; then remove workload, rotate secrets/service account tokens, rebuild from trusted image

---

## 1. Isolate Without Destroying

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: quarantine-case42, namespace: payments }
spec:
  podSelector: { matchLabels: { quarantine: "case42" } }
  policyTypes: [Ingress, Egress]
```

```bash
kubectl label pod web-7f9c -n payments quarantine=case42 --overwrite
kubectl cordon node-12                                   # no new scheduling
kubectl annotate pod web-7f9c -n payments cluster-autoscaler.kubernetes.io/safe-to-evict="false"
```

Remove the pod from Service selectors (change the app label) so traffic stops but the container keeps running. Requires a CNI that enforces NetworkPolicy.

---

## 2. Preserve Container Evidence

```bash
# Kubernetes level
kubectl get pod web-7f9c -n payments -o yaml > pod.yaml
kubectl logs web-7f9c -n payments --all-containers --timestamps > logs.txt
kubectl logs web-7f9c -n payments --previous > logs_prev.txt
kubectl describe pod web-7f9c -n payments > describe.txt
# Docker hosts
docker inspect <id> > inspect.json
docker diff <id> > diff.txt                     # A/C/D changes vs image
docker export <id> -o container_fs.tar           # full filesystem (not volumes)
docker cp <id>:/tmp ./tmp_copy
# containerd nodes
crictl ps -a ; crictl inspect <id> > inspect.json ; crictl logs <id> > logs.txt
```

**Checkpointing (memory + state):** Docker `docker checkpoint create` (experimental, CRIU); Kubernetes kubelet checkpoint API (`POST /checkpoint/{namespace}/{pod}/{container}` on the kubelet; feature gate `ContainerCheckpoint`, beta and enabled by default in recent releases — verify for your version/runtime). Checkpoint archives land on the node (e.g., `/var/lib/kubelet/checkpoints/`) and can be analyzed with checkpointctl or restored in a sandbox.

---

## 3. Node-Level Artifacts

| Artifact | Location |
|---|---|
| Pod logs | `/var/log/pods/<ns>_<pod>_<uid>/`, `/var/log/containers/` |
| containerd state & snapshots | `/var/lib/containerd/` (overlayfs snapshots under `io.containerd.snapshotter.v1.overlayfs`) |
| Docker | `/var/lib/docker/overlay2/<id>/diff` (upper layer = changes) |
| kubelet logs | `journalctl -u kubelet` |
| Runtime logs | `journalctl -u containerd` / `docker` |
| Host artifacts | Standard Linux forensics (`defensive-linux-forensics`) — escape attempts often leave host traces |
| Falco | Alerts + capture files (Falco 0.42+ capture feature) |

For managed nodes, snapshot the node's disk (cloud snapshot) and memory if possible before termination (`defensive-disk-imaging`).

---

## 4. Control-Plane Evidence

| Source | Look for |
|---|---|
| Kubernetes audit log | `pods/exec`, `pods/attach`, `pods/portforward`, `secrets` get/list, `clusterrolebindings` create, privileged pod creation, `serviceaccounts/token` requests |
| EKS | CloudWatch control plane logs (audit, authenticator), CloudTrail (EKS API, IAM roles for service accounts) |
| AKS | Diagnostic settings → `kube-audit`, `kube-audit-admin`; Entra sign-ins |
| GKE | Cloud Audit Logs (Admin Activity, Data Access for K8s API) |
| Registry | Image push/pull logs; was the image digest expected? |

```bash
jq -c 'select(.objectRef.subresource=="exec") | {t:.requestReceivedTimestamp,u:.user.username,ns:.objectRef.namespace,pod:.objectRef.name,cmd:.requestURI}' audit.log
jq -c 'select(.objectRef.resource=="secrets" and (.verb=="get" or .verb=="list")) | {t:.requestReceivedTimestamp,u:.user.username,ns:.objectRef.namespace,name:.objectRef.name}' audit.log
```

---

## 5. Analysis Questions

1. How did the attacker get in? (vulnerable app, exposed dashboard/kubelet, stolen kubeconfig, malicious image)
2. What ran in the container? (diff, logs, process events, Falco)
3. Did they escape or access the node? (hostPath, privileged, `nsenter`, kernel exploits)
4. What credentials were reachable? (service account token, mounted secrets, cloud metadata/IRSA/workload identity)
5. Lateral movement in cluster? (exec into other pods, new workloads, RBAC changes)

---

## 6. Recovery

Delete compromised workloads after preservation; rotate service account tokens and mounted secrets; rotate cloud credentials reachable via workload identity; rebuild images from trusted source with pinned digests; review RBAC and admission policies (`defensive-k8s-security`).

---

## Engagement Cheatsheet

```text
identify pod/node/digest/SA → quarantine NetworkPolicy + remove from Service + cordon → kubectl get -o yaml, logs (--previous), describe
→ docker/crictl inspect, diff, export, checkpoint → node: /var/log/pods, overlay upper dirs, kubelet/containerd journals, node snapshot
→ K8s audit (exec, secrets, RBAC) + cloud logs → escape & credential analysis → delete, rotate, rebuild pinned
```

---

## Key References

- Kubernetes docs (auditing, kubelet checkpoint API, NetworkPolicy); CNCF/Falco docs; SANS FOR509 topics
- Related: `defensive-k8s-security`, `defensive-tool-falco`, `defensive-linux-forensics`, `defensive-cloud-ir`, `defensive-disk-imaging`
