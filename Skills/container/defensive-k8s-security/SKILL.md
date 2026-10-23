---
name: defensive-k8s-security
description: "Kubernetes security hardening and detection: API server and kubelet hardening, RBAC least privilege and dangerous verbs (escalate, bind, impersonate, pods/exec, secrets list), service account token automount, Pod Security Admission (restricted/baseline), admission policies (Kyverno, OPA Gatekeeper, ValidatingAdmissionPolicy/CEL), NetworkPolicy default deny, secrets encryption at rest and external secret stores, etcd protection, image signature verification, audit policy and audit log detections, Falco runtime rules, kube-bench (CIS) and kubescape, and managed cluster specifics (EKS, AKS, GKE). Use for cluster hardening reviews, audit log hunting, and K8s incident response."
---

# Kubernetes Security

Kubernetes attacks pivot through the API server: stolen service account tokens, over-permissive RBAC, privileged pods, and exposed kubelets. Lock down who can talk to the API, what they can do, and what pods may run.

## Quick Workflow

1. Benchmark: kube-bench (CIS), kubescape (NSA/CISA, MITRE)
2. API access: private endpoint, OIDC auth, no anonymous, audit logging
3. RBAC review: remove wildcard and dangerous permissions
4. Pod Security Admission `restricted` on workload namespaces
5. Admission policies for images, registries, signatures, resources
6. NetworkPolicy default deny per namespace
7. Runtime detection (Falco) + audit log detections

---

## 1. Control Plane & Nodes

```text
[ ] API server not public (or IP-restricted); --anonymous-auth=false; OIDC for users
[ ] Audit logging enabled with a policy (below)
[ ] etcd: TLS client auth, not exposed, encrypted backups; Secrets encryption at rest (KMS provider)
[ ] Kubelet: --anonymous-auth=false, --authorization-mode=Webhook, read-only port 10255 disabled
[ ] Node OS minimal and patched; no SSH where avoidable
[ ] Cloud metadata blocked from pods (NetworkPolicy/IMDS hop limit; EKS Pod Identity / GKE Workload Identity / AKS Workload Identity)
```

---

## 2. RBAC

Dangerous permissions:

| Permission | Why |
|---|---|
| `*` verbs/resources | Full control |
| `create pods` (any namespace with privileged allowed) | Escape to node |
| `pods/exec`, `pods/attach`, `pods/portforward` | Code execution in pods |
| `get/list secrets` | Token and credential theft |
| `escalate`, `bind` on roles | Self-grant privileges |
| `impersonate` users/groups/serviceaccounts | Act as cluster-admin |
| `create serviceaccounts/token` | Mint tokens |
| `nodes/proxy` | Kubelet API access (exec via kubelet) |
| `patch/update` on `validatingwebhookconfigurations`/`mutatingwebhookconfigurations` | Disable or hijack admission |
| `create/update` on `clusterrolebindings` | Cluster-admin |

```bash
kubectl auth can-i --list --as=system:serviceaccount:app:default -n app
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name + " -> " + ([.subjects[]?.name]|join(","))'
```

Set `automountServiceAccountToken: false` on pods/SA that don't call the API.

---

## 3. Pod Security Admission

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: app
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

`restricted` requires: non-root, no privilege escalation, drop ALL capabilities, seccomp RuntimeDefault, no host namespaces/paths/ports.

Compliant securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
```

---

## 4. Admission Policies

Kyverno — require signed images from approved registry:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: verify-images }
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-signature
      match: { any: [ { resources: { kinds: [Pod] } } ] }
      verifyImages:
        - imageReferences: ["registry.example.com/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/org/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

Also enforce: disallow `:latest`, require resource limits, restrict registries, disallow hostPath, require labels. Native alternative: `ValidatingAdmissionPolicy` (CEL), GA in recent Kubernetes versions.

---

## 5. NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny, namespace: app }
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-dns-and-api, namespace: app }
spec:
  podSelector: { matchLabels: { app: web } }
  policyTypes: [Egress]
  egress:
    - to: [ { namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }, podSelector: { matchLabels: { k8s-app: kube-dns } } } ]
      ports: [ { protocol: UDP, port: 53 }, { protocol: TCP, port: 53 } ]
    - to: [ { podSelector: { matchLabels: { app: api } } } ]
      ports: [ { protocol: TCP, port: 8080 } ]
```

Requires a CNI that enforces policies (Calico, Cilium, cloud-native implementations).

---

## 6. Audit Policy & Detections

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "serviceaccounts/token"]
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
  - level: Request
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
  - level: Metadata
```

(Use `Metadata` instead of `RequestResponse` for secrets if logs would store secret values — balance visibility vs exposure.)

| Detection | Audit filter |
|---|---|
| Exec into pod | `objectRef.subresource in (exec, attach)` |
| Secrets enumeration | `objectRef.resource=secrets, verb in (list, watch)` by non-system user |
| New cluster-admin binding | `clusterrolebindings create` with `roleRef.name=cluster-admin` |
| Privileged pod | `pods create` with `securityContext.privileged=true`, `hostPID/hostNetwork`, `hostPath` |
| Anonymous access | `user.username=system:anonymous` and response code < 400 |
| Token creation | `serviceaccounts/token create` |
| Webhook tampering | `validatingwebhookconfigurations/mutatingwebhookconfigurations` update/delete |

```bash
jq -c 'select(.objectRef.subresource=="exec") | {t:.requestReceivedTimestamp,u:.user.username,ns:.objectRef.namespace,pod:.objectRef.name}' audit.log
```

---

## 7. Runtime (Falco)

Default Falco rules cover: terminal shell in container, sensitive file reads, writes below binary dirs, privileged container launch, K8s API contact from pods, outbound to suspicious ports, package management in container. Tune with macros/lists rather than disabling rules.

---

## 8. Managed Clusters

| Platform | Key controls |
|---|---|
| EKS | Access entries / IAM auth, private endpoint, control plane logs (audit/authenticator), EKS Pod Identity or IRSA, GuardDuty EKS Protection + Runtime Monitoring |
| AKS | Entra ID integration + Azure RBAC, private cluster, Defender for Containers, Workload Identity, Azure Policy for AKS |
| GKE | Private cluster, Workload Identity Federation for GKE, Binary Authorization, Shielded GKE nodes, GKE Security Posture |

---

## Engagement Cheatsheet

```text
kube-bench/kubescape → private API + audit policy → RBAC cleanup (exec/secrets/escalate/bind/impersonate)
→ PSA restricted → Kyverno/VAP (signatures, registries, no hostPath) → NetworkPolicy default deny
→ secrets encryption/KMS → Falco + audit detections
```

---

## Key References

- Kubernetes Security docs; CIS Kubernetes Benchmark; NSA/CISA Kubernetes Hardening Guide
- MITRE ATT&CK Containers matrix; Microsoft Threat Matrix for Kubernetes
- Kyverno, OPA Gatekeeper, Falco, kube-bench, kubescape docs
- Related: `defensive-container-hardening`, `defensive-cloud-ir`, `defensive-linux-telemetry`
