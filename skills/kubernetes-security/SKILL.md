---
name: kubernetes-security
description: Audits Kubernetes manifests, Helm charts, and Kustomize overlays for the misconfigurations AI coding assistants default to when generating YAML for k3s/homelab and production clusters alike — containers with no `securityContext` (root, no capability drop, no seccomp), RBAC wildcards and `cluster-admin` bindings, plaintext secrets in `values.yaml` or committed `Secret` manifests, no `NetworkPolicy` (every pod reachable from every pod by default), mutable image tags, and workloads exposed via `NodePort` or an unauthenticated kubelet port. Use whenever the project has a `Chart.yaml`, `values.yaml`, or `kustomization.yaml`, a manifest declaring `apiVersion apps/v1` and `kind Deployment`, or when reviewing k3s, Helm, or `kubectl apply` output.
license: MIT
---

# Kubernetes & Helm Security

A Kubernetes manifest is a request, not a guarantee: the cluster grants exactly the permissions,
capabilities, and reachability the YAML asks for, and its defaults are permissive because they
optimize for "the pod starts," not "the pod is contained." An assistant asked to "deploy this to
k3s" or "write me a Helm chart" ships a `Deployment`, a `Service`, maybe an `Ingress` — because
that's what "it works" looks like. It rarely ships a `securityContext`, a `NetworkPolicy`, a scoped
`Role`, or an external-secret reference, because none of those are needed for `kubectl apply` to
succeed. The password lands in plaintext `values.yaml` because that's the simplest way to make it
configurable; the `Role` gets `verbs: ["*"]` because a wildcard is the fastest way to stop seeing
`Forbidden`; the container runs as whatever UID the base image defaults to, because nobody said
otherwise. None of that shows up in a `helm template` render that just prints valid YAML — until
the cluster is what an attacker who popped one container tries to move laterally through.

This skill covers the manifest and chart layer. For the container image itself — Dockerfile
hygiene, secrets baked into layers, base-image pinning — see `secaudit:docker-security`; the two
are complementary layers of one supply chain (the image is what runs, the manifest is what's
allowed to run it and what it can reach). For generic credential hygiene that applies just as much
inside a `values.yaml` as inside application source, see `secaudit:secrets`.

## When to Use

- The project has a `Chart.yaml` (Helm chart), a `kustomization.yaml` (Kustomize overlay), or raw
  manifests with `apiVersion: apps/v1` and `kind: Deployment` / `StatefulSet` / `DaemonSet`.
- Reviewing anything deployed to k3s, k0s, kubeadm, or a managed Kubernetes service — homelab and
  production clusters share the same misconfiguration patterns.
- Writing or reviewing RBAC, `Secret` objects, `NetworkPolicy`, or Pod Security Admission labels.
- Before `helm install`, `kubectl apply -f`, or wiring CI to run either.

```bash
find . -iname 'Chart.yaml' -o -iname 'values*.yaml' -o -iname 'kustomization.yaml'
grep -rl 'apiVersion: apps/v1' --include='*.y*ml' .
grep -rl 'kind: Deployment\|kind: StatefulSet\|kind: DaemonSet' --include='*.y*ml' .

# The workflow every section below builds on: render the chart the way the cluster will see it,
# then grep the rendered output
helm template . > /tmp/rendered.yaml
grep -c '^kind: NetworkPolicy' /tmp/rendered.yaml
```

`helm template` does no server-side validation and fakes cluster-derived data locally (§8) —
treat its output as ground truth for *what the chart produces*, not proof the cluster accepts or
safely runs it.

## 1. Secrets in `values.yaml`, ConfigMaps, and Committed `Secret` Manifests

**What to look for:** a database password, API key, or token set directly in `values.yaml` (or a
parent chart's), a `ConfigMap` holding anything credential-shaped, or a `kind: Secret` manifest
committed with its `data:`/`stringData:` populated.

**Why it's exploitable:** base64 is encoding, not encryption — "Base64 encoding is *not* an
encryption method, it provides no additional confidentiality over plain text," and "sharing this
file or checking it in to a source repository means the secret is available to everyone who can
read the manifest." The cluster doesn't protect it by default either: "Kubernetes Secrets are, by
default, stored unencrypted in the API server's underlying data store (etcd)... anyone who is
authorized to create a Pod in a namespace can use that access to read any Secret in that
namespace." Two RBAC corollaries make a "read-only" `Role` riskier than it looks: "Granting `list`
access to Secrets implicitly lets the subject fetch the contents," and "A user who can create a Pod
that uses a Secret can also see the value of that Secret." A `ConfigMap` has none of a Secret's
(already weak) handling and isn't covered by encryption-at-rest at all.

**Fix:** never commit a populated `Secret` or a `values.yaml` with real credentials. Keep
`values.yaml` holding a *reference*, and materialize the real `Secret` at deploy time:

- **External Secrets Operator** — reads AWS/GCP/Azure/Vault/etc. and "automatically injects the
  values into a Kubernetes Secret," so the committed manifest is an `ExternalSecret` pointer.
- **Sealed Secrets** — encrypts client-side into a `SealedSecret` CRD safe to commit; only the
  in-cluster controller can decrypt it.
- **helm-secrets** — a Helm plugin keeping values encrypted in git (`sops`/`vals` backends) and
  decrypting only at render time.
- For native `Secret` objects, enable **encryption at rest**: `kube-apiserver
  --encryption-provider-config` pointed at an `EncryptionConfiguration` whose first provider is a
  real cipher — "the default `identity` provider does not provide any confidentiality protection."

Also watch Helm's value precedence: chart `values.yaml` → parent chart → `-f` file → `--set`, each
overriding the last — a password on `--set password=...` lands in shell history and, in CI, in logs.

```yaml
# BAD — values.yaml, committed
database:
  password: "hunter2"           # plaintext, in every clone and every values-diff review
---
apiVersion: v1
kind: Secret
metadata: { name: app-db }
type: Opaque
data:
  password: aHVudGVyMg==        # base64, not encryption
```

```yaml
# GOOD — values.yaml holds only a reference; ESO materializes the real Secret in-cluster
database:
  existingSecret: app-db
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: { name: app-db }
spec:
  secretStoreRef: { name: vault-backend, kind: ClusterSecretStore }
  target: { name: app-db }
  data:
    - secretKey: password
      remoteRef: { key: prod/app/db, property: password }
```

**Detection:**

```bash
# values files with a credential-shaped literal (not a template ref or existingSecret)
grep -rniE '(password|secret|token|api[_-]?key)[[:space:]]*:[[:space:]]*["'"'"']?[^{[:space:]]' \
  --include='values*.yaml' .

# committed Secret manifests with real data
grep -rlZ '^kind: Secret' --include='*.y*ml' . | xargs -0 -I{} sh -c \
  'grep -qE "^(data|stringData):" "{}" && echo "REVIEW: {}"'

# spot-decode a suspicious Secret
kubectl get secret <name> -o jsonpath='{.data.password}' | base64 -d
```

## 2. RBAC: Wildcards, `cluster-admin`, and the Default ServiceAccount

**What to look for:** a `Role`/`ClusterRole` with `verbs: ["*"]` or `resources: ["*"]`, a binding to
`cluster-admin` or the `system:masters` group, a `ClusterRoleBinding` where a namespaced
`RoleBinding` would do, and a pod with no `automountServiceAccountToken: false` even though it
never calls the API.

**Why it's exploitable:** wildcards over-grant the future, not just the present — "providing
wildcard access gives rights not just to all object types that currently exist in the cluster, but
also to all object types which are created in the future." `system:masters` is worse than any Role:
membership "bypasses all RBAC rights checks and will always have unrestricted superuser access,
which cannot be revoked by removing RoleBindings or ClusterRoleBindings" — deleting the binding
that *looks* like the grant does nothing. And identity is free by default: "every Kubernetes
namespace contains at least one ServiceAccount: the default ServiceAccount... If you do not specify
a ServiceAccount when you create a Pod, Kubernetes automatically assigns" it, token mounted at
`/var/run/secrets/kubernetes.io/serviceaccount/token`. Bind an over-broad Role to `default`, and the
first RCE in *any* pod in the namespace is a standing API credential — commonly the Secret-read
primitive from §1.

**Fix:** scope every `Role` to exact resources/verbs; prefer namespaced `RoleBinding`s over
`ClusterRoleBinding`s ("assign permissions at the namespace level where possible"); never bind
`cluster-admin`/`system:masters` for routine workloads; set
`automountServiceAccountToken: false` on the `ServiceAccount` and/or Pod spec for anything that
doesn't call the API (the Pod spec value wins if both are set).

```yaml
# BAD — effectively cluster-admin scoped to wherever this binds
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: app-role }
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

```yaml
# GOOD — least privilege, namespaced, no standing API token
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: app-role, namespace: app }
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch"]
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: app-sa, namespace: app }
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: app-role-binding, namespace: app }
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: app
roleRef: { kind: Role, name: app-role, apiGroup: rbac.authorization.k8s.io }
```

**Detection:**

```bash
# wildcard verbs or resources
helm template . | grep -B5 -E 'verbs:[[:space:]]*\[.*"\*".*\]|resources:[[:space:]]*\[.*"\*".*\]'

# bindings to cluster-admin
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name'

# ServiceAccounts with no automount opt-out
kubectl get sa -A -o json | \
  jq -r '.items[] | select(.automountServiceAccountToken != false) | "\(.metadata.namespace)/\(.metadata.name)"'
```

## 3. Pod `securityContext`: the Restricted Profile

**What to look for:** a `Deployment`/`Pod` spec with no `securityContext` block at all — the most
common finding in AI-generated charts — or one missing `runAsNonRoot`,
`allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, or a `seccompProfile`. Separately,
flag anything tripping the *Baseline* profile Restricted inherits: `privileged: true`, a `hostPath`
volume, `hostNetwork: true`, or `hostPID: true`.

**Why it's exploitable:** Kubernetes names this ladder explicitly. Privileged is "unrestricted...
allows for known privilege escalations." Baseline "prevents known privilege escalations [and]
allows the default Pod configuration" — which is exactly the risk: the *default* is what an
assistant ships. Restricted is "heavily restricted... following current Pod hardening best
practices," and its required fields are specific: `runAsNonRoot: true`,
`allowPrivilegeEscalation: false`, `capabilities.drop` including `"ALL"`, and
`seccompProfile.type` of `RuntimeDefault` or `Localhost`, applied per container. Baseline forbids
`hostPath` (must be undefined), `hostNetwork`/`hostPID` (undefined or `false`), and `privileged`
(undefined or `false`) — not hardening suggestions, the line between "contained" and "can see and
touch the host."

**Fix:** set a full `securityContext` at pod and container level matching Restricted's four
required fields, plus `readOnlyRootFilesystem: true` wherever the app doesn't need to write to its
own image — not part of the enforced profile, but it closes the same persistence gap
`secaudit:docker-security` §8 covers at the runtime layer.

```yaml
# BAD — no securityContext: root, all default capabilities, writable rootfs, no seccomp
containers:
  - name: app
    image: "myapp:1.4.0"
```

```yaml
# GOOD — matches PSS Restricted's required fields
securityContext:
  runAsNonRoot: true
  seccompProfile: { type: RuntimeDefault }
containers:
  - name: app
    image: "myapp:1.4.0"
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities: { drop: ["ALL"] }
      readOnlyRootFilesystem: true
    volumeMounts:
      - { name: tmp, mountPath: /tmp }
volumes:
  - name: tmp
    emptyDir: {}
```

**Detection:**

```bash
# containers with no securityContext at all
helm template . | grep -c 'securityContext' # compare to container count; 0 or low is a finding

# Baseline-violating fields anywhere in the rendered output
helm template . | grep -nE 'privileged:[[:space:]]*true|hostNetwork:[[:space:]]*true|hostPID:[[:space:]]*true|hostPath:'

# runtime truth for a live pod
kubectl get pod <pod> -o jsonpath='{.spec.securityContext}{"\n"}{.spec.containers[*].securityContext}'
```

## 4. Pod Security Admission Labels: `enforce` Only Applies to Pods

**What to look for:** a namespace with no `pod-security.kubernetes.io/*` labels, or — the sharper
footgun — `enforce: restricted` alone, assumed to reject a non-conforming `Deployment` outright.

**Why it's exploitable:** labels take the form `pod-security.kubernetes.io/<MODE>: <LEVEL>`, `MODE`
one of `enforce | audit | warn`. `enforce` does what it says — "policy violations will cause the pod
to be rejected" — **but only for pods**: "enforce mode is not applied to workload resources, only
to the resulting pod objects." So `kubectl apply -f deployment.yaml` against an `enforce:
restricted` namespace **succeeds** — the `Deployment` is valid and gets created — and only the
ReplicaSet controller's attempt to create actual Pods fails, silently as far as `apply` is
concerned. The `Deployment` sits at `0/N` ready with no top-level error, easy to log as "deployed"
and easy to miss without checking `kubectl get pods` afterward.

**Fix:** set `audit` and `warn` alongside `enforce` — both **do** apply to workload resources (the
exclusion above is specific to `enforce`), so `warn` surfaces the same violation as an immediate
`kubectl apply` warning against the `Deployment` itself, and `audit` logs it even when missed.
Confirm rollout status in CI rather than trusting a clean `apply` exit code.

```yaml
# BAD — enforce only; a bad Deployment "applies" and silently produces 0 pods
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

```yaml
# GOOD — warn/audit catch the same violation against the Deployment itself
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

**Detection:**

```bash
kubectl get ns --show-labels | grep -v 'pod-security.kubernetes.io'
kubectl get ns <ns> -o jsonpath='{.metadata.labels}' | grep -q '"warn"' || echo "FINDING: enforce with no warn label"
kubectl get deploy <name> -o jsonpath='{.status.readyReplicas}'
kubectl get events --field-selector reason=FailedCreate -A
```

## 5. NetworkPolicy: Default-Allow in Both Directions

**What to look for:** a chart or manifest set with `Deployment`/`Service`/`Secret` objects but zero
`NetworkPolicy` resources anywhere in the namespace.

**Why it's exploitable:** networking is open unless something closes it — "by default, a pod is
non-isolated for ingress; all inbound connections are allowed," and the same for egress. A pod is
isolated only once *some* `NetworkPolicy` selects it for that direction; there is no cluster-wide
default-deny without explicitly creating one. Any pod compromised through an application bug can,
by default, reach every other pod and `Service` in the cluster — an internal admin API, a database
with no business being reachable from the public frontend, another tenant's namespace on a shared
cluster. `NetworkPolicy` is enforced by the CNI plugin, not the API server — confirm your cluster's
CNI actually implements it before treating the object's presence as proof of enforcement.

**Fix:** ship a default-deny policy per namespace, then add narrow allow rules per real traffic path.

```yaml
# GOOD — default-deny both directions, then one explicit allow
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-all, namespace: app }
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-frontend-to-backend, namespace: app }
spec:
  podSelector: { matchLabels: { app: backend } }
  policyTypes: ["Ingress"]
  ingress:
    - from: [{ podSelector: { matchLabels: { app: frontend } } }]
      ports: [{ port: 8080, protocol: TCP }]
```

The BAD case here has no YAML to show — the finding is what's *absent* from `helm template .`
output: workloads with zero `NetworkPolicy` objects anywhere in the chart.

**Detection:**

```bash
helm template . > /tmp/rendered.yaml
grep -q '^kind: Deployment' /tmp/rendered.yaml && \
  [ "$(grep -c '^kind: NetworkPolicy' /tmp/rendered.yaml)" -eq 0 ] && \
  echo "FINDING: workloads with zero NetworkPolicy objects"

kubectl get networkpolicy -n <namespace>
```

## 6. Image Pinning, Pull Policy, and Resource Limits as a DoS Control

**What to look for:** `image:` with no tag or `:latest`, no explicit `imagePullPolicy`, and
containers with no `resources.requests`/`limits` — and no namespace `LimitRange`/`ResourceQuota`
behind that.

**Why it's exploitable:** an untagged image resolves to `:latest`, which is mutable; digest is the
only immutable reference — "only digest is used for pulling" when both are given. Pull policy
compounds it: default is `Always` for `:latest`/no tag, `IfNotPresent` otherwise — so an untagged
image is re-pulled on every restart, meaning *what actually runs* can change with nothing in the
chart changing. Resources are unbounded unless stated: "by default, containers run with unbounded
compute resources on a Kubernetes cluster" — a bug, a traffic spike, or an attacker who finds a way
to make the app allocate has no ceiling and can starve every other workload on the node. That's a
denial-of-service primitive with no exploit required.

**Fix:** pin by digest (keep the tag for readability), set an explicit pull policy, set
requests/limits on every container, and back that with `LimitRange` — "making sure that a single
object cannot monopolize all available resources within a namespace," violations rejected outright
— and `ResourceQuota`, which "provides constraints that limit aggregate resource consumption per
namespace" and can cap object counts too, so a compromised CI job can't fork-bomb the namespace
with `Job`s either.

```yaml
# BAD
containers:
  - name: app
    image: myapp:latest
```

```yaml
# GOOD — digest-pinned, explicit pull policy, bounded resources + namespace guardrails
containers:
  - name: app
    image: "myapp:1.4.0@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    imagePullPolicy: IfNotPresent
    resources:
      requests: { cpu: "100m", memory: "128Mi" }
      limits: { cpu: "500m", memory: "256Mi" }
---
apiVersion: v1
kind: ResourceQuota
metadata: { name: namespace-quota, namespace: app }
spec:
  hard: { requests.cpu: "4", requests.memory: 4Gi, limits.cpu: "8", limits.memory: 8Gi, pods: "20" }
```

**Detection:**

```bash
# images with no digest, especially latest/untagged
helm template . | grep -E '^\s*image:' | grep -v '@sha256:'
helm template . | grep -E '^\s*image:\s*[^@]+:(latest)?\s*$'

# containers with no resources block
helm template . | grep -c 'resources:'   # compare to container count

# namespace guardrails present at all?
kubectl get limitrange,resourcequota -n <namespace>
```

## 7. Exposure: NodePort/LoadBalancer, the Kubelet Read-Only Port, and Anonymous API Access

**What to look for:** `Service` type `NodePort`/`LoadBalancer` with nothing in front of it; a
kubelet left with its read-only port enabled; API-server anonymous auth left on with no RBAC
boundary around `system:anonymous`; and any Kubernetes Dashboard deployment.

**Why it's exploitable:** `NodePort` publishes on every node's IP at a static
`30000–32767`-range port — on a k3s box with a public IP and no separate firewall, that's a service
on the internet with no ingress, TLS, or auth in front; `LoadBalancer` builds on the same mechanism
via the cloud provider. The kubelet's read-only port is exactly what it says: "the read-only port
for the Kubelet to serve on with no authentication/authorization" — default `10255`, disabled only
by setting it to `0`. The API server's anonymous access has the same shape: "anonymous access is
enabled by default if an authorization mode other than `AlwaysAllow` is used," resolving to
`system:anonymous`/`system:unauthenticated` — harmless *only* as long as no binding grants that
identity anything, which "requires explicit authorization" to happen, so confirm none exists rather
than assume it. The Dashboard adds a fourth path with a name that invites over-trust: "not deployed
by default," but its own quick-start warns "the sample user created in the tutorial will have
administrative privileges and is for educational purposes only," and the project itself is now
"deprecated and unmaintained."

**Fix:** default to `ClusterIP` with a real ingress (TLS, auth where needed) instead of a direct
`NodePort`; scope any `LoadBalancer` with cloud firewall rules rather than `0.0.0.0/0`; disable the
kubelet read-only port (`--read-only-port=0`); keep `--anonymous-auth=false` unless something
specific depends on it, and audit that nothing binds `system:anonymous`/`system:unauthenticated`;
avoid deploying the Dashboard, and never create its admin-privileged sample user outside a
throwaway lab.

```yaml
# BAD — database directly on every node's port range, no auth in front
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec:
  type: NodePort
  ports: [{ port: 5432, nodePort: 30432 }]
```

```yaml
# GOOD — ClusterIP only; nothing outside the cluster network reaches it directly
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec:
  type: ClusterIP
  ports: [{ port: 5432 }]
```

**Detection:**

```bash
helm template . | grep -B5 'type: NodePort\|type: LoadBalancer'
curl -sk http://<node-ip>:10255/pods   # 200 with pod data is the finding
kubectl get clusterrolebinding -o json | \
  jq -r '.items[] | select(.subjects[]?.name=="system:anonymous" or .subjects[]?.name=="system:unauthenticated") | .metadata.name'
kubectl get deploy -A | grep -i kubernetes-dashboard
```

## 8. Helm-Specific Review: `helm template`, `lint`, and Chart Provenance

**What to look for:** review that stops at `helm lint`, static `helm template` review of a chart
whose templates use `lookup`, and installing a chart — especially from an OCI registry — without
checking provenance.

**Why it's exploitable:** `helm lint` "runs a series of tests to verify that the chart is
well-formed" — schema and template well-formedness, not security; a chart can lint clean while
shipping every finding in §1–§7. `helm template` — "render chart templates locally and display the
output" — is the right static-review tool for those findings *and* has a specific blind spot:
"Helm is not supposed to contact the Kubernetes API Server during a
`helm template|install|upgrade|delete|rollback --dry-run` operation," so a template's `lookup(...)`
call, which normally "queries Kubernetes," gets faked locally — "an empty value is returned" on
not-found. A chart using `lookup` to decide whether to generate a fresh password, or to read an
existing resource, renders differently under `helm template` than under a real install — so static
review can miss what actually gets applied, and `lookup` itself reads live cluster state (including
Secrets, per §1) with the installer's own credentials. Use `--dry-run=server` when behavior depends
on `lookup`. For provenance, Helm's mechanism is the `.prov` file — GnuPG-signed, containing
`Chart.yaml` and a sha256 — checked by `helm verify`/`helm install --verify`. For OCI charts, Helm
points to the same signing ecosystem used for images: "the `helm-sigstore` plugin allows using
Sigstore to sign Helm charts with the same tools used to sign container images." Where a chart's
supply chain runs through CI, the signature-verification discipline in `secaudit:ci-cd-security` §9
(checking *who* signed, not just that a signature is valid) applies to the packaged chart the same
way it applies to a container image.

**Fix:** treat `helm lint` as a well-formedness gate only; make `helm template . | <grep from
§1–§7>` the standard static review; re-check with `--dry-run=server` for any chart using `lookup`;
verify provenance before installing anything from a third-party or public repo.

```bash
# BAD — installs whatever the repo currently serves, no integrity check
helm install myapp community/myapp

# GOOD — verifies against the signed provenance record before installing
helm install myapp community/myapp --verify

# lookup-dependent chart: don't trust `helm template` alone
helm template . --dry-run=server
```

**Detection:**

```bash
grep -rn 'lookup(' --include='*.tpl' --include='*.yaml' templates/ 2>/dev/null
grep -rn -- '--verify' --include='*.sh' --include='*.y*ml' .
grep -rniE 'helm lint' --include='*.md' . | grep -iE 'security|audit|review'  # process smell, not YAML
```

## Footgun Checklist

- No `securityContext` block at all — the pod runs exactly as the Privileged profile allows.
- A credential-shaped literal in `values.yaml` or a populated, committed `Secret` — it's in git
  history and in etcd, unencrypted, by default.
- `verbs: ["*"]`/`resources: ["*"]` on any `Role`, or a binding to `cluster-admin`/`system:masters`.
- Default `ServiceAccount` used implicitly, with no `automountServiceAccountToken: false`.
- `enforce: restricted` with no matching `warn`/`audit` — violations fail silently at the Pod level
  while `kubectl apply` reports success on the Deployment.
- Zero `NetworkPolicy` objects in a namespace with real workloads.
- `image:` with no digest, especially `:latest` or no tag.
- No `resources.requests`/`limits`, and no namespace `LimitRange`/`ResourceQuota` behind that.
- `NodePort`/`LoadBalancer` on anything that doesn't need external reachability.
- Kubelet read-only port or API-server anonymous auth left on with no RBAC audit around it.
- The Dashboard deployed at all, or with its admin-privileged sample user outside a lab.
- `helm lint` reported as the security review.

## OWASP Mapping

**OWASP Kubernetes Top 10:** K01 Insecure Workload Configurations (§3, §6), K02 Overly Permissive
Authorization Configurations (§2), K03 Secrets Management Failures (§1), K04 Lack Of Cluster Level
Policy Enforcement (§4), K05 Missing Network Segmentation Controls (§5), K06 Overly Exposed
Kubernetes Components (§7), K07 Misconfigured And Vulnerable Cluster Components (§7, §8), K08
Cluster To Cloud Lateral Movement (§2 + §5 combined), K09 Broken Authentication Mechanisms (§7),
K10 Inadequate Logging And Monitoring — not covered here, see `secaudit:logging-monitoring`.

**OWASP Top 10 (2025):** most findings here are **A02:2025 Security Misconfiguration** — a
`securityContext`, `NetworkPolicy`, or PSA label that was never set is a missing default, the
defining shape of that category, and the same one `secaudit:docker-security` maps to for the image
layer directly below this. A narrower slice is **A05:2025 Injection**: a chart that interpolates an
untrusted or multi-tenant-controlled value straight into a container's `command:`/`args:` builds a
shell command from that input — the same injection shape `secaudit:data-access` covers for
application code, one templating layer up.

## Cross-References

- `secaudit:docker-security` — the image layer this skill's manifests deploy: root containers,
  unpinned bases, secrets baked into layers. §3 and §6 are the same arguments one layer up.
- `secaudit:secrets` — the redaction rule and credential-hygiene patterns for §1 apply the same way
  inside `values.yaml` as inside application source.
- `secaudit:ci-cd-security` — if a pipeline runs `helm install`/`kubectl apply`: §9's signature
  discipline applies to a chart's provenance (§8 here), and the pipeline's own token scope is a
  §2-shaped least-privilege question.
- `secaudit:rate-limiting` — application-level throttling; §6 here is the platform-level ceiling
  underneath it.
- `secaudit:deployment` — environment separation and security headers for what's running once a
  workload from this cluster is reachable at a URL.

## Sources

- https://kubernetes.io/docs/concepts/security/pod-security-standards/ -- Privileged/Baseline/Restricted profile definitions and required fields
- https://kubernetes.io/docs/concepts/security/pod-security-admission/ -- enforce/audit/warn labels; enforce not applied to workload resources
- https://kubernetes.io/docs/concepts/security/rbac-good-practices/ -- wildcard, cluster-admin, system:masters, automountServiceAccountToken guidance
- https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/ -- default ServiceAccount, token mount path, automount precedence
- https://kubernetes.io/docs/concepts/configuration/secret/ -- Secrets stored unencrypted in etcd by default; Pod-creation read access
- https://kubernetes.io/docs/concepts/security/secrets-good-practices/ -- base64 is not encryption; manifest sharing; list-implies-read
- https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/ -- EncryptionConfiguration; identity provider gives no confidentiality
- https://external-secrets.io/latest/ -- External Secrets Operator
- https://github.com/bitnami/sealed-secrets -- Sealed Secrets
- https://github.com/jkroepke/helm-secrets -- helm-secrets plugin (sops/vals backends)
- https://helm.sh/docs/chart_template_guide/values_files/ -- values.yaml precedence order
- https://helm.sh/docs/chart_template_guide/functions_and_pipelines/ -- lookup() behavior under helm template vs install
- https://kubernetes.io/docs/concepts/services-networking/network-policies/ -- default-allow ingress/egress; default-deny examples
- https://kubernetes.io/docs/concepts/containers/images/ -- digest pinning; imagePullPolicy defaults
- https://kubernetes.io/docs/concepts/policy/limit-range/ -- unbounded resources by default; LimitRange
- https://kubernetes.io/docs/concepts/policy/resource-quotas/ -- ResourceQuota, aggregate and object-count limits
- https://kubernetes.io/docs/concepts/services-networking/service/ -- NodePort/LoadBalancer exposure mechanics
- https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/ -- Dashboard not default; sample user is admin-privileged; deprecated/unmaintained
- https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/ -- --read-only-port default and no-auth behavior
- https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/ -- readOnlyPort / anonymous.enabled config-file defaults
- https://kubernetes.io/docs/reference/access-authn-authz/authentication/ -- anonymous-auth default, system:anonymous/system:unauthenticated, explicit-authorization requirement
- https://www.cisecurity.org/benchmark/kubernetes -- CIS Kubernetes Benchmark
- https://github.com/aquasecurity/kube-bench -- CIS Benchmark automated checks
- https://github.com/kubescape/kubescape -- Kubernetes security platform (IDE/CI/cluster)
- https://trivy.dev/docs/latest/target/kubernetes/ -- Trivy Kubernetes target (images, manifests, cluster components)
- https://github.com/FairwindsOps/polaris -- policy engine for resource configuration
- https://github.com/stackrox/kube-linter -- static analysis for Kubernetes YAML and Helm charts
- https://helm.sh/docs/helm/helm_template/ -- helm template: local render, no server-side validation
- https://helm.sh/docs/helm/helm_lint/ -- helm lint: well-formedness, not a security check
- https://helm.sh/docs/topics/provenance/ -- .prov files, helm verify, chart integrity
- https://helm.sh/docs/topics/registries/ -- OCI chart registries; helm-sigstore signing
- https://kubernetes-top10.owasp.org/ -- OWASP Kubernetes Top 10 (K01-K10)
- https://top10.owasp.org/2025/ -- OWASP Top 10 (2025): A02 Security Misconfiguration, A05 Injection
