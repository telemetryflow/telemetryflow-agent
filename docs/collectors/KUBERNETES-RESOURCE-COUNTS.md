# Kubernetes Resource Counts Collector

Collects per-namespace counts of Secrets, ConfigMaps, and Ingresses.

## Data Source

Kubernetes API:

- `v1/secrets` — namespace-filtered
- `v1/configmaps` — namespace-filtered
- `networking.k8s.io/v1/ingresses` — namespace-filtered

## Architecture

```mermaid
flowchart LR
    K8S[Kubernetes API Server] -->|v1/secrets| CLIENT[API Client]
    K8S -->|v1/configmaps| CLIENT
    K8S -->|networking.k8s.io/v1/ingresses| CLIENT
    CLIENT --> COLL[Resource Count Collector]
    COLL --> OTLP[OTLP Export Pipeline]
```

## Sub-collector Hierarchy

```mermaid
flowchart TD
    A[Resource Counts Collector] --> B[Secrets]
    A --> C[ConfigMaps]
    A --> D[Ingresses]

    B --> B1[Per-namespace count]
    C --> C1[Per-namespace count]
    D --> D1[Per-namespace count]
```

## Metrics

| Metric                | Type  | Labels                 | Description                   |
| --------------------- | ----- | ---------------------- | ----------------------------- |
| `k8s.secret.count`    | Gauge | `cluster`, `namespace` | Secret count per namespace    |
| `k8s.configmap.count` | Gauge | `cluster`, `namespace` | ConfigMap count per namespace |
| `k8s.ingress.count`   | Gauge | `cluster`, `namespace` | Ingress count per namespace   |

## State Fields (sent to platform)

`ResourceCounts`:

```go
type ResourceCounts struct {
    Secrets    map[string]int  // namespace → count
    ConfigMaps map[string]int
    Ingresses  map[string]int
}
```

## Use Cases

- Config drift: unexpected growth in Secret or ConfigMap counts
- Ingress inventory: track how many Ingresses exist per namespace/team
- Quotas: compare against `ResourceQuota` limits
- Compliance: flag namespaces with too many secrets
