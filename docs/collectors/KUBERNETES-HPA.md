# Kubernetes HPA Collector

Collects HorizontalPodAutoscaler replica bounds, current state, and scaling condition metrics.

## Data Source

Kubernetes API: `autoscaling/v2/horizontalpodautoscalers` (all namespaces, namespace-filtered).

## Metrics

### Replica Counts

| Metric                     | Type  | Labels                                                      | Description                      |
| -------------------------- | ----- | ----------------------------------------------------------- | -------------------------------- |
| `k8s.hpa.replicas.min`     | Gauge | `cluster`, `namespace`, `hpa`, `target_kind`, `target_name` | Minimum replica bound            |
| `k8s.hpa.replicas.max`     | Gauge | `cluster`, `namespace`, `hpa`, `target_kind`, `target_name` | Maximum replica bound            |
| `k8s.hpa.replicas.current` | Gauge | `cluster`, `namespace`, `hpa`, `target_kind`, `target_name` | Current replica count            |
| `k8s.hpa.replicas.desired` | Gauge | `cluster`, `namespace`, `hpa`, `target_kind`, `target_name` | Desired (computed) replica count |

### Conditions

| Metric              | Type  | Labels                                     | Description                       |
| ------------------- | ----- | ------------------------------------------ | --------------------------------- |
| `k8s.hpa.condition` | Gauge | `cluster`, `namespace`, `hpa`, `condition` | Condition status: 1=True, 0=False |

**Standard HPA condition types:**

| Condition        | Meaning                                     |
| ---------------- | ------------------------------------------- |
| `AbleToScale`    | HPA can currently scale the target          |
| `ScalingActive`  | Scaling is active (metrics available)       |
| `ScalingLimited` | Desired replicas are constrained by min/max |

## State Fields (sent to platform)

- `Name`, `Namespace`
- `ScaleTargetKind`, `ScaleTargetName`
- `MinReplicas`, `MaxReplicas`
- `CurrentReplicas`, `DesiredReplicas`
- `Conditions` — map[string]bool
- `Labels`

## Configuration

```yaml
kubernetes:
  hpa: true # default: true
```

## Use Cases

- Autoscaler saturation: `k8s.hpa.replicas.current == k8s.hpa.replicas.max` sustained
- Scaling blocked: `k8s.hpa.condition{condition="AbleToScale"} == 0`
- Metrics unavailable: `k8s.hpa.condition{condition="ScalingActive"} == 0`
- Scale difference: `k8s.hpa.replicas.desired - k8s.hpa.replicas.current`
