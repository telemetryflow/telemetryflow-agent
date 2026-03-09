# Kubernetes Workloads Collector

Collects replica and scheduling metrics for StatefulSets, DaemonSets, ReplicaSets, Jobs, and CronJobs.

## Data Source

Kubernetes API: `apps/v1` and `batch/v1` resources (all namespaces, namespace-filtered).

## StatefulSet Metrics

| Metric                           | Type  | Labels                                | Description           |
| -------------------------------- | ----- | ------------------------------------- | --------------------- |
| `k8s.statefulset.replicas`       | Gauge | `cluster`, `namespace`, `statefulset` | Desired replica count |
| `k8s.statefulset.replicas.ready` | Gauge | `cluster`, `namespace`, `statefulset` | Ready replica count   |

### State Fields

- `Kind=StatefulSet`, `Name`, `Namespace`
- `Desired`, `Current`, `Ready`

---

## DaemonSet Metrics

| Metric                  | Type  | Labels                              | Description              |
| ----------------------- | ----- | ----------------------------------- | ------------------------ |
| `k8s.daemonset.desired` | Gauge | `cluster`, `namespace`, `daemonset` | Desired number scheduled |
| `k8s.daemonset.current` | Gauge | `cluster`, `namespace`, `daemonset` | Current number scheduled |
| `k8s.daemonset.ready`   | Gauge | `cluster`, `namespace`, `daemonset` | Number ready             |

### State Fields

- `Kind=DaemonSet`, `Name`, `Namespace`
- `Desired`, `Current`, `Ready`

---

## ReplicaSet Metrics

| Metric                          | Type  | Labels                               | Description           |
| ------------------------------- | ----- | ------------------------------------ | --------------------- |
| `k8s.replicaset.replicas`       | Gauge | `cluster`, `namespace`, `replicaset` | Desired replica count |
| `k8s.replicaset.replicas.ready` | Gauge | `cluster`, `namespace`, `replicaset` | Ready replica count   |

### State Fields

- `Kind=ReplicaSet`, `Name`, `Namespace`
- `Desired`, `Current`, `Ready`

---

## Job Metrics

| Metric              | Type  | Labels                        | Description         |
| ------------------- | ----- | ----------------------------- | ------------------- |
| `k8s.job.active`    | Gauge | `cluster`, `namespace`, `job` | Active pod count    |
| `k8s.job.succeeded` | Gauge | `cluster`, `namespace`, `job` | Succeeded pod count |
| `k8s.job.failed`    | Gauge | `cluster`, `namespace`, `job` | Failed pod count    |

### State Fields

- `Kind=Job`, `Name`, `Namespace`
- `Active`, `Succeeded`, `Failed`

---

## CronJob Metrics

| Metric               | Type  | Labels                            | Description                |
| -------------------- | ----- | --------------------------------- | -------------------------- |
| `k8s.cronjob.active` | Gauge | `cluster`, `namespace`, `cronjob` | Currently active job count |

### State Fields

- `Kind=CronJob`, `Name`, `Namespace`
- `Active`

---

## Use Cases

- DaemonSet health: `k8s.daemonset.ready < k8s.daemonset.desired`
- StatefulSet degraded: `k8s.statefulset.replicas.ready < k8s.statefulset.replicas`
- Job failure: `k8s.job.failed > 0`
- CronJob backlog: `k8s.cronjob.active > N` (unexpected concurrent runs)
