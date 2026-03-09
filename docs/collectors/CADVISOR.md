# cAdvisor Collector

Scrapes container and machine metrics from a running cAdvisor instance's Prometheus `/metrics` endpoint.

## Data Source

HTTP GET to cAdvisor Prometheus endpoint (default: `http://localhost:8080/metrics`).

Parser: Prometheus text format (`expfmt.TextParser`).

## Metric Filtering

By default, only metrics with the following prefixes are collected:

| Prefix       | Description           |
| ------------ | --------------------- |
| `container_` | Per-container metrics |
| `machine_`   | Host machine metrics  |

If `metric_names` is configured, only the exact metric names listed are collected.

## Key cAdvisor Metrics Collected (defaults)

### Container CPU

| Metric                                      | Type    | Description                  |
| ------------------------------------------- | ------- | ---------------------------- |
| `container_cpu_usage_seconds_total`         | Counter | Cumulative CPU time consumed |
| `container_cpu_system_seconds_total`        | Counter | CPU time in system mode      |
| `container_cpu_user_seconds_total`          | Counter | CPU time in user mode        |
| `container_cpu_cfs_throttled_seconds_total` | Counter | CPU throttled time           |
| `container_cpu_cfs_periods_total`           | Counter | Total CFS periods            |
| `container_cpu_cfs_throttled_periods_total` | Counter | Throttled CFS periods        |

### Container Memory

| Metric                               | Type    | Description                |
| ------------------------------------ | ------- | -------------------------- |
| `container_memory_usage_bytes`       | Gauge   | Current memory usage       |
| `container_memory_working_set_bytes` | Gauge   | Working set memory         |
| `container_memory_rss`               | Gauge   | Resident set size          |
| `container_memory_cache`             | Gauge   | Page cache                 |
| `container_memory_swap`              | Gauge   | Swap usage                 |
| `container_memory_failures_total`    | Counter | Memory allocation failures |

### Container Network (per-interface)

| Metric                                             | Type    | Description       |
| -------------------------------------------------- | ------- | ----------------- |
| `container_network_receive_bytes_total`            | Counter | Bytes received    |
| `container_network_transmit_bytes_total`           | Counter | Bytes transmitted |
| `container_network_receive_errors_total`           | Counter | Receive errors    |
| `container_network_transmit_errors_total`          | Counter | Transmit errors   |
| `container_network_receive_packets_dropped_total`  | Counter | Received drops    |
| `container_network_transmit_packets_dropped_total` | Counter | Transmitted drops |

### Container Filesystem

| Metric                            | Type    | Description                   |
| --------------------------------- | ------- | ----------------------------- |
| `container_fs_usage_bytes`        | Gauge   | Bytes used by the container   |
| `container_fs_limit_bytes`        | Gauge   | Bytes limit for the container |
| `container_fs_reads_bytes_total`  | Counter | Bytes read from filesystem    |
| `container_fs_writes_bytes_total` | Counter | Bytes written to filesystem   |

### Machine Metrics

| Metric                                 | Type  | Description           |
| -------------------------------------- | ----- | --------------------- |
| `machine_cpu_cores`                    | Gauge | Number of CPU cores   |
| `machine_memory_bytes`                 | Gauge | Total memory in bytes |
| `machine_cpu_cache_capacity_kilobytes` | Gauge | CPU cache capacity    |

## Metric Type Handling

| Prometheus type | Converted to                                            |
| --------------- | ------------------------------------------------------- |
| GAUGE           | `MetricTypeGauge`                                       |
| COUNTER         | `MetricTypeCounter`                                     |
| UNTYPED         | `MetricTypeGauge`                                       |
| SUMMARY         | `{name}_sum` (Counter) + `{name}_count` (Counter)       |
| HISTOGRAM       | `{name}_sum` + `{name}_count` + `{name}_bucket{le=...}` |

## Configuration

```yaml
cadvisor:
  enabled: true
  interval: 15s
  endpoint: "http://localhost:8080"
  metrics_path: "/metrics"
  timeout: 10s
  metric_names: [] # empty = collect all container_* and machine_* metrics
  labels: {} # extra labels added to all metrics
```

## Notes

- cAdvisor must be running separately (e.g. as a DaemonSet in Kubernetes, or `docker run google/cadvisor`).
- All cAdvisor labels from the Prometheus exposition are preserved (container, pod, namespace, image, etc.).
- For Kubernetes environments, cAdvisor is typically embedded in the Kubelet — accessible at `/api/v1/nodes/{name}/proxy/metrics/cadvisor`. Use the Kubernetes API server proxy URL as the endpoint in that case.
