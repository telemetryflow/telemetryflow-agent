# Docker Collector

Collects per-container CPU, memory, network, disk I/O, and PID metrics from the Docker Engine API.

## Data Source

Docker Engine API via Unix socket (`/var/run/docker.sock`). Uses a single-shot `ContainerStats` call per container (no streaming).

## Metrics

### Container State Summary (all containers)

| Metric                       | Type  | Description                                                     |
| ---------------------------- | ----- | --------------------------------------------------------------- |
| `container.state.running`    | Gauge | Number of running containers                                    |
| `container.state.stopped`    | Gauge | Number of stopped/exited/dead containers                        |
| `container.state.paused`     | Gauge | Number of paused containers                                     |
| `container.state.restarting` | Gauge | Number of restarting containers                                 |
| `container.state.total`      | Gauge | Total containers (including stopped if `include_stopped: true`) |

### Per-Container Labels

All per-container metrics carry these labels:

| Label          | Description                           |
| -------------- | ------------------------------------- |
| `container_id` | Short container ID (12 characters)    |
| `name`         | Container name (leading `/` stripped) |
| `image`        | Container image name                  |
| `state`        | Container state (`running`)           |

---

### CPU (flag: `collect_cpu: true`)

| Metric                            | Type    | Unit        | Description                                                     |
| --------------------------------- | ------- | ----------- | --------------------------------------------------------------- |
| `container.cpu.usage_percent`     | Gauge   | percent     | CPU usage % (delta-based: cpuDelta/systemDelta × numCPUs × 100) |
| `container.cpu.usage_total`       | Counter | nanoseconds | Total cumulative CPU time                                       |
| `container.cpu.user`              | Counter | nanoseconds | CPU time in user mode                                           |
| `container.cpu.kernel`            | Counter | nanoseconds | CPU time in kernel mode                                         |
| `container.cpu.online_cpus`       | Gauge   | —           | Number of online CPUs                                           |
| `container.cpu.throttled_periods` | Counter | —           | Number of throttled periods                                     |
| `container.cpu.throttled_time`    | Counter | nanoseconds | Total throttled CPU time                                        |

---

### Memory (flag: `collect_memory: true`)

| Metric                           | Type  | Unit    | Description                                                |
| -------------------------------- | ----- | ------- | ---------------------------------------------------------- |
| `container.memory.usage`         | Gauge | bytes   | Memory usage including cache                               |
| `container.memory.working_set`   | Gauge | bytes   | Working set (usage − inactive_file, matches `kubectl top`) |
| `container.memory.limit`         | Gauge | bytes   | Memory limit                                               |
| `container.memory.max_usage`     | Gauge | bytes   | Peak memory usage recorded                                 |
| `container.memory.rss`           | Gauge | bytes   | Resident set size (if available)                           |
| `container.memory.cache`         | Gauge | bytes   | Page cache (if available)                                  |
| `container.memory.usage_percent` | Gauge | percent | Working set as % of limit                                  |

---

### Network (flag: `collect_network: true`)

Labels: per-container labels + `interface`

| Metric                         | Type    | Unit  | Description                 |
| ------------------------------ | ------- | ----- | --------------------------- |
| `container.network.rx_bytes`   | Counter | bytes | Bytes received              |
| `container.network.tx_bytes`   | Counter | bytes | Bytes transmitted           |
| `container.network.rx_packets` | Counter | —     | Packets received            |
| `container.network.tx_packets` | Counter | —     | Packets transmitted         |
| `container.network.rx_errors`  | Counter | —     | Receive errors              |
| `container.network.tx_errors`  | Counter | —     | Transmit errors             |
| `container.network.rx_dropped` | Counter | —     | Received packets dropped    |
| `container.network.tx_dropped` | Counter | —     | Transmitted packets dropped |

---

### Disk I/O (flag: `collect_disk_io: true`)

| Metric                         | Type    | Unit  | Description                          |
| ------------------------------ | ------- | ----- | ------------------------------------ |
| `container.diskio.read_bytes`  | Counter | bytes | Total bytes read from block devices  |
| `container.diskio.write_bytes` | Counter | bytes | Total bytes written to block devices |
| `container.diskio.read_ops`    | Counter | —     | Total read operations                |
| `container.diskio.write_ops`   | Counter | —     | Total write operations               |

---

### PIDs (flag: `collect_pids: true`)

| Metric                   | Type  | Description                             |
| ------------------------ | ----- | --------------------------------------- |
| `container.pids.current` | Gauge | Current number of PIDs in the container |

---

## Configuration

```yaml
docker:
  enabled: true
  interval: 15s
  socket_path: "/var/run/docker.sock"
  include_stopped: false
  collect_cpu: true
  collect_memory: true
  collect_network: true
  collect_disk_io: true
  collect_pids: true
  include_containers: [] # allowlist by name (empty = all)
  exclude_containers: [] # denylist by name
```

## Notes

- The collector pings the Docker daemon on startup. If unreachable, initialization fails.
- Only containers in `running` state get per-container stats (stopped containers only count toward state summary if `include_stopped: true`).
- CPU `usage_percent` requires two consecutive stat snapshots (via `PreCPUStats`). Docker returns both in a single stats call.
