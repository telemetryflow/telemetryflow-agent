# System Host Collector

Collects summary-level host metrics for the agent's own heartbeat and lightweight system monitoring. This collector is simpler than Node Exporter — it emits a small set of cross-platform metrics and provides rich `SystemInfo` for the platform's agent registration/heartbeat endpoint.

## Metrics

### CPU

| Metric             | Type  | Unit    | Description                                  |
| ------------------ | ----- | ------- | -------------------------------------------- |
| `system.cpu.usage` | Gauge | percent | Total CPU usage percentage (1-second sample) |
| `system.cpu.cores` | Gauge | —       | Number of logical CPU cores                  |

### Memory

| Metric                    | Type  | Unit    | Description             |
| ------------------------- | ----- | ------- | ----------------------- |
| `system.memory.total`     | Gauge | bytes   | Total memory            |
| `system.memory.used`      | Gauge | bytes   | Used memory             |
| `system.memory.available` | Gauge | bytes   | Available memory        |
| `system.memory.usage`     | Gauge | percent | Memory usage percentage |

### Disk

Labels: `path`

| Metric              | Type  | Unit    | Description           |
| ------------------- | ----- | ------- | --------------------- |
| `system.disk.total` | Gauge | bytes   | Total disk space      |
| `system.disk.used`  | Gauge | bytes   | Used disk space       |
| `system.disk.free`  | Gauge | bytes   | Free disk space       |
| `system.disk.usage` | Gauge | percent | Disk usage percentage |

Default path: `/` (Linux/macOS), `C:` (Windows). Configurable via `DiskPaths`.

### Network

| Metric                           | Type    | Unit    | Description                                 |
| -------------------------------- | ------- | ------- | ------------------------------------------- |
| `system.network.bytes_sent`      | Counter | bytes   | Total bytes sent (all interfaces)           |
| `system.network.bytes_recv`      | Counter | bytes   | Total bytes received                        |
| `system.network.packets_sent`    | Counter | —       | Total packets sent                          |
| `system.network.packets_recv`    | Counter | —       | Total packets received                      |
| `system.network.errors_in`       | Counter | —       | Total input errors                          |
| `system.network.errors_out`      | Counter | —       | Total output errors                         |
| `system.network.bytes_sent_rate` | Gauge   | bytes/s | Bytes sent per second (computed from delta) |
| `system.network.bytes_recv_rate` | Gauge   | bytes/s | Bytes received per second                   |

> Rate metrics only appear after the second collection cycle (require a previous sample).

---

## SystemInfo (heartbeat payload)

`GetSystemInfo()` returns a comprehensive `SystemInfo` struct sent to the platform on each heartbeat. This is **not** emitted as OTLP metrics — it goes through the heartbeat/registration channel.

### Key fields

**Host:** `Hostname`, `OS`, `OSVersion`, `Platform`, `PlatformFamily`, `KernelVersion`, `Architecture`, `Uptime`, `BootTime`, `HostID`, `Timezone`

**CPU:** `CPUModel`, `CPUVendor`, `CPUCores`, `CPULogicalCores`, `CPUPhysicalCores`, `CPUMhz`, `CPUUsage`, `CPUPerCore[]`, `LoadAvg1/5/15`, per-mode percents (user/system/idle/iowait/steal/guest/irq/softirq/nice)

**Memory:** full breakdown (total/used/available/free/cached/buffers/active/inactive/wired/shared/slab/page_tables/committed/dirty/writeback), swap (total/used/free/in/out), page faults (major/minor, Linux)

**Disk:** primary disk (total/used/available/usage/inodes), I/O counters (read/write bytes+ops+time), IOPS, latency, per-partition list

**Network:** totals (bytes sent/recv, packets, errors, drops, fifo), per-interface list with IP addresses and counters, TCP connection state counts (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, LISTEN, etc.), TCP retransmits (Linux `/proc/net/snmp`)

**Processes:** total count, running/sleeping/stopped/zombie/blocked, thread count

**System resources (Linux):** open/max file descriptors, entropy available, context switches, interrupts, soft interrupts, system calls

**Container/Virtualization detection:**

- `IsContainer`, `ContainerID`, `ContainerRuntime`, `ContainerName`, `ContainerImage`
- `IsVirtualized`, `VirtualizationType` (vmware, kvm, xen, hyper-v, aws, gcp)
- `IsKubernetes`, `K8sProvider` (eks, gke, aks, ack, cce, k3s, kind, minikube, rancher, openshift, okd, microshift, kubesphere, self-managed)
- `CloudProvider`, `CloudInstanceID`, `CloudInstanceType`, `CloudRegion`, `CloudZone`

**Agent metadata:** `AgentVersion`, `AgentStartTime`, `AgentUptime`, `CollectionTime`, `CollectionDuration`

---

## Configuration

```yaml
system:
  enabled: true
  interval: 15s
  collect_cpu: true
  collect_memory: true
  collect_disk: true
  collect_network: true
  disk_paths:
    - "/"
```
