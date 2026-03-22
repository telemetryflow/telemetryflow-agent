# TelemetryFlow Agent — Collector Reference

Documentation for all metric collectors in the TelemetryFlow Agent.

## Kubernetes Collector

The Kubernetes collector uses four data sources:

| Source                                 | Used by                                                                                                  |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Kubernetes API server                  | Nodes, Pods, Deployments, Workloads, Storage, HPA, PDB, Events, Resource Counts, Pod Logs                |
| metrics-server (MetricsV1beta1)        | Node and pod/container CPU+memory usage                                                                  |
| Kubelet `/stats/summary` (proxied)     | Node CPU-ns, memory working set, filesystem, imageFs, network; Container ephemeral storage + working set |
| cAdvisor `/metrics/cadvisor` (proxied) | Container CPU throttle seconds (`container_cpu_cfs_throttled_seconds_total`)                             |

| Document                                                       | Description                                                                               |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [KUBERNETES-NODES.md](KUBERNETES-NODES.md)                     | Node capacity, allocatable, usage, filesystem, network                                    |
| [KUBERNETES-PODS.md](KUBERNETES-PODS.md)                       | Pod phase, container resources, ephemeral storage, working set, CPU throttle, termination |
| [KUBERNETES-DEPLOYMENTS.md](KUBERNETES-DEPLOYMENTS.md)         | Deployment replica counts and rollout conditions                                          |
| [KUBERNETES-WORKLOADS.md](KUBERNETES-WORKLOADS.md)             | StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs                                     |
| [KUBERNETES-STORAGE.md](KUBERNETES-STORAGE.md)                 | PersistentVolumes and PersistentVolumeClaims                                              |
| [KUBERNETES-NETWORK.md](KUBERNETES-NETWORK.md)                 | Namespace-level network I/O from Kubelet summary                                          |
| [KUBERNETES-HPA.md](KUBERNETES-HPA.md)                         | HorizontalPodAutoscaler replicas and conditions                                           |
| [KUBERNETES-PDB.md](KUBERNETES-PDB.md)                         | PodDisruptionBudget health and disruption budget                                          |
| [KUBERNETES-EVENTS.md](KUBERNETES-EVENTS.md)                   | Kubernetes events and aggregate event counts                                              |
| [KUBERNETES-RESOURCE-COUNTS.md](KUBERNETES-RESOURCE-COUNTS.md) | Secrets, ConfigMaps, Ingresses per namespace                                              |
| [KUBERNETES-POD-LOGS.md](KUBERNETES-POD-LOGS.md)               | Pod container log collection                                                              |

## Host Collectors

| Document                             | Description                                                                                        |
| ------------------------------------ | -------------------------------------------------------------------------------------------------- |
| [NODE-EXPORTER.md](NODE-EXPORTER.md) | Full node_exporter equivalent: CPU, memory, disk I/O, filesystem, network, load, thermal, textfile |
| [SYSTEM.md](SYSTEM.md)               | Lightweight host metrics + rich SystemInfo for agent heartbeat                                     |

## Container Collectors

| Document                   | Description                                                        |
| -------------------------- | ------------------------------------------------------------------ |
| [DOCKER.md](DOCKER.md)     | Docker Engine API: container CPU, memory, network, disk I/O, PIDs  |
| [CADVISOR.md](CADVISOR.md) | cAdvisor Prometheus scraper: `container_*` and `machine_*` metrics |

## Kernel Collector

| Document           | Description                                                                           |
| ------------------ | ------------------------------------------------------------------------------------- |
| [EBPF.md](EBPF.md) | eBPF: syscalls, TCP/UDP, file I/O, scheduler, memory faults, TCP state, Cilium Hubble |

## Metric Naming Conventions

| Prefix                      | Collector                            |
| --------------------------- | ------------------------------------ |
| `k8s.*`                     | Kubernetes collector                 |
| `node.*`                    | Node Exporter collector              |
| `system.*`                  | System Host collector                |
| `container.*`               | Docker collector                     |
| `container_*` / `machine_*` | cAdvisor (original Prometheus names) |
| `ebpf.*`                    | eBPF collector                       |
