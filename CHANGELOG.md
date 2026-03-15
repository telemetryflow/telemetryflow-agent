<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg">
    <img src="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg" alt="TelemetryFlow Logo" width="80%">
  </picture>

  <h3>TelemetryFlow Agent (OTEL Agent)</h3>

[![Version](https://img.shields.io/badge/Version-1.1.9-orange.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://golang.org/)
[![OTEL SDK](https://img.shields.io/badge/OpenTelemetry_SDK-1.40.0-blueviolet)](https://opentelemetry.io/)
[![OpenTelemetry](https://img.shields.io/badge/OTLP-100%25%20Compliant-success?logo=opentelemetry)](https://opentelemetry.io/)

</div>

---

# Changelog

All notable changes to TelemetryFlow Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.1/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.9] - 2026-03-15

### Added

- **K8s Node Log Collection** (`internal/collector/kubernetes/node_logs.go`): New collector that retrieves kubelet, kube-proxy, and containerd logs from every K8s node
  - Uses K8s API server node proxy endpoint: `GET /api/v1/nodes/{name}/proxy/logs/{source}.log`
  - Configurable via `node_logs: true`, `node_logs_tail_lines: 200`, `node_log_sources: [kubelet, kube-proxy, containerd]`
  - Collected log lines included in cluster sync payload (`node_logs` field in `ClusterState`)
  - Backend stores in dedicated `kubernetes_node_logs` ClickHouse table (7-day TTL) + dual-write to unified `logs` table (30-day TTL)
- **VM File & Journald Log Collector** (`internal/collector/log/`): Full implementation of the previously-stubbed `LogCollectorConfig`
  - `collector.go`: Main `LogCollector` implementing `collector.Collector` interface — orchestrates file tailers and journald, exports via OTLP callback
  - `tail.go`: `FileTailer` engine — tails log files from EOF, handles rotation (truncation/inode change), supports glob path expansion
  - `journald_linux.go`: Systemd journal follower via `journalctl --follow --output=json` with unit and priority filtering
  - `journald_stub.go`: No-op stub for non-Linux platforms
  - `inode_unix.go` / `inode_windows.go`: Platform-specific inode detection for log rotation
  - Enhanced `LogCollectorConfig`: `interval`, `max_line_size`, `batch_size`, `multiline_pattern`, nested `journald { enabled, units, priorities }`
  - Self-monitoring metrics: `tfo.log_collector.lines_total`, `tfo.log_collector.bytes_total`
  - Include/exclude regex pattern filtering applied at collection time (before buffering)
- **Extended K8s Metrics Config Fields** (`collectors.kubernetes`): Five new config fields enabling TFO Agent to replace Prometheus, kube-state-metrics, and cAdvisor as external dependencies
  - `apiserver_metrics: true` — Scrape kube-apiserver `/metrics` endpoint for request rates, latency, error rates, work queue depth, CPU/memory usage
  - `coredns_metrics: true` — Scrape CoreDNS `/metrics` endpoint for DNS request rates, cache hit rates, duration p99, upstream requests, error rates
  - `coredns_service` — CoreDNS service address (default: `kube-dns.kube-system.svc.cluster.local:9153`)
  - `container_extended_metrics: true` — Collect per-container CPU throttling, memory working set, and OOM kill detection via Kubelet `/stats/summary` and cAdvisor
  - `pv_io_stats: true` — Collect PersistentVolume usage, IOPS, and throughput from Kubelet volume stats API
- **cAdvisor TLS & Auth Support** (`internal/collector/cadvisor/cadvisor.go`): cAdvisor collector now supports HTTPS kubelet endpoints
  - `InsecureSkipVerify` config field to skip TLS certificate verification for self-signed kubelet certs
  - `BearerTokenPath` config field for custom ServiceAccount token path (auto-detected from standard K8s mount if empty)
  - Auto-reads bearer token from `/var/run/secrets/kubernetes.io/serviceaccount/token` for kubelet authentication
- **RBAC Updates** (`deploy/helm/`, `deploy/kubernetes/`): Added missing permissions for new collectors
  - `pods/log` — required for pod log collection
  - `poddisruptionbudgets` (policy API group) — required for PDB collector
  - `endpointslices` (discovery.k8s.io) — replaces deprecated v1 Endpoints
  - `/metrics/cadvisor` non-resource URL — required for cAdvisor scraping

- **Prometheus Remote Write Receiver (`internal/receiver/remotewrite/`)**: New push-based ingestion path accepting Prometheus `remote_write` traffic directly
  - `receiver.go`: HTTP server lifecycle with graceful start/stop and configurable port
  - `handler.go`: HTTP request handler — snappy decompression + protobuf decode, content-type validation
  - `decoder.go`: `DecodeWriteRequest` converts raw HTTP body (snappy + protobuf `WriteRequest`) to `prompb.WriteRequest`
  - `converter.go`: `ConvertTimeSeries` maps each `prompb.TimeSeries` to `[]collector.Metric`; extracts `__name__` as metric name, sanitizes all other labels
  - `metrics.go`: Prometheus instrumentation counters for requests, bytes, timeseries, errors per receiver instance
  - `config.go`: `RemoteWriteReceiverConfig` struct (Enabled, Port) mapping to `collectors.remote_write_receiver` config section
  - Property-based tests (`converter_pbt_test.go`) validating label preservation, name extraction, and missing-name error path
- **KSM Gap Sub-collectors** (`collectors.kubernetes`): Five new fields filling coverage gaps left by kube-state-metrics
  - `resource_quotas: true` — ResourceQuota hard/used per namespace
  - `limit_ranges: true` — LimitRange default/max constraints per namespace
  - `pod_conditions: true` — Per-pod condition status (Ready, PodScheduled, ContainersReady, etc.)
  - `node_taints: true` — Node taint inventory (key, effect, value)
  - `workload_generations: true` — Deployment/StatefulSet observed vs desired generation drift
- **`collectors.remote_write_receiver` config section**: Added to all config files (`tfo-agent.yaml`, `tfo-agent.default.yaml`, `tfo-agent-one-for-all.yaml`), default: `enabled: false`, `port: 9091`
- **Apache License 2.0 headers**: Full license boilerplate + package documentation added to all 187 `.go` files across all packages; property-based test files previously missing headers now covered

### Fixed

- **Config env var expansion** (`internal/config/loader.go`): Viper-based config loader now calls `os.ExpandEnv()` on YAML content before parsing, resolving `${VAR}` placeholders in config values (e.g., `${NODE_IP}` in cAdvisor endpoint). Previously, env var references in config values were passed as literal strings, causing URL parse failures
- **cAdvisor kubelet HTTPS** (`internal/collector/cadvisor/cadvisor.go`): HTTP client now respects `insecure_skip_verify` config and includes ServiceAccount bearer token in requests. Previously, HTTPS kubelet endpoints failed with `x509: certificate signed by unknown authority` and `403 Forbidden`
- **eBPF build constraints**: Restored `//go:build linux` and `//go:build !linux` constraints to all 9 eBPF package files after bulk header replacement had stripped them
  - `types.go`, `gen.go`, `loader.go`, `helpers.go`, `config_linux.go`, `linux.go`, `hubble_linux.go` → `//go:build linux`
  - `linux_other.go`, `hubble_other.go` → `//go:build !linux`

### Changed

- **Helm chart path**: Renamed `deploy/helm/tfo-agent/` → `deploy/helm/telemetryflow-agent/` for naming consistency with other TelemetryFlow Helm charts
- **Platform monolith configs** (`config/tfo-agent/`): All three deployment configs (`tfo-agent.yaml`, `tfo-agent.k8s.yaml`, `tfo-agent.container.yaml`) updated with KSM gap fields and `remote_write_receiver` section
- **All config files updated** (`configs/`, `deploy/`): Added extended K8s metrics fields (`apiserver_metrics`, `coredns_metrics`, `container_extended_metrics`, `pv_io_stats`) to all config variants — `configs/tfo-agent.yaml`, `configs/tfo-agent.default.yaml`, `configs/tfo-agent-one-for-all.yaml`, `deploy/helm/values.yaml`, `deploy/helm/values-one-for-all.yaml`, `deploy/kubernetes/configmap.yaml`

## [1.1.8] - 2026-03-09

### Added

- **Stable Agent Identity (`internal/agent/identity.go`)**: Agent ID is now deterministic across restarts and container rebuilds via UUIDv5 fingerprinting — no more phantom duplicate agents after pod rollouts
  - **Priority chain**: explicit `TELEMETRYFLOW_ID` / `agent.id` config → UUIDv5 fingerprint → random UUIDv4 fallback (with warning)
  - **Fingerprint components**: `NODE_NAME` (Kubernetes Downward API, highest priority) + OS `HostID` (`/etc/machine-id` on Linux, hardware UUID on macOS) + hostname — joined and hashed with a fixed TelemetryFlow namespace UUID
  - Same agent UUID is produced on every restart as long as the underlying host/node identity is unchanged
  - Logs `Derived stable agent ID from host fingerprint` with component labels for observability
- **Kubernetes Provider Detection (`internal/collector/system/host.go`)**: Host collector now detects the Kubernetes distribution/provider and exposes it in `SystemInfo`
  - New `detectK8sProvider()` function covers all 15 provider types matching `K8sProviderEnum` on the platform backend
  - **Managed cloud**: `eks` (AWS), `gke` (GCP), `aks` (Azure), `ack` (Alibaba Cloud), `cce` (Huawei Cloud) — detected from cloud-injected environment variables
  - **OpenShift variants** (priority order): `microshift` → `openshift` → `okd` — detected via env vars and host filesystem paths
  - **Lightweight/local distributions**: `k3s`, `rancher` (RKE/RKE2), `minikube`, `kind` — detected via `CATTLE_*` env vars and `/var/lib/rancher/*` host paths
  - **Platform distributions**: `kubesphere` — detected via `KUBESPHERE_NAMESPACE` env var
  - **Generic fallback**: `self-managed` when `KUBERNETES_SERVICE_HOST` is set but no specific distribution is identified
  - Host filesystem paths checked both directly and under `TELEMETRYFLOW_HOST_ROOT` prefix — detection works correctly inside DaemonSet containers
  - Returns `(false, "")` when not running in a Kubernetes environment at all
  - New `IsKubernetes bool` and `K8sProvider string` fields added to `collector.SystemInfo` struct
- **HPA Sub-collector (`collectors.kubernetes.hpa: true`)**: HorizontalPodAutoscaler monitoring
  - 5 new metrics: `k8s.hpa.min_replicas`, `k8s.hpa.max_replicas`, `k8s.hpa.current_replicas`, `k8s.hpa.desired_replicas`, `k8s.hpa.condition`
  - Condition types: `AbleToScale`, `ScalingActive`, `ScalingLimited` — emitted as `1` (True) / `0` (False/Unknown)
  - Labels: `namespace`, `hpa`, `target_kind`, `target_name`
- **PDB Sub-collector (`collectors.kubernetes.pdb: true`)**: PodDisruptionBudget health monitoring
  - 4 new metrics: `k8s.pdb.pods_healthy`, `k8s.pdb.pods_desired`, `k8s.pdb.disruptions_allowed`, `k8s.pdb.expected_pods`
  - Labels: `namespace`, `pdb`
  - RBAC: `policy` apiGroup with `poddisruptionbudgets` resource added to ClusterRole
- **Pod Log Collection (`collectors.kubernetes.pod_logs: true`)**: Tail-based container log collection from the Kubernetes API
  - Collects last N lines (`pod_logs_tail_lines`, default 100) per running container per cycle
  - Optional namespace allowlist via `pod_logs_namespaces` (empty = same as `namespace_filter`)
  - Emits `PodLogEntry` records: `timestamp`, `namespace`, `pod`, `container`, `log_line`
  - Respects the existing `namespace_filter` / `exclude_namespaces` config
- **Kubelet `/stats/summary` Expansion**: Extended Kubelet summary scraping with container-level and node-level data
  - **Container ephemeral storage**: `k8s.pod.container.ephemeral_storage.usage` and `k8s.pod.container.ephemeral_storage.limit` (bytes)
  - **Container memory working set**: `k8s.pod.container.memory.working_set` (bytes, matches `kubectl top`)
  - **Node-level network I/O** via Kubelet summary: namespace-level `k8s.network.rx_bytes` / `k8s.network.tx_bytes` (existing `network: true` flag)
- **Collector Documentation (`docs/collectors/`)**: 17 new reference documents covering every collector and sub-collector
  - Kubernetes: NODES, PODS, DEPLOYMENTS, WORKLOADS, STORAGE, NETWORK, HPA, PDB, EVENTS, RESOURCE-COUNTS, POD-LOGS
  - Host: NODE-EXPORTER (50+ metrics), SYSTEM (14 metrics + SystemInfo heartbeat fields)
  - Container: DOCKER (24 metrics), CADVISOR (Prometheus scraper)
  - Kernel: EBPF (20 metrics, 7 sub-collectors)
  - `README.md` index with data source table and metric naming conventions

### Changed

- **`internal/agent/agent.go`**: Replaced inline `uuid.New()` call with `ResolveAgentID(cfg.Agent.ID, cfg.Agent.Hostname, logger)` from the new identity module
- **`deploy/kubernetes/daemonset.yaml`**: Added `HOST_PROC`, `HOST_ETC`, `HOST_SYS`, `HOST_VAR`, `HOST_RUN` environment variables so that `gopsutil` reads `/etc/machine-id` and other identity files from the **host node** rather than the container image — required for a stable `HostID` in the fingerprint
- **Config files updated** — all YAML configs now include `hpa`, `pdb`, `pod_logs`, `pod_logs_tail_lines`, `pod_logs_namespaces` under `collectors.kubernetes`:
  - `configs/tfo-agent.yaml`
  - `configs/tfo-agent.default.yaml`
  - `deploy/helm/tfo-agent/values.yaml` (both `config` and `kubernetes.config` sections)
- **RBAC ClusterRole** (`deploy/helm/tfo-agent/templates/clusterrole.yaml`): Added `policy` apiGroup rule for `poddisruptionbudgets` (required by PDB sub-collector)

### Fixed

- **Duplicate `SyncKubernetesState` declaration**: Removed stale method from `pkg/api/client.go` (path-based, no gzip) that conflicted with the purpose-built declaration in `pkg/api/kubernetes.go`
- **`KubernetesSyncClient` interface mismatch**: Updated `pkg/api/kubernetes.go` `SyncKubernetesState` signature from `(ctx, state interface{})` to `(ctx, clusterID string, payload interface{})`, matching the `exporter.KubernetesSyncClient` interface and the `sendSync` call in `internal/exporter/kubernetes_sync.go`; path now built as `/monitoring/kubernetes/clusters/{clusterID}/sync` with gzip encoding

### Security

- **Go toolchain upgraded 1.25 → 1.26** (`Dockerfile`, `go.mod`): addresses two Go `crypto/x509` vulnerabilities in the stdlib fixed in Go 1.26
  - **CVE-2026-27138** (UNKNOWN): certificate chain verification could panic when a certificate contained certain malformed fields
  - **CVE-2026-27137** (UNKNOWN): certificate chain containing a crafted certificate could trigger incorrect verification behaviour
- **zlib upgraded to 1.3.2-r0** via `apk upgrade --no-cache` in the runtime Alpine stage (already present): addresses two zlib vulnerabilities fixed in Alpine package `zlib 1.3.2-r0`
  - **CVE-2026-22184** (CRITICAL): arbitrary code execution via buffer overflow in the `untgz` utility
  - **CVE-2026-27171** (MEDIUM): denial of service via infinite loop in CRC32 combine functions

## [1.1.6] - 2026-02-21

### Changed

- **Go Version**: Upgraded to Go 1.25.7 (via gvm), updated `golangci-lint` to v2.10.1 for compatibility
- **OpenTelemetry SDK**: Bumped to v1.40.0

### Fixed

- **Lint — proper build tags (no `//nolint`)**: All eBPF/Hubble code that is Linux-only now carries explicit `//go:build linux` / `//go:build !linux` constraints instead of suppression comments
  - `internal/collector/ebpf/types.go` — added `//go:build linux` (BPF map structs)
  - `internal/collector/ebpf/helpers.go` — added `//go:build linux` (syscall/TCP state name maps)
  - `internal/collector/ebpf/config.go` — removed `shouldIncludeProcess`; moved to new `config_linux.go`
  - `internal/collector/ebpf/hubble_linux.go` — full `hubbleClient` implementation (linux-only)
  - `internal/collector/ebpf/hubble_other.go` — minimal stub for non-Linux builds
- **errcheck**: All unchecked `Close()` / `Body.Close()` calls wrapped with `_ =` or `defer func() { _ = ... }()` across cadvisor, docker, ebpf collectors and prometheus server test
- **staticcheck**: Replaced deprecated `fake.NewSimpleClientset` with `fake.NewClientset` in `tests/mocks/kubernetes_client.go`

## [1.1.5] - 2026-02-19

### Added

- **Docker Container Metrics Collector**: Native Docker Engine API collector replacing cAdvisor dependency
  - Uses Docker SDK (`github.com/docker/docker`) with `ContainerStatsOneShot` for per-container metrics
  - **CPU**: `container.cpu.usage_percent`, `container.cpu.usage_total`, `container.cpu.user`, `container.cpu.kernel`, `container.cpu.online_cpus`, `container.cpu.throttled_periods`, `container.cpu.throttled_time`
  - **Memory**: `container.memory.usage`, `container.memory.working_set` (usage - inactive_file), `container.memory.limit`, `container.memory.max_usage`, `container.memory.rss`, `container.memory.cache`, `container.memory.usage_percent`
  - **Network**: Per-interface `container.network.{rx,tx}_{bytes,packets,errors,dropped}`
  - **Disk I/O**: `container.diskio.{read,write}_{bytes,ops}`
  - **PIDs**: `container.pids.current`
  - **State Summary**: `container.state.{running,stopped,paused,restarting,total}`
  - Container filtering with regex include/exclude patterns
  - Labels per metric: `container_id`, `container_name`, `image`, `status`
  - CPU delta tracking for accurate percentage calculation
- **cAdvisor Prometheus Scraper Collector**: Scrapes container metrics from cAdvisor's `/metrics` endpoint
  - Parses Prometheus text format using `prometheus/common/expfmt`
  - Collects `container_*` and `machine_*` metric families by default
  - Supports all Prometheus types: counter, gauge, histogram, summary, untyped
  - Optional `metric_names` allowlist for selective collection
  - Custom labels injection from config
  - Configurable endpoint, metrics path, timeout, and interval
- **Tags and Labels Propagation**: Agent tags and custom labels now included in heartbeat and OTLP exports
  - `tags` and `labels` fields added to heartbeat payload
  - Tags/labels exported as OTEL resource attributes

### Fixed

- **CPU Usage on macOS**: Removed `omitempty` from float64 fields in `SystemInfoPayload` that caused valid 0.0 values (CPU idle, iowait, steal, etc.) to be dropped from JSON serialization, resulting in "NaN %" display in dashboard

### Changed

- **Alphabetical Ordering**: All collectors in `config.go`, `agent.go`, and `tfo-agent.yaml` are now sorted alphabetically (cAdvisor → Docker → eBPF → Kubernetes → Logs → Node Exporter → Process → System)

### Dependencies

- Added `github.com/docker/docker v27.5.1+incompatible` for Docker Engine API

## [1.1.4] - 2026-02-11

### Added

- **eBPF Collector**: Full kernel-level metrics collector using `cilium/ebpf` library
  - 6 BPF C programs: syscalls, network, file I/O, scheduler, memory, TCP state transitions
  - 7 sub-collectors individually togglable via config flags
  - 28 metrics across syscall tracing, TCP/UDP monitoring, VFS I/O, scheduler analysis, memory page faults, and TCP state lifecycle
  - Process filtering with regex include/exclude patterns
  - Platform-safe: returns empty metrics on non-Linux (build-tagged stubs)
  - `bpf2go` code generation directives for CI compilation
  - Syscall name mapping (60+ Linux amd64 syscalls) and TCP state name mapping (12 states)
- **Cilium Hubble Integration**: gRPC client for Cilium Hubble Relay
  - L3/L4 network flow metrics
  - L7 protocol visibility (HTTP, DNS)
  - Network policy verdict and drop metrics
  - Mutual TLS support for production Cilium clusters
  - 6 Hubble metrics: flows, drops, policy_verdicts, http_requests, dns_queries, l7_errors
- **eBPF Configuration**: Full config support under `collectors.ebpf`
  - YAML config with sub-collector toggles, process filters, buffer sizes, BTF/pin paths
  - Environment variables: `TELEMETRYFLOW_EBPF_ENABLED`, `TELEMETRYFLOW_EBPF_BTF_PATH`, `TELEMETRYFLOW_EBPF_PIN_PATH`
  - Cilium sub-config with Hubble address, TLS, and collection toggles
- **eBPF Unit Tests**: 34 tests covering collector lifecycle, config validation, metric structures
  - `tests/unit/domain/ebpf/` with 4 test files
  - Config validation (sample_rate, buffer sizes, process filters, Cilium config)
  - Metric structure verification for all 28 metric types
  - Platform-aware tests (Linux vs non-Linux)
- **eBPF Documentation**: 6 documents in `docs/integrations/eBPF/`
  - Architecture with mermaid diagrams showing kernel/userspace data flow
  - Full YAML configuration reference with tuning guide
  - Complete metric catalog with PromQL examples
  - BPF C program design: map strategy, tracepoint details, CO-RE support
  - Cilium Hubble integration guide
  - Operations guide: requirements, deployment, troubleshooting, security
- **Makefile Targets**: Added `test-ebpf`, `generate-ebpf`, `build-ebpf` targets
- **New Dependency**: `github.com/cilium/ebpf v0.20.0` for BPF program loading and map interaction

## [1.1.3] - 2026-02-04

### Added

- **Network Retransmit Metrics**: TCP retransmit segment counting from `/proc/net/snmp` (Linux)
  - Parses `RetransSegs` from the TCP section of `/proc/net/snmp`
  - Provides visibility into network reliability and congestion issues
- **Network Throughput Rate Calculation**: Real-time bytes sent/recv rate metrics in `GetSystemInfo()`
  - Calculates `NetworkBytesSentRate` and `NetworkBytesRecvRate` using cached previous values
  - Thread-safe rate tracking via `systemInfoCache` with mutex protection
- **Container Name Detection**: New `getContainerName()` function for container identity
  - Supports `CONTAINER_NAME`, Docker Compose (`COMPOSE_PROJECT_NAME` + `COMPOSE_SERVICE`)
  - Kubernetes pod name via `POD_NAME` environment variable
  - Docker container name via `DOCKER_CONTAINER_NAME`
- **Container Image Detection**: New `getContainerImage()` function for container image tracking
  - Supports `CONTAINER_IMAGE`, Kubernetes `POD_IMAGE`, and Docker `DOCKER_IMAGE` environment variables
- **Memory Page Fault Metrics**: Page fault tracking from `/proc/vmstat` (Linux)
  - Major page faults (`pgmajfault`) and minor page faults (derived from total `pgfault` - major)
- **Disk IOPS Calculation**: Operations per second metric derived from disk I/O counters
  - Calculates IOPS from total read/write operations and IO time
- **System Call Counting**: Aggregate system call metrics from all processes (Linux)
  - Reads from `/proc/[pid]/io` to count read (`syscr`) and write (`syscw`) system calls

## [1.1.2] - 2026-01-03

### Added

- **New Open Source Observability Integrations**: Added five new open-source observability platforms
  - **SigNoz**: Open-source APM with OTLP support for metrics, logs, and traces
  - **Coroot**: eBPF-based observability with automatic service map discovery
  - **HyperDX**: Open-source observability platform built on ClickHouse
  - **OpenObserve**: Efficient observability platform for logs, metrics, and traces
  - **Netdata**: Real-time infrastructure monitoring for metrics
- **New APM Integrations**: Added three new enterprise APM platform integrations
  - **Dynatrace**: Full metrics, logs, and traces support via MINT protocol and OTLP
  - **IBM Instana**: Full metrics, logs (as events), and traces support with zone configuration
  - **ManageEngine**: Metrics and logs support for OpManager, Site24x7, and Applications Manager
- **Makefile Refactoring**: Comprehensive Makefile update aligned with TFO-Collector
  - Added CI-specific targets: `ci`, `ci-lint`, `ci-test`, `ci-build`, `ci-release`
  - Added new development targets: `run-debug`, `dev-watch`, `test-verbose`, `test-race`
  - Added `build-windows` target for Windows platform builds
  - Added `info` target to display build configuration
  - Added `integrations` target to list all 35+ supported integrations
  - Added `docker` alias and `docker-run` targets
  - Improved section organization with clear headers
  - Updated LDFLAGS to include OTELSDKVersion
- **Specific Test Runner Script**: New `scripts/test-specific.sh` for running individual unit tests
  - Run tests by package name (e.g., `./scripts/test-specific.sh integrations`)
  - Run tests by function name pattern (e.g., `./scripts/test-specific.sh TestPerconaCollector`)
  - Run specific test in a package (e.g., `./scripts/test-specific.sh integrations:TestKafka`)
  - Support for coverage, race detection, timeout, and count options
  - CI mode with `--ci` flag for race detection and coverage combined
  - List available test packages with `-l` or `--list` option
- **Makefile Test Targets**: Added new make targets for specific test execution
  - `make test-run PKG=<package>` - Run all tests in a package
  - `make test-run TEST=<name>` - Run tests matching a name pattern
  - `make test-run PKG=<package> TEST=<name>` - Run specific test in a package
  - `make test-list` - List all available test packages
- **README Integration Documentation**: Added comprehensive integration capabilities section
  - Integration Categories table with 34+ integrations across 10 categories
  - Data Type Support Matrix showing Metrics/Logs/Traces support per integration
  - Integration Capabilities Comparison vs Datadog, New Relic, Dynatrace, Instana, Splunk, ManageEngine, Grafana Stack
  - Key Differentiators highlighting TFO-Agent unique features

### Changed

- **Configuration Files**: All integration configurations now alphabetically sorted
  - `.env.example`: 34 integrations sorted A-Z with clear section headers
  - `tfo-agent.yaml`: Integrations section reorganized alphabetically
  - `docs/integrations/OBSERVABILITY.md`: Quick reference table sorted alphabetically

### Fixed

- **Linter Fix**: Removed unused `dynatraceMetricLine` struct in Dynatrace exporter

## [1.1.1] - 2024-12-29

### Added

- **Enterprise 3rd Party Integrations**: Added comprehensive integration support for enterprise environments
  - **Cloud Providers**: GCP (Cloud Monitoring, Logging, Trace), Azure (Monitor, Log Analytics, App Insights), Alibaba Cloud (CMS, SLS, ARMS)
  - **Infrastructure**: Proxmox VE, VMware vSphere, Nutanix (Prism Central/Element), Azure Arc
  - **Network & IoT**: Cisco (DNA Center, Meraki Dashboard), SNMP v1/v2c/v3, MQTT
  - **Kernel/System**: eBPF for Linux kernel-level observability (syscalls, network, file I/O, scheduler)
  - **Observability**: Blackbox (synthetic monitoring), Telegraf, Grafana Alloy, Percona PMM
- **Integration Manager**: New centralized manager for all integration exporters with parallel export, health checks, and statistics
- **Integration Documentation**: Added comprehensive documentation with Mermaid diagrams
  - `docs/integrations/README.md` - Integration overview and architecture
  - `docs/integrations/CLOUD-PROVIDERS.md` - GCP, Azure, Alibaba configuration
  - `docs/integrations/INFRASTRUCTURE.md` - Proxmox, VMware, Nutanix, Azure Arc
  - `docs/integrations/NETWORK.md` - Cisco, SNMP, MQTT configuration
  - `docs/integrations/KERNEL.md` - eBPF observability guide
  - `docs/integrations/OBSERVABILITY.md` - Backend integrations
- **Dual Endpoint Ingestion Support**: Updated docker-compose and E2E configs for TFO-Collector dual ingestion
  - v1 endpoints: Standard OTEL community format (`/v1/traces`, `/v1/metrics`, `/v1/logs`)
  - v2 endpoints: TelemetryFlow enhanced format (`/v2/traces`, `/v2/metrics`, `/v2/logs`)
  - gRPC endpoint: Same port (4317) for both v1 and v2
- **TFO-Collector as Default**: Docker-compose.e2e.yml now uses `telemetryflow/telemetryflow-collector` as default image
  - Commented alternatives for TFO-Collector-OCB and OTEL Collector Contrib
  - Separate volume mounts for each collector type
- **Enhanced Port Configuration**: Added additional ports for observability
  - zPages (55679) for debugging
  - pprof (1777) for profiling
  - Prometheus exporter (8889)
- **Documentation**: Added missing documentation files
  - `docs/DEVELOPMENT.md` - Comprehensive development guide with coding standards, testing practices, and debugging tips
  - `docs/TROUBLESHOOTING.md` - Complete troubleshooting guide covering common issues, diagnostics, and solutions
  - README.md updated with OTEL Collector Ports table and dual endpoint documentation

### Fixed

- **Security Fixes (gosec)**: Resolved all gosec security warnings with proper fixes
  - **G115 Integer Overflow**: Added bounds checking for `int64` to `uint64` conversions in `host.go`
  - **G304 File Inclusion**: Added `#nosec` directive for hardcoded system paths in virtualization detection
  - **G402 TLS InsecureSkipVerify**: Added `#nosec` directives with justification and enforced `MinVersion: TLS12` for all integrations
  - **G505 Weak Crypto**: Added `#nosec` directive for `crypto/sha1` in Alibaba Cloud integration (required by API)
- **Race Condition Fixes**: Resolved data race issues detected by Go race detector (`-race` flag)
  - Fixed race condition in `TestClientRetry` - converted `attempts` counter to use `sync/atomic` operations
  - Fixed race condition in `TestHeartbeatStart` - added `sync.RWMutex` protection for `mockHeartbeatClient` fields
  - Added thread-safe getter methods `LastAgentID()` and `LastSysInfo()` for mock client
- **Flaky Test Fixes**: Improved test reliability under race detection
  - Increased timeouts in heartbeat tests from 30-50ms to 100-200ms for race detector overhead
  - Made system info tests resilient to empty OS-dependent fields
  - Added `t.Skip()` for network tests when no network interfaces are available
- **Linter Compliance**: Removed `//nolint` directives while maintaining functionality
  - Refactored deprecated `cfg.API` field access using reflection to avoid staticcheck SA1019
  - Isolated TLS `InsecureSkipVerify` into `newTLSConfig()` helper function with documentation

### Changed

- **Test Infrastructure**: Tests now pass consistently with `make ci-test` (race detection enabled)
- **Code Quality**: All tests pass with `-race -covermode=atomic` flags

## [1.1.0] - 2024-12-27

### Added

- **OpenTelemetry SDK Standardization**: Agent now uses standard OpenTelemetry Go SDK v1.39.0 directly
  - Aligned with TFO-Go-SDK v1.1.0 (same OTEL SDK v1.39.0 base)
  - Aligned with TFO-Collector v1.1.0 architecture (dual-identity model)
  - Added `OTELSDKVersion` constant for version tracking
  - Updated banner and version output to display OTEL SDK version
  - Consistent TelemetryFlow branding + standard OTEL SDK foundation
- **New OTLP Exporter**: Created `internal/exporter/otlp.go` with native OpenTelemetry SDK v1.39.0 support
  - gRPC and HTTP protocol support
  - TLS configuration with skip verify option
  - Authentication headers (X-TelemetryFlow-Key-ID, X-TelemetryFlow-Key-Secret, X-TelemetryFlow-Agent-ID)
  - Compression support (gzip)
  - Configurable batch size and flush interval
- **New `telemetryflow` Configuration Section**: Unified configuration aligned with TFO-Collector
  - `api_key_id` and `api_key_secret` for TelemetryFlow authentication
  - `endpoint` for OTLP receiver (default: `localhost:4317`)
  - `protocol` selection (grpc/http)
  - `tls` configuration with `enabled` and `skip_verify` options
  - `retry` configuration with `max_attempts`, `initial_interval`, `max_interval`
- **Configuration Helper Methods**:
  - `GetEffectiveEndpoint()` - Prefers TelemetryFlow endpoint, falls back to legacy API
  - `GetEffectiveAPIKeyID()` - Prefers TelemetryFlow API key ID, falls back to legacy
  - `GetEffectiveAPIKeySecret()` - Prefers TelemetryFlow API key secret, falls back to legacy
- **Architecture Documentation**: Added `docs/ARCHITECTURE.md` with comprehensive Mermaid diagrams
  - System architecture diagram
  - Component diagram
  - Data flow sequence diagram
  - Configuration structure diagram
  - Authentication flow diagram
  - Buffer strategy state diagram
  - OTLP export protocols diagram
  - Deployment architecture diagram
  - Package structure diagram
  - Version compatibility matrix

### Changed

- **Configuration Format**: Updated `configs/tfo-agent.yaml` to align with TFO-Collector format
- **Environment Variables**: Standardized to use `TELEMETRYFLOW_*` prefix
  - `TELEMETRYFLOW_API_KEY_ID` for API key ID
  - `TELEMETRYFLOW_API_KEY_SECRET` for API key secret
  - `TELEMETRYFLOW_ENDPOINT` for OTLP endpoint
  - `TELEMETRYFLOW_ENVIRONMENT` for deployment environment
  - `TELEMETRYFLOW_AGENT_ID` for agent identification
  - `TELEMETRYFLOW_AGENT_NAME` for agent naming
- **GitHub Workflows**:
  - Updated CodeQL Action from v3 to v4
  - Enhanced Docker workflow with disk cleanup, Go version tracking, SBOM fixes
  - Improved release workflow with DMG creation enhancements

### Fixed

- Buffer test failures: Added `MaxAge` and `FlushInterval` to test configurations
- Exporter test context mismatch: Fixed mock expectations for context handling
- Heartbeat test assertions: Corrected error vs nil return expectations

### Removed

- **Unused telemetryflow-go-sdk Dependency**: Removed `telemetryflow-go-sdk v1.1.0` from go.mod as it was declared but never imported (agent already uses standard OpenTelemetry SDK)

### Dependencies

- OpenTelemetry SDK: v1.39.0
- OpenTelemetry OTLP Exporters: v1.39.0
- gRPC: v1.77.0
- Go: 1.24+

## [1.0.1] - 2024-12-17

### Added

- GitHub Actions workflow for Docker image building with semantic versioning
- Multi-platform Docker support (linux/amd64, linux/arm64)
- SBOM generation for Docker images
- Trivy security scanning in CI/CD pipeline
- GitHub Container Registry publishing
- Docker Hub publishing support
- GitHub Workflows documentation

### Changed

- Updated documentation structure with new GITHUB-WORKFLOWS.md

## [1.0.0] - 2024-12-17

### Added

- Initial release of TelemetryFlow Agent
- OpenTelemetry native telemetry collection
- OTLP export for metrics, logs, and traces
- Agent registration with TelemetryFlow backend
- Heartbeat monitoring and health status sync
- System metrics collection (CPU, memory, disk, network)
- Disk-backed buffer for resilient retry
- Auto-reconnection with exponential backoff
- Graceful shutdown signal handling
- Cross-platform support (Linux, macOS, Windows)
- Docker and Docker Compose support
- Systemd service configuration
- RPM and DEB package builds
- macOS DMG installer
- Windows ZIP with PowerShell installer
- CLI commands: `start`, `version`, `config validate`
- LEGO building blocks architecture
- Plugin registry system

### Documentation

- README with quick start guide
- Installation guide for all platforms
- Configuration reference
- CLI commands reference

---

## Version History

| Version | Date       | OTEL SDK | Description                                                                                                       |
| ------- | ---------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| 1.1.9   | 2026-03-12 | v1.40.0  | Prometheus Remote Write Receiver; KSM gap fields (5); license headers all .go files; eBPF build constraint fixes; Helm rename |
| 1.1.8   | 2026-03-09 | v1.40.0  | HPA/PDB/pod-logs sub-collectors; Kubelet summary ephemeral + working set; Go 1.26 + security fixes; 17 collector docs |
| 1.1.7   | 2026-03-08 | v1.40.0  | Stable agent identity via UUIDv5 host fingerprint; K8s provider detection (15 providers); fix SyncKubernetesState |
| 1.1.6   | 2026-02-21 | v1.40.0  | Go 1.25.7, OTEL SDK v1.40.0, build-tag lint fixes, errcheck/staticcheck cleanup                                   |
| 1.1.5   | 2026-02-19 | v1.39.0  | Docker container collector, cAdvisor scraper, CPU fix macOS, tags/labels propagation                              |
| 1.1.4   | 2026-02-11 | v1.39.0  | eBPF collector (28 metrics), Cilium Hubble integration, 6 BPF programs, kernel-level observability                |
| 1.1.3   | 2026-02-04 | v1.39.0  | Network retransmit metrics, container name/image detection, page faults, IOPS, system calls                       |
| 1.1.2   | 2026-01-03 | v1.39.0  | OSS observability (SigNoz, Coroot, HyperDX, OpenObserve, Netdata), APM (Dynatrace, Instana, ManageEngine)         |
| 1.1.1   | 2024-12-29 | v1.39.0  | Enterprise integrations (GCP, Azure, Alibaba, Proxmox, VMware, Nutanix, Cisco, SNMP, MQTT, eBPF)                  |
| 1.1.0   | 2024-12-27 | v1.39.0  | OTEL SDK standardization, aligned with TFO-Go-SDK & TFO-Collector                                                 |
| 1.0.1   | 2024-12-17 | -        | Docker workflow, SBOM, multi-platform support                                                                     |
| 1.0.0   | 2024-12-17 | -        | Initial release                                                                                                   |

## Upgrade Guide

### From Pre-release to 1.0.0

This is the initial stable release. No upgrade steps required.

### Future Upgrades

For future upgrades, check the changelog for breaking changes and follow the upgrade instructions provided.

## Support

- **Issues**: [GitHub Issues](https://github.com/telemetryflow/telemetryflow-platform/issues)
- **Documentation**: [TelemetryFlow Docs](https://docs.telemetryflow.id)
- **Email**: [support@telemetryflow.id](mailto:support@telemetryflow.id)
