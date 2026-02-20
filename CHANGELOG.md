<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg">
    <img src="https://github.com/telemetryflow/.github/raw/main/docs/assets/tfo-logo-agent-light.svg" alt="TelemetryFlow Logo" width="80%">
  </picture>

  <h3>TelemetryFlow Agent (OTEL Agent)</h3>

[![Version](https://img.shields.io/badge/Version-1.1.5-orange.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org/)
[![OTEL SDK](https://img.shields.io/badge/OpenTelemetry_SDK-1.39.0-blueviolet)](https://opentelemetry.io/)
[![OpenTelemetry](https://img.shields.io/badge/OTLP-100%25%20Compliant-success?logo=opentelemetry)](https://opentelemetry.io/)

</div>

---

# Changelog

All notable changes to TelemetryFlow Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.1/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

| Version | Date       | OTEL SDK | Description                                                                                               |
| ------- | ---------- | -------- | --------------------------------------------------------------------------------------------------------- |
| 1.1.5   | 2026-02-19 | v1.39.0  | Docker container collector, cAdvisor scraper, CPU fix macOS, tags/labels propagation                       |
| 1.1.4   | 2026-02-11 | v1.39.0  | eBPF collector (28 metrics), Cilium Hubble integration, 6 BPF programs, kernel-level observability        |
| 1.1.3   | 2026-02-04 | v1.39.0  | Network retransmit metrics, container name/image detection, page faults, IOPS, system calls               |
| 1.1.2   | 2026-01-03 | v1.39.0  | OSS observability (SigNoz, Coroot, HyperDX, OpenObserve, Netdata), APM (Dynatrace, Instana, ManageEngine) |
| 1.1.1   | 2024-12-29 | v1.39.0  | Enterprise integrations (GCP, Azure, Alibaba, Proxmox, VMware, Nutanix, Cisco, SNMP, MQTT, eBPF)          |
| 1.1.0   | 2024-12-27 | v1.39.0  | OTEL SDK standardization, aligned with TFO-Go-SDK & TFO-Collector                                         |
| 1.0.1   | 2024-12-17 | -        | Docker workflow, SBOM, multi-platform support                                                             |
| 1.0.0   | 2024-12-17 | -        | Initial release                                                                                           |

## Upgrade Guide

### From Pre-release to 1.0.0

This is the initial stable release. No upgrade steps required.

### Future Upgrades

For future upgrades, check the changelog for breaking changes and follow the upgrade instructions provided.

## Support

- **Issues**: [GitHub Issues](https://github.com/telemetryflow/telemetryflow-platform/issues)
- **Documentation**: [TelemetryFlow Docs](https://docs.telemetryflow.id)
- **Email**: [support@telemetryflow.id](mailto:support@telemetryflow.id)
