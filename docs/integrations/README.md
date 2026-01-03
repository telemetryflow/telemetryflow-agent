# TelemetryFlow Agent Integrations

[![Version](https://img.shields.io/badge/Version-1.1.2-orange.svg)](../../CHANGELOG.md)

This document provides an overview of all third-party integrations supported by the TelemetryFlow Agent.

## Integration Architecture

```mermaid
flowchart TB
    subgraph "TelemetryFlow Agent"
        IM[Integration Manager]

        subgraph "Cloud Providers"
            GCP[GCP Exporter]
            AZURE[Azure Exporter]
            ALIBABA[Alibaba Exporter]
        end

        subgraph "Infrastructure"
            PROXMOX[Proxmox Exporter]
            VMWARE[VMware Exporter]
            NUTANIX[Nutanix Exporter]
            AZUREARC[Azure Arc Exporter]
        end

        subgraph "Network & IoT"
            CISCO[Cisco Exporter]
            SNMP[SNMP Exporter]
            MQTT[MQTT Exporter]
        end

        subgraph "Kernel/System"
            EBPF[eBPF Exporter]
        end

        subgraph "APM Platforms"
            DD[Datadog]
            NR[New Relic]
            DT[Dynatrace]
            INST[IBM Instana]
        end

        subgraph "Observability Backends"
            PROM[Prometheus]
            SPLUNK[Splunk]
            ES[Elasticsearch]
            INFLUX[InfluxDB]
            KAFKA[Kafka]
            LOKI[Loki]
            JAEGER[Jaeger]
            ME[ManageEngine]
        end
    end

    IM --> GCP & AZURE & ALIBABA
    IM --> PROXMOX & VMWARE & NUTANIX & AZUREARC
    IM --> CISCO & SNMP & MQTT
    IM --> EBPF
    IM --> DD & NR & DT & INST
    IM --> PROM & SPLUNK & ES & INFLUX & KAFKA & LOKI & JAEGER & ME
```

## Integration Categories

| Category | Integrations | Description |
|----------|-------------|-------------|
| [Cloud Providers](CLOUD-PROVIDERS.md) | GCP, Azure, Alibaba | Major cloud platform integrations |
| [Infrastructure](INFRASTRUCTURE.md) | Proxmox, VMware, Nutanix, Azure Arc | Virtualization and hybrid cloud |
| [Network & IoT](NETWORK.md) | Cisco, SNMP, MQTT | Network devices and IoT messaging |
| [Kernel/System](KERNEL.md) | eBPF | Linux kernel-level observability |
| [Observability](OBSERVABILITY.md) | Prometheus, Datadog, Dynatrace, Instana, ManageEngine, Splunk, etc. | APM & monitoring backends |

## Data Flow

```mermaid
sequenceDiagram
    participant S as Data Source
    participant E as Exporter
    participant M as Manager
    participant B as Backend

    S->>E: Raw Data
    E->>E: Transform
    E->>E: Validate
    E->>M: Telemetry Data
    M->>M: Batch & Buffer
    M->>B: Export
    B-->>M: Ack/Error
    M-->>E: Result
```

## Integration Interface

All integrations implement the `Exporter` interface:

```go
type Exporter interface {
    Name() string
    Type() string
    IsEnabled() bool
    SupportedDataTypes() []DataType
    Init(ctx context.Context) error
    Validate() error
    Export(ctx context.Context, data *TelemetryData) (*ExportResult, error)
    ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error)
    ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error)
    ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error)
    Health(ctx context.Context) (*HealthStatus, error)
    Close(ctx context.Context) error
}
```

## Supported Data Types

```mermaid
graph LR
    subgraph "Telemetry Data Types"
        M[Metrics]
        L[Logs]
        T[Traces]
    end

    subgraph "Exporters"
        E1[Full Support<br/>Metrics + Logs + Traces]
        E2[Metrics Only]
        E3[Logs Only]
    end

    M --> E1 & E2
    L --> E1 & E3
    T --> E1
```

| Integration | Metrics | Logs | Traces |
|-------------|---------|------|--------|
| GCP | ✅ | ✅ | ✅ |
| Azure | ✅ | ✅ | ✅ |
| Alibaba | ✅ | ✅ | ✅ |
| Proxmox | ✅ | ❌ | ❌ |
| VMware | ✅ | ❌ | ❌ |
| Nutanix | ✅ | ❌ | ❌ |
| Azure Arc | ✅ | ❌ | ❌ |
| Cisco | ✅ | ❌ | ❌ |
| SNMP | ✅ | ❌ | ❌ |
| MQTT | ✅ | ✅ | ✅ |
| eBPF | ✅ | ❌ | ❌ |
| Dynatrace | ✅ | ✅ | ✅ |
| IBM Instana | ✅ | ✅ | ✅ |
| ManageEngine | ✅ | ✅ | ❌ |

## Configuration

All integrations are configured in the `integrations` section of `tfo-agent.yaml`:

```yaml
integrations:
  # Cloud Providers
  gcp:
    enabled: false
    project_id: "${GCP_PROJECT_ID}"

  azure:
    enabled: false
    subscription_id: "${AZURE_SUBSCRIPTION_ID}"

  # Infrastructure
  proxmox:
    enabled: false
    api_url: "https://proxmox:8006"

  vmware:
    enabled: false
    vcenter_url: "https://vcenter.example.com"

  # Network
  cisco:
    enabled: false
    api_type: dnac

  snmp:
    enabled: false
    version: v2c

  mqtt:
    enabled: false
    broker: "tcp://mqtt:1883"

  # System
  ebpf:
    enabled: false
```

## Health Monitoring

Each integration reports health status:

```mermaid
stateDiagram-v2
    [*] --> Disabled
    [*] --> Initializing
    Initializing --> Healthy: Init Success
    Initializing --> Unhealthy: Init Failed
    Healthy --> Unhealthy: Connection Lost
    Unhealthy --> Healthy: Reconnected
    Healthy --> [*]: Close
    Unhealthy --> [*]: Close
```

## Quick Links

- [Cloud Providers](CLOUD-PROVIDERS.md) - GCP, Azure, Alibaba Cloud
- [Infrastructure](INFRASTRUCTURE.md) - Proxmox, VMware, Nutanix, Azure Arc
- [Network & IoT](NETWORK.md) - Cisco, SNMP, MQTT
- [Kernel/System](KERNEL.md) - eBPF observability
- [Observability Backends](OBSERVABILITY.md) - Prometheus, Datadog, etc.

---

**Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.**
