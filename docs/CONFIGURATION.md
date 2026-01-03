# TelemetryFlow Agent Configuration Reference

- **Version:** 1.1.2
- **OTEL SDK Version:** 1.39.0
- **Last Updated:** January 2026

---

## Overview

TelemetryFlow Agent uses a custom YAML configuration format with `enabled` flags for easy feature toggling. Built on the standard OpenTelemetry Go SDK v1.39.0, the agent maintains TelemetryFlow identity and branding while leveraging OTEL SDK capabilities for telemetry collection and export.

Starting with v1.1.2, the agent introduces a new `telemetryflow` configuration section that aligns with TFO-Collector for unified platform configuration.

---

## Configuration File Locations

The agent searches for configuration in the following order:

1. Path specified via `--config` flag
2. `./configs/tfo-agent.yaml` (current directory)
3. `~/.tfo-agent/tfo-agent.yaml` (user home)
4. `/etc/tfo-agent/tfo-agent.yaml` (system)

---

## TelemetryFlow Platform Configuration (v1.1.2+)

The new `telemetryflow` section provides unified configuration for connecting to the TelemetryFlow platform:

```yaml
# TelemetryFlow Platform Connection
telemetryflow:
  # API credentials (supports environment variable substitution)
  api_key_id: "${TELEMETRYFLOW_API_KEY_ID}"
  api_key_secret: "${TELEMETRYFLOW_API_KEY_SECRET}"

  # OTLP endpoint (default: localhost:4317)
  endpoint: "${TELEMETRYFLOW_ENDPOINT:-localhost:4317}"

  # Protocol: grpc or http
  protocol: grpc

  # Connection timeout
  timeout: 30s

  # TLS configuration
  tls:
    enabled: true
    skip_verify: false
    cert_file: ""
    key_file: ""
    ca_file: ""

  # Retry configuration
  retry:
    enabled: true
    max_attempts: 3
    initial_interval: 1s
    max_interval: 30s
```

### Authentication Headers

When connecting to TFO-Collector, the agent automatically sends these headers:

| Header | Description |
|--------|-------------|
| `X-TelemetryFlow-Key-ID` | API key ID (tfk_xxx) |
| `X-TelemetryFlow-Key-Secret` | API key secret (tfs_xxx) |
| `X-TelemetryFlow-Agent-ID` | Unique agent identifier |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEMETRYFLOW_API_KEY_ID` | API key ID | - |
| `TELEMETRYFLOW_API_KEY_SECRET` | API key secret | - |
| `TELEMETRYFLOW_ENDPOINT` | OTLP endpoint | `localhost:4317` |
| `TELEMETRYFLOW_ENVIRONMENT` | Deployment environment | `production` |
| `TELEMETRYFLOW_AGENT_ID` | Agent identifier | Auto-generated UUID |
| `TELEMETRYFLOW_AGENT_NAME` | Agent display name | `TelemetryFlow Agent` |

---

## Complete Configuration Reference

```yaml
# =============================================================================
# TelemetryFlow Agent Configuration
# =============================================================================
# Version: 1.1.2
# Format: Custom YAML (not standard OTEL format)
# =============================================================================

# -----------------------------------------------------------------------------
# TelemetryFlow Platform (v1.1.2+)
# -----------------------------------------------------------------------------
telemetryflow:
  api_key_id: "${TELEMETRYFLOW_API_KEY_ID}"
  api_key_secret: "${TELEMETRYFLOW_API_KEY_SECRET}"
  endpoint: "${TELEMETRYFLOW_ENDPOINT:-localhost:4317}"
  protocol: grpc
  timeout: 30s
  tls:
    enabled: true
    skip_verify: false
  retry:
    enabled: true
    max_attempts: 3
    initial_interval: 1s
    max_interval: 30s

# -----------------------------------------------------------------------------
# Agent Identification
# -----------------------------------------------------------------------------
agent:
  # Unique agent identifier (auto-generated UUID if empty)
  id: ""

  # Agent hostname (auto-detected from OS if empty)
  hostname: ""

  # Human-readable description
  description: "TelemetryFlow Agent"

  # Custom tags for labeling and filtering
  tags:
    environment: "production"
    datacenter: "dc1"
    team: "platform"

# -----------------------------------------------------------------------------
# Collectors Configuration
# -----------------------------------------------------------------------------
collectors:
  # System Metrics Collector
  metrics:
    enabled: true
    # Collection interval
    interval: 60s
    # Specific collectors to enable
    cpu:
      enabled: true
      per_cpu: true  # Per-core metrics
    memory:
      enabled: true
    disk:
      enabled: true
      mount_points:
        - /
        - /data
      exclude_mount_points:
        - /dev
        - /proc
        - /sys
    network:
      enabled: true
      interfaces:
        - eth0
        - ens*
      exclude_interfaces:
        - lo
        - docker*
    process:
      enabled: false  # High cardinality, enable carefully
      names:
        - nginx
        - postgres

  # Log Collector
  logs:
    enabled: true
    # Files to tail
    paths:
      - /var/log/*.log
      - /var/log/app/*.log
    # Files to exclude
    exclude_paths:
      - /var/log/*.gz
      - /var/log/*debug*.log
    # Start position: "beginning" or "end"
    start_at: "end"
    # Multi-line configuration
    multiline:
      enabled: false
      pattern: '^\d{4}-\d{2}-\d{2}'
      negate: false
      match: after
    # Parsing configuration
    parsing:
      # Auto-detect JSON logs
      json_auto_detect: true
      # Timestamp parsing
      timestamp:
        enabled: true
        layout: "2006-01-02T15:04:05.000Z"
        location: "UTC"

  # Trace Collector (OTLP Receiver)
  traces:
    enabled: true

# -----------------------------------------------------------------------------
# Receivers Configuration
# -----------------------------------------------------------------------------
receivers:
  # OTLP Receiver
  otlp:
    enabled: true
    protocols:
      grpc:
        enabled: true
        endpoint: "0.0.0.0:4317"
        max_recv_msg_size_mib: 4
        max_concurrent_streams: 100
        # TLS configuration
        tls:
          enabled: false
          cert_file: ""
          key_file: ""
          ca_file: ""
        # Keepalive settings
        keepalive:
          server_parameters:
            max_connection_idle: 15s
            max_connection_age: 30s
            time: 10s
            timeout: 5s

      http:
        enabled: true
        endpoint: "0.0.0.0:4318"
        max_request_body_size: 10485760  # 10MB
        # TLS configuration
        tls:
          enabled: false
          cert_file: ""
          key_file: ""
        # CORS settings
        cors:
          allowed_origins:
            - "*"
          allowed_headers:
            - "*"
          max_age: 7200

  # Prometheus Scraper (optional)
  prometheus:
    enabled: false
    scrape_configs:
      - job_name: "node-exporter"
        scrape_interval: 15s
        scrape_timeout: 10s
        metrics_path: "/metrics"
        static_configs:
          - targets:
              - "localhost:9100"
            labels:
              env: "production"

# -----------------------------------------------------------------------------
# Processors Configuration
# -----------------------------------------------------------------------------
processors:
  # Batch Processor
  batch:
    enabled: true
    # Target batch size
    send_batch_size: 8192
    # Maximum batch size (0 = no limit)
    send_batch_max_size: 0
    # Maximum time to wait before sending
    timeout: 200ms

  # Memory Limiter
  memory_limiter:
    enabled: true
    # How often to check memory usage
    check_interval: 1s
    # Hard limit in MiB (0 = use percentage)
    limit_mib: 0
    # Spike limit in MiB
    spike_limit_mib: 0
    # Limit as percentage of total memory
    limit_percentage: 80
    # Spike limit as percentage
    spike_limit_percentage: 25

  # Attributes Processor
  attributes:
    enabled: false
    actions:
      - key: "environment"
        action: "insert"
        value: "production"
      - key: "agent.id"
        action: "upsert"
        value: "${AGENT_ID}"

  # Resource Detection
  resource_detection:
    enabled: true
    detectors:
      - env
      - system
      - docker

# -----------------------------------------------------------------------------
# Exporter Configuration
# -----------------------------------------------------------------------------
exporter:
  # OTLP Exporter (to Collector or Backend)
  otlp:
    enabled: true
    # Collector endpoint
    endpoint: "http://tfo-collector:4317"
    # Use gRPC or HTTP (grpc, http)
    protocol: "grpc"
    # Compression (none, gzip, zstd)
    compression: "gzip"
    # Request timeout
    timeout: 30s
    # TLS configuration
    tls:
      enabled: false
      cert_file: ""
      key_file: ""
      ca_file: ""
      insecure_skip_verify: false
    # Custom headers
    headers:
      X-API-Key: ""
      X-Tenant-Id: ""
    # Retry configuration
    retry:
      enabled: true
      initial_interval: 5s
      max_interval: 30s
      max_elapsed_time: 300s
    # Sending queue
    queue:
      enabled: true
      num_consumers: 10
      queue_size: 1000

  # Prometheus Exporter (for self metrics)
  prometheus:
    enabled: false
    endpoint: "0.0.0.0:8888"
    namespace: "tfo_agent"

# -----------------------------------------------------------------------------
# Buffer Configuration
# -----------------------------------------------------------------------------
buffer:
  # Enable disk-based buffering
  enabled: true
  # Buffer directory path
  path: "/var/lib/tfo-agent/buffer"
  # Maximum buffer size in MB
  max_size_mb: 100
  # Flush interval
  flush_interval: 5s
  # Compression for buffered data
  compression: "gzip"

# -----------------------------------------------------------------------------
# Extensions Configuration
# -----------------------------------------------------------------------------
extensions:
  # Health Check
  health_check:
    enabled: true
    endpoint: "0.0.0.0:13133"
    path: "/"

  # zPages (debugging)
  zpages:
    enabled: false
    endpoint: "0.0.0.0:55679"

  # pprof (profiling)
  pprof:
    enabled: false
    endpoint: "0.0.0.0:1777"

# -----------------------------------------------------------------------------
# Heartbeat Configuration
# -----------------------------------------------------------------------------
heartbeat:
  enabled: true
  # Heartbeat interval
  interval: 60s
  # Timeout for heartbeat requests
  timeout: 10s
  # Maximum retries
  max_retries: 3

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
logging:
  # Log level: debug, info, warn, error
  level: "info"
  # Log format: json, text
  format: "json"
  # Log file path (empty = stdout)
  file: ""
  # Log rotation settings
  max_size_mb: 100
  max_backups: 3
  max_age_days: 7
  # Development mode (more verbose)
  development: false
  # Log sampling (for high-volume production)
  sampling:
    enabled: true
    initial: 100
    thereafter: 100
```

---

## Configuration Sections

### Agent Section

Identifies the agent instance:

```yaml
agent:
  id: "prod-agent-001"           # Unique identifier
  hostname: "server-01"          # Hostname (auto-detected if empty)
  description: "Production"      # Human-readable description
  tags:                          # Custom labels
    environment: "production"
    datacenter: "us-east-1"
```

### Collectors Section

Configures what data to collect:

```yaml
collectors:
  metrics:
    enabled: true
    interval: 60s                # Collection interval
    cpu:
      enabled: true
      per_cpu: true              # Per-core metrics
    memory:
      enabled: true
    disk:
      enabled: true
      mount_points: ["/", "/data"]
    network:
      enabled: true
      interfaces: ["eth0"]
```

### Receivers Section

Configures OTLP receivers for external data:

```yaml
receivers:
  otlp:
    enabled: true
    protocols:
      grpc:
        enabled: true
        endpoint: "0.0.0.0:4317"
      http:
        enabled: true
        endpoint: "0.0.0.0:4318"
```

### Exporter Section

Configures where to send data:

```yaml
exporter:
  otlp:
    enabled: true
    endpoint: "http://tfo-collector:4317"
    compression: "gzip"
    retry:
      enabled: true
      initial_interval: 5s
```

### Buffer Section

Configures disk-based buffering for resilience:

```yaml
buffer:
  enabled: true
  path: "/var/lib/tfo-agent/buffer"
  max_size_mb: 100
  flush_interval: 5s
```

---

## Environment Variable Substitution

Configuration values can reference environment variables:

```yaml
exporter:
  otlp:
    endpoint: "${COLLECTOR_ENDPOINT:-http://localhost:4317}"
    headers:
      X-API-Key: "${API_KEY}"
```

**Syntax:**
- `${VAR}` - Required variable (error if not set)
- `${VAR:-default}` - Variable with default value
- `${VAR:?error message}` - Required with custom error

---

## Configuration Profiles

### Minimal Configuration

```yaml
agent:
  description: "Minimal Agent"

collectors:
  metrics:
    enabled: true
    interval: 60s

exporter:
  otlp:
    enabled: true
    endpoint: "http://tfo-collector:4317"
```

### Production Configuration

```yaml
agent:
  id: ""
  hostname: ""
  description: "Production Agent"
  tags:
    environment: "production"

collectors:
  metrics:
    enabled: true
    interval: 30s
  logs:
    enabled: true
    paths:
      - /var/log/app/*.log
  traces:
    enabled: true

receivers:
  otlp:
    enabled: true
    protocols:
      grpc:
        enabled: true
        endpoint: "0.0.0.0:4317"
      http:
        enabled: true
        endpoint: "0.0.0.0:4318"

processors:
  batch:
    enabled: true
    send_batch_size: 8192
    timeout: 200ms
  memory_limiter:
    enabled: true
    limit_percentage: 80

exporter:
  otlp:
    enabled: true
    endpoint: "http://tfo-collector:4317"
    compression: "gzip"
    retry:
      enabled: true
    queue:
      enabled: true
      queue_size: 5000

buffer:
  enabled: true
  path: "/var/lib/tfo-agent/buffer"
  max_size_mb: 500

logging:
  level: "info"
  format: "json"
```

### High-Security Configuration

```yaml
agent:
  id: "secure-agent-001"

receivers:
  otlp:
    protocols:
      grpc:
        enabled: true
        endpoint: "0.0.0.0:4317"
        tls:
          enabled: true
          cert_file: "/etc/tfo-agent/certs/agent.crt"
          key_file: "/etc/tfo-agent/certs/agent.key"
          ca_file: "/etc/tfo-agent/certs/ca.crt"
      http:
        enabled: false  # Disable HTTP, use gRPC only

exporter:
  otlp:
    enabled: true
    endpoint: "https://tfo-collector:4317"
    tls:
      enabled: true
      cert_file: "/etc/tfo-agent/certs/agent.crt"
      key_file: "/etc/tfo-agent/certs/agent.key"
      ca_file: "/etc/tfo-agent/certs/ca.crt"
```

---

## Configuration Validation

### Validate Command

```bash
# Validate configuration file
./build/tfo-agent config --config configs/tfo-agent.yaml

# Output shows parsed configuration
```

### Common Validation Errors

**Missing Required Field:**
```
Error: exporter.otlp.endpoint is required when enabled=true
```

**Invalid Value:**
```
Error: logging.level must be one of: debug, info, warn, error
```

**Invalid Duration:**
```
Error: collectors.metrics.interval: invalid duration "60"
```

---

## Dynamic Configuration (Hot Reload)

The agent supports configuration hot-reload via SIGHUP:

```bash
# Edit configuration
vim /etc/tfo-agent/tfo-agent.yaml

# Reload configuration
kill -HUP $(pgrep tfo-agent)

# Or via systemctl
sudo systemctl reload tfo-agent
```

**Note:** Some changes require restart:
- Receiver endpoints
- TLS certificates
- Buffer path

---

## Configuration Best Practices

### 1. Use Environment Variables for Secrets

```yaml
exporter:
  otlp:
    headers:
      X-API-Key: "${TFO_API_KEY}"  # Not hardcoded
```

### 2. Enable Memory Limiter

```yaml
processors:
  memory_limiter:
    enabled: true
    limit_percentage: 80
```

### 3. Configure Buffering for Resilience

```yaml
buffer:
  enabled: true
  max_size_mb: 100
```

### 4. Use Appropriate Batch Sizes

```yaml
processors:
  batch:
    send_batch_size: 8192    # Default, good for most cases
    timeout: 200ms
```

### 5. Enable Compression

```yaml
exporter:
  otlp:
    compression: "gzip"      # Reduces bandwidth ~70%
```

---

**Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.**
