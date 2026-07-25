# TelemetryFlow Agent Configuration Reference

- **Version:** 1.3.0-dev
- **OTEL SDK Version:** 1.47.0
- **Last Updated:** July 2026

---

## Overview

TelemetryFlow Agent uses a custom YAML configuration format with `enabled` flags for easy feature toggling. Built on the standard OpenTelemetry Go SDK v1.40.0, the agent maintains TelemetryFlow identity and branding while leveraging OTEL SDK capabilities for telemetry collection and export.

Starting with v1.2.1, the agent introduces a new `telemetryflow` configuration section that aligns with TFO-Collector for unified platform configuration.

---

## Configuration File Locations

The agent searches for configuration in the following order:

1. Path specified via `--config` flag
2. `./configs/tfo-agent.yaml` (current directory)
3. `~/.tfo-agent/tfo-agent.yaml` (user home)
4. `/etc/tfo-agent/tfo-agent.yaml` (system)

---

## TelemetryFlow Platform Configuration (v1.2.1+)

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

| Header                       | Description              |
| ---------------------------- | ------------------------ |
| `X-TelemetryFlow-Key-ID`     | API key ID (tfk_xxx)     |
| `X-TelemetryFlow-Key-Secret` | API key secret (tfs_xxx) |
| `X-TelemetryFlow-Agent-ID`   | Unique agent identifier  |

### Environment Variables

| Variable                       | Description            | Default               |
| ------------------------------ | ---------------------- | --------------------- |
| `TELEMETRYFLOW_API_KEY_ID`     | API key ID             | -                     |
| `TELEMETRYFLOW_API_KEY_SECRET` | API key secret         | -                     |
| `TELEMETRYFLOW_ENDPOINT`       | OTLP endpoint          | `localhost:4317`      |
| `TELEMETRYFLOW_ENVIRONMENT`    | Deployment environment | `production`          |
| `TELEMETRYFLOW_AGENT_ID`       | Agent identifier       | Auto-generated UUID   |
| `TELEMETRYFLOW_AGENT_NAME`     | Agent display name     | `TelemetryFlow Agent` |

---

## Complete Configuration Reference

```yaml
# =============================================================================
# TelemetryFlow Agent Configuration
# =============================================================================
# Version: 1.3.0-dev
# Format: Custom YAML (not standard OTEL format)
# =============================================================================

# -----------------------------------------------------------------------------
# TelemetryFlow Platform (v1.2.1+)
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
      per_cpu: true # Per-core metrics
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
      enabled: false # High cardinality, enable carefully
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
        max_request_body_size: 10485760 # 10MB
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
    # NOTE: TLS for OTLP export is controlled by the top-level telemetryflow.tls
    # block (telemetryflow.tls.skip_verify / cert_file / key_file / ca_file).
    # The OTLP exporter has no separate tls block of its own.
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
  id: "prod-agent-001" # Unique identifier
  hostname: "server-01" # Hostname (auto-detected if empty)
  description: "Production" # Human-readable description
  tags: # Custom labels
    environment: "production"
    datacenter: "us-east-1"
```

### Collectors Section

Configures what data to collect:

```yaml
collectors:
  metrics:
    enabled: true
    interval: 60s # Collection interval
    cpu:
      enabled: true
      per_cpu: true # Per-core metrics
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

## Foundation Configuration (1.3.0+)

The 1.3.0 release adds the M1 foundation layer: a typed plugin system, a
channel-based processor pipeline, disk-backed retry buffer wiring, plugin
state persistence, secret resolution, and a versioned config migration
framework. All of these are opt-in — a 1.2.x config continues to work
unchanged. See `docs/ARCHITECTURE.md` for the full plugin/pipeline design.

### Buffer (disk-backed retry)

Sits between `MetricForwarder` and the OTLP sink. When the backend is
unreachable, metrics are spilled to disk and replayed on recovery instead of
being dropped. Opt-in via `buffer.enabled: true`.

```yaml
buffer:
  enabled: true
  path: /var/lib/tfo-agent/buffer
  max_size_mb: 100        # maximum on-disk buffer size
  max_age: 24h            # entries older than this are pruned
  flush_interval: 5s      # drain cadence to the downstream sink
```

| Field            | Type         | Default                          | Description                                         |
| ---------------- | ------------ | -------------------------------- | --------------------------------------------------- |
| `enabled`        | bool         | `false`                          | Gates buffer wiring. No-op when false.              |
| `path`           | string       | `/var/lib/tfo-agent/buffer`      | Buffer directory. Created if missing.               |
| `max_size_mb`    | int          | `100`                            | Maximum total buffered size in megabytes.           |
| `max_age`        | duration     | `24h`                            | Maximum age of a buffered entry before pruning.     |
| `flush_interval` | duration     | `5s`                             | How often the buffer drains into the OTLP sink.     |

### Persister (plugin state persistence)

Atomic JSON state persistence for plugins that implement the
`StatefulPlugin` mixin. State is loaded before collectors start, saved at
shutdown, and periodically via `StartSaveLoop`. First consumer: M3 log tail
offsets. Opt-in via `persister.enabled: true`.

```yaml
persister:
  enabled: false
  statefile: /var/lib/tfo-agent/state.json
  save_interval: 5m
```

| Field           | Type     | Default                          | Description                                                       |
| ---------------- | -------- | -------------------------------- | ----------------------------------------------------------------- |
| `enabled`        | bool     | `false`                          | Gates persister wiring. When false the Persister is not created.  |
| `statefile`      | string   | `/var/lib/tfo-agent/state.json`  | JSON path used for atomic state writes.                           |
| `save_interval`  | duration | `5m`                             | Periodic save cadence in addition to the shutdown save.           |

### Secret Stores

The `@{store:key}` resolver lets the YAML reference secrets by logical name
without hardcoding them. Resolution order is `${VAR}` (env) → `@{store:key}`
(secret store). Three backends ship out of the box: `env`, `file`, `vault`.

```yaml
secret_stores:
  - type: env                # resolves keys from os.Getenv
  - type: file               # JSON map of {key: value}
    name: file
    path: /etc/tfo-agent/secrets.json
  - type: vault              # HashiCorp Vault KV-v2 over net/http (no SDK)
    name: vault
    address: https://vault.internal:8200
    token: ${VAULT_TOKEN}    # stores bootstrap their own config from env
    namespace: ""            # Vault Enterprise namespace (optional)
    mount_path: secret       # KV-v2 mount point

# Reference anywhere in the YAML:
telemetryflow:
  api_key_secret: "@{vault:tfo/api-key-secret}"
```

| Field                          | Applies to | Description                                                                    |
| ------------------------------ | ---------- | ------------------------------------------------------------------------------ |
| `type`                         | all        | Backend name: `env`, `file`, or `vault`. Must be registered via the plugin API.|
| `name`                         | all        | Identifier used in `@{name:key}` references. Must be unique per resolver.      |
| `path`                         | `file`     | Path to a JSON file mapping keys to string values.                             |
| `address`                      | `vault`    | Vault server URL (e.g. `https://vault.internal:8200`).                         |
| `token`                        | `vault`    | Vault auth token. `${VAULT_TOKEN}` is expanded before the store initialises.   |
| `namespace`                    | `vault`    | Vault Enterprise namespace (optional).                                         |
| `mount_path`                   | `vault`    | KV-v2 mount point (default `secret`).                                          |

### Pipeline (processor engine)

Channel-based DAG topology that wires `inputs → pre-aggregator processors →
aggregators → post-aggregator processors → outputs`. Mirrors the Telegraf
model. The pipeline is opt-in: the existing `metric_forwarder` path keeps
working for backwards compatibility, and an empty `pipeline:` block
reproduces 1.2.x behaviour exactly.

```yaml
pipeline:
  queue_size: 10000                 # per-stage channel capacity
  drop_policy: drop_newest          # block | drop_oldest | drop_newest
  aggregator_period: 30s            # aggregator Push/Reset window
  flush_interval: 5s                # output stage drain cadence

  processors:
    pre_aggregator:                 # run BEFORE aggregators
      - type: filter
        rules:
          - action: drop
            metric_name: "go_.*"    # drop agent self noise
      - type: starlark
        script: |
          def apply(metric):
              metric["labels"]["env"] = "prod"
              return metric

    post_aggregator: []             # run AFTER aggregators

  aggregators: []                   # windowed aggregator plugins
```

| Field                    | Type     | Default        | Description                                                              |
| ------------------------ | -------- | -------------- | ------------------------------------------------------------------------ |
| `queue_size`             | int      | `10000`        | Per-stage buffered channel capacity.                                     |
| `drop_policy`            | string   | `drop_newest`  | `block` (back-pressure), `drop_oldest`, or `drop_newest`.                |
| `aggregator_period`      | duration | `30s`          | Window duration for aggregator `Push`/`Reset` calls.                     |
| `flush_interval`         | duration | `5s`           | How often the output stage drains to the configured outputs.             |
| `processors.pre_aggregator`  | list | `[]`           | Streaming processors applied before aggregators (see Processors below).  |
| `processors.post_aggregator` | list | `[]`           | Streaming processors applied after aggregators.                          |
| `aggregators`            | list     | `[]`           | Aggregator plugin declarations.                                          |

Pre/post processor entries share the same `{type: <name>, ...config}` shape as
the standalone processors documented in **Log Processors (1.3.0+)** below.

### Config Migrations

Versioned schema upgrades run automatically on every config load. The loader
runs a three-stage preprocess pipeline — `ApplyLatest → os.ExpandEnv →
secret.Resolver` — so older YAML keeps working without manual edits.

Currently registered migrations:

| From → To       | Name                    | Description                                                       |
| --------------- | ----------------------- | ----------------------------------------------------------------- |
| `1.2.0 → 1.3.0` | `tls_skip_verify_rename`| Rewrites `insecure_skip_verify:` to the unified `tls_skip_verify:`|

Migrations log the version they upgraded from/to at agent startup. Disable the
whole chain by passing `--no-migration` on the CLI (or wiring
`WithMigrationEnabled(false)` programmatically).

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
        enabled: false # Disable HTTP, use gRPC only

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

## MongoDB Community Collector

The MongoDB Community collector monitors standalone, replica set, and sharded MongoDB Community Edition deployments.

### Configuration

```yaml
mongodb_community:
  enabled: true

  # Collection intervals
  interval: 10s # serverStatus metrics (default: 10s)
  current_op_interval: 30s # currentOp sampling (default: 30s)
  profile_interval: 60s # slow query profiler (default: 60s)
  collstats_interval: 300s # collection/index stats (default: 300s)
  discover_databases: true # auto-discover non-system databases

  instances:
    - name: "mongo-rs-0"
      uri: "mongodb://mongo-0:27017"
      username: "${MONGO_USER}"
      password: "${MONGO_PASSWORD}"
      tags:
        env: "production"
        role: "primary"
```

### Collected Metrics

| Category         | Metrics                                                           | Interval |
| ---------------- | ----------------------------------------------------------------- | -------- |
| Connections      | current, available, total_created, active                         | 10s      |
| Opcounters       | insert, query, update, delete, getmore, command (+ repl variants) | 10s      |
| Memory           | resident_mb, virtual_mb, mapped_mb                                | 10s      |
| Documents        | inserted, updated, deleted, returned                              | 10s      |
| Cursors          | open.total, open.no_timeout, open.pinned, timed_out               | 10s      |
| Network          | bytes_in, bytes_out, requests                                     | 10s      |
| Asserts          | regular, warning, msg, user, rollovers                            | 10s      |
| Global Lock      | current_queue (total/readers/writers), active_clients             | 10s      |
| WiredTiger       | cache bytes, dirty, evictions, tickets, checkpoints               | 10s      |
| Replication      | member_state, member_health, lag_seconds, oplog window            | 10s      |
| Sharding         | total_shards, chunks_per_shard, balancer status                   | 10s      |
| Operations       | active, waiting_for_lock, running_longer thresholds               | 30s      |
| Query Profiler   | slow queries, fingerprint aggregation                             | 60s      |
| Collection Stats | document_count, size_bytes, index stats                           | 300s     |
| Database Stats   | document_count, data_size, storage_size, index_size               | 300s     |

### TLS Configuration

```yaml
mongodb_community:
  instances:
    - name: "secure-mongo"
      uri: "mongodb://mongo.prod:27017"
      username: "${MONGO_USER}"
      password: "${MONGO_PASSWORD}"
      tls_ca_file: "/etc/ssl/mongo-ca.pem"
      tls_cert_file: "/etc/ssl/mongo-client.pem"
      tls_key_file: "/etc/ssl/mongo-client.key"
      tls_skip_verify: false
```

### Alert Rules

The platform includes 8 pre-configured alert rules for MongoDB:

| Rule                         | Condition                     | Severity |
| ---------------------------- | ----------------------------- | -------- |
| Connection Pool Exhaustion   | connections.utilization > 90% | critical |
| Replication Lag Critical     | lag_seconds > 30              | critical |
| WiredTiger Cache Pressure    | cache.utilization > 95%       | warning  |
| WiredTiger Ticket Exhaustion | tickets.available < 5         | critical |
| Oplog Window Shrinking       | oplog.window_seconds < 3600   | warning  |
| High Cursor Count            | cursors.open > 1000           | warning  |
| Assert Rate Spike            | asserts.regular_rate > 10/min | warning  |
| Global Lock Queue            | current_queue.total > 50      | warning  |

---

## Network Monitoring Collectors (1.3.0+)

Eight new collectors land under `collectors:` in the M2 milestone. All default
to `enabled: false` and are opt-in. Detailed metric tables live next to each
implementation under `internal/collector/<name>/`.

### ping — ICMP probe

ICMP echo probe via `golang.org/x/net/icmp`. Supports privileged (raw socket,
root / `CAP_NET_RAW`) and unprivileged (UDP, Linux `net.ipv4.ping_group_range`)
modes with automatic fallback. Emits `rtt_min/avg/max/stddev_ms`,
`packets_sent/received`, `loss_percent`, `ttl`, and `state` per target. See
`internal/collector/ping/`.

```yaml
collectors:
  ping:
    enabled: true
    interval: 30s
    count: 5                  # echo requests per probe cycle
    timeout: 5s               # per-target probe timeout
    interval_between: 1s      # wait between successive packets
    privileged: false         # true = raw socket (root); false = unprivileged UDP
    targets:
      - host: 10.0.0.1
        name: core-router
      - host: 8.8.8.8
        name: dns-google
```

### dns — DNS query probe

DNS query probe via `github.com/miekg/dns`. Supports `A`, `AAAA`, `TXT`, `MX`,
`NS`, `CNAME`, and `PTR` records. Emits `query_time_ms`, `result_code`,
`records_returned`, and `state` per (server × query). See
`internal/collector/dns/`.

```yaml
collectors:
  dns:
    enabled: true
    interval: 30s
    port: 53
    timeout: 5s               # per query
    servers:
      - address: 10.0.0.10
        name: primary-dns
      - address: 1.1.1.1
        name: cloudflare
    queries:
      - domain: telemetryflow.id
        record_type: A
      - domain: example.com
        record_type: MX
```

### tcp_probe — TCP/UDP port probe

TCP/UDP port probe (stdlib only). Emits `connect_time_ms`,
`response_time_ms`, `state`, and `string_found` per target. Optional `send` /
`expect` fields turn the probe into a banner grab. See
`internal/collector/tcp_probe/`.

```yaml
collectors:
  tcp_probe:
    enabled: true
    interval: 30s
    targets:
      - host: db.internal
        port: 5432
        name: postgres
        protocol: tcp         # "tcp" (default) or "udp"
        timeout: 5s
        send: ""              # optional bytes sent after connect
        expect: ""            # optional substring expected in response
```

### http_probe — HTTP synthetic check

HTTP synthetic check (stdlib only). Emits `response_time_ms`, `status_code`,
`content_length`, `state`, `tls_days_remaining`, `tls_valid`, `redirect_count`,
and `string_found` per target. See `internal/collector/http_probe/`.

```yaml
collectors:
  http_probe:
    enabled: true
    interval: 60s
    targets:
      - url: https://api.telemetryflow.id/healthz
        name: api-health
        method: GET
        headers:
          User-Agent: tfo-agent/1.3
        body: ""
        expected_status: [200, 204]
        expected_body_regex: ""  # optional regex anchored on response body
        follow_redirects: true
        timeout: 10s
        tls_skip_verify: false
        username: ""             # basic auth (optional)
        password: ""
```

### snmp — SNMP v1/v2c/v3 polling

SNMP polling via `github.com/gosnmp/gosnmp`. Scalar `GET` + table `WALK` with
ASN.1 → gauge/counter conversion. Emits `network.snmp.<field_name>` per agent ×
field plus `state` per agent. See `internal/collector/snmp/`.

```yaml
collectors:
  snmp:
    enabled: true
    interval: 60s
    agents:
      - host: 10.0.0.1
        name: edge-switch
        community: public        # v1/v2c community string
        version: "2c"            # "1", "2c" (default), or "3"
        port: 161
        timeout: 10s
        retries: 3
        auth:                    # SNMPv3 only (Version == "3")
          username: ro-user
          auth_protocol: SHA     # MD5, SHA, SHA256, SHA512
          auth_password: "${SNMP_AUTH_PASS}"
          priv_protocol: AES     # DES, AES, AES256, AES192C, AES256C
          priv_password: "${SNMP_PRIV_PASS}"
          security_level: authPriv  # noAuthNoPriv | authNoPriv | authPriv
    fields:
      - name: sysDescr
        oid: 1.3.6.1.2.1.1.1.0
      - name: sysUpTime
        oid: 1.3.6.1.2.1.1.3.0
        unit: ticks
    tables:
      - name: ifTable
        oid: 1.3.6.1.2.1.2.2
        index_as_tag: true       # exposes the OID index as a tag value
```

### netflow — NetFlow v5/v9/IPFIX listener

NetFlow v5 listener (stdlib parser); v9/IPFIX do header-only inspection today
and emit aggregate counters only to avoid per-flow metric explosion. Emits
`packets_received_total`, `flows_received_total`, `bytes_received_total`,
`parse_errors_total`, and `packets_by_version` per cycle. See
`internal/collector/netflow/`.

```yaml
collectors:
  netflow:
    enabled: true
    address: 0.0.0.0
    port: 2055                   # IANA NetFlow
    protocol: udp                # udp (default); future: tcp, sctp
    workers: 4                   # background parser goroutines
    buffer_size: 65535           # UDP socket buffer bytes
    protocols: ["5", "9", "ipfix"]  # versions to accept
    flush_interval: 30s          # cadence for emitting aggregate counters
    tags:
      site: dc1
```

### syslog_listener — syslog receiver

Syslog receiver via `github.com/leodido/go-syslog/v4`. Supports RFC 3164 /
RFC 5424 / Cisco formats over UDP, TCP, and Unix sockets. Emits
`messages_received_total`, `parse_errors_total`, `bytes_received_total`,
`messages_by_severity`, and `messages_by_facility` per cycle. See
`internal/collector/syslog_listener/`.

```yaml
collectors:
  syslog_listener:
    enabled: true
    default_format: rfc3164      # rfc3164 (default) | rfc5424 | cisco
    timezone: UTC
    flush_interval: 30s
    listeners:
      - protocol: udp            # udp (default) | tcp | unix
        address: 0.0.0.0
        port: 514                # 514 UDP; 601 TCP per RFC 3195
      - protocol: tcp
        address: 0.0.0.0
        port: 601
        format: rfc5424          # override default_format per listener
```

### sflow — sFlow v5 listener

sFlow v5 listener (stdlib parser). Header + sample envelope decoding today;
detailed sample-body decoding is deferred. Emits `packets_received_total`,
`samples_received_total`, `bytes_received_total`, `parse_errors_total`, and
`samples_by_format` per cycle. See `internal/collector/sflow/`.

```yaml
collectors:
  sflow:
    enabled: true
    address: 0.0.0.0
    port: 6343                   # IANA sFlow
    protocol: udp
    workers: 4
    buffer_size: 65535
    flush_interval: 30s
    tags:
      site: dc1
```

---

## Log Processors (1.3.0+)

Five new streaming processors land under `internal/processor/` in the M3
milestone. They register with the plugin registry and are selected via the
`pipeline.processors.pre_aggregator` / `post_aggregator` lists documented
above. Each processor is a `{type: <name>, ...config}` entry.

### multiline — aggregate continuation lines

Aggregates continuation lines (stack traces, wrapped logs) into a single
metric. A header line starts a new record; subsequent continuation lines
within the same stream are appended to `Description` separated by `\n`.
Buffered records are flushed when the next header arrives or when no
continuation is received within `timeout`. See
`internal/processor/multiline/`.

```yaml
pipeline:
  processors:
    pre_aggregator:
      - type: multiline
        pattern: '^\d{4}-\d{2}-\d{2}'   # matches a NEW header line
        negate: false                   # true = match identifies a header,
                                        #       non-match = continuation
        timeout: 5s                     # flush idle buffer after this
        stream_key: container_id        # group lines per stream (empty = global)
```

### grok_parser — grok pattern parsing

Parses the log line in `metric.Description` using `%{PATTERN:name}` grok
syntax. A self-contained RE2 translator maps 18 common grok patterns
(`TIMESTAMP_ISO8601`, `LOGLEVEL`, `GREEDYDATA`, `IP`, etc.) to Go RE2 at
compile time — no external grok library required. Named captures become metric
labels. See `internal/processor/grok_parser/`.

```yaml
pipeline:
  processors:
    pre_aggregator:
      - type: grok_parser
        pattern: '%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}'
        named_only: true                # only emit named captures
        keep_original: false            # keep Description on match?
        metric_name_prefix: ""          # override output metric name
```

### json_parser — JSON line parsing

Parses `metric.Description` as a JSON object and promotes selected keys (or all
top-level keys when `tag_keys` is empty) to metric labels. Optionally overrides
`metric.Value` from a numeric JSON field. Invalid JSON passes through
unchanged. See `internal/processor/json_parser/`.

```yaml
pipeline:
  processors:
    pre_aggregator:
      - type: json_parser
        tag_keys:                        # empty = promote all top-level keys
          - user.id                      # dotted paths traverse nested objects
          - event.type
        value_key: duration_ms           # optional numeric override for metric.Value
```

### regex_parser — regex named captures

Parses `metric.Description` using a Go RE2 regex with named captures. Each
named capture becomes a new metric label. Non-matching metrics are forwarded
unchanged unless `drop_when_no_match` is true. See
`internal/processor/regex_parser/`.

```yaml
pipeline:
  processors:
    pre_aggregator:
      - type: regex_parser
        pattern: '^(?P<timestamp>\S+) (?P<level>\w+) (?P<message>.*)$'
        drop_when_no_match: false        # true = drop on no match
```

### tail_sampling — probabilistic + policy sampling

Applies probabilistic + policy-based sampling to high-volume metric streams.
Policies are evaluated in declaration order; the first matching policy
determines the fate of each metric (`always`, `probabilistic`, or `drop`).
Probabilistic sampling uses a deterministic FNV-1a hash of (name + sorted
labels) so the same series always yields the same decision. Metrics that
match no policy are forwarded unchanged. See
`internal/processor/tail_sampling/`.

```yaml
pipeline:
  processors:
    post_aggregator:
      - type: tail_sampling
        policies:
          - name: keep-errors
            type: always
            filter:
              metric_name: '.*\.error$'
          - name: sample-debug
            type: probabilistic
            sampling_percentage: 5.0     # 0.0 – 100.0
            filter:
              metric_name: 'debug\..*'
              label:
                key: env
                value_regex: '^(staging|dev)$'
          - name: drop-noise
            type: drop
            filter:
              metric_name: 'go_.*'
```

| Policy `type`     | Action on filter match                                          |
| ----------------- | --------------------------------------------------------------- |
| `always`          | Forward every matching metric.                                  |
| `probabilistic`   | Forward with probability `sampling_percentage / 100`.           |
| `drop`            | Drop every matching metric.                                     |

---

## Configuration Best Practices

### 1. Use Environment Variables for Secrets

```yaml
exporter:
  otlp:
    headers:
      X-API-Key: "${TFO_API_KEY}" # Not hardcoded
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
    send_batch_size: 8192 # Default, good for most cases
    timeout: 200ms
```

### 5. Enable Compression

```yaml
exporter:
  otlp:
    compression: "gzip" # Reduces bandwidth ~70%
```

---

**Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.**
