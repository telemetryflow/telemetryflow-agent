# TelemetryFlow Agent CLI Commands

- **Version:** 1.3.1
- **Last Updated:** July 2026

---

## Overview

TelemetryFlow Agent provides a Cobra-based CLI with multiple commands for different operations. This document describes all available commands and their options.

> **1.3.1 note.** `config validate` and `config show` now run the
> migration framework on the raw config bytes and apply `${VAR}` env
> expansion plus `@{store:key}` secret resolution before parsing. The
> `plugins` and `test` commands listed in the roadmap below are planned for
> `1.4.0`.

---

## Global Flags

These flags are available for all commands:

```bash
--config string    Path to configuration file (default searches standard locations)
--log-level string Override log level (debug, info, warn, error)
-h, --help         Help for the command
```

---

## Commands Reference

### tfo-agent

The root command displays help and usage information.

```bash
./build/tfo-agent

# Output:
TelemetryFlow Agent - Enterprise Observability Platform

TelemetryFlow Agent is an enterprise-grade telemetry collection agent
that collects system metrics, logs, and traces and exports them to the
TelemetryFlow platform using OTLP protocol.

Features:
  • System metrics collection (CPU, memory, disk, network)
  • Log collection and forwarding
  • Heartbeat monitoring with auto-reconnection
  • Automatic retry and disk-backed buffering
  • Graceful shutdown with signal handling
  • Cross-platform support (Linux, macOS, Windows)

Usage:
  tfo-agent [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  config      Show parsed configuration
  help        Help about any command
  start       Start the TelemetryFlow Agent
  version     Show version information

Flags:
      --config string   Path to configuration file
  -h, --help            help for tfo-agent

Use "tfo-agent [command] --help" for more information about a command.
```

---

### tfo-agent start

Starts the TelemetryFlow Agent with the specified configuration.

```bash
./build/tfo-agent start --config configs/tfo-agent.yaml
```

**Options:**

```bash
--config string    Path to configuration file (required)
--log-level string Override log level from config
-h, --help         Help for start command
```

**Examples:**

```bash
# Start with default config location
./build/tfo-agent start

# Start with specific config file
./build/tfo-agent start --config /etc/tfo-agent/tfo-agent.yaml

# Start with debug logging
./build/tfo-agent start --config configs/tfo-agent.yaml --log-level debug
```

**Startup Output:**

```
    ___________    .__                        __
    \__    ___/___ |  |   ____   _____   _____/  |________ ___.__.
      |    |_/ __ \|  | _/ __ \ /     \_/ __ \   __\_  __ <   |  |
      |    |\  ___/|  |_\  ___/|  Y Y  \  ___/|  |  |  | \/\___  |
      |____| \___  >____/\___  >__|_|  /\___  >__|  |__|   / ____|
                 \/          \/      \/     \/             \/
                    ___________.__
                    \_   _____/|  |   ______  _  __
                     |    __)  |  |  /  _ \ \/ \/ /
                     |     \   |  |_(  <_> )     /
                     |___  /   |____/\____/ \/\_/
                         \/
                  _____                         __
                 /  _  \    ____   ____   _____/  |_
                /  /_\  \  / ___\_/ __ \ /    \   __\
               /    |    \/ /_/  >  ___/|   |  \  |
               \____|__  /\___  / \___  >___|  /__|
                       \//_____/      \/     \/

  ══════════════════════════════════════════════════════════════════════════════
    TelemetryFlow Agent v1.2.2
    AI-Powered Observability & Incident Response Management (IRM) Platform
  ══════════════════════════════════════════════════════════════════════════════
    Platform     darwin/arm64
    Go Version   go1.26.0
    Commit       abc1234
    Built        2026-06-19T10:00:00Z
  ──────────────────────────────────────────────────────────────────────────────
    Vendor       TelemetryFlow (https://telemetryflow.id)
    Developer    Telemetri Data Indonesia
    License      Apache-2.0
    Support      https://docs.telemetryflow.id
  ──────────────────────────────────────────────────────────────────────────────
    Copyright (c) 2024-2026 Telemetri Data Indonesia
  ══════════════════════════════════════════════════════════════════════════════

{"level":"info","ts":"2026-06-19T10:00:00Z","msg":"Starting TelemetryFlow Agent","version":"1.2.2"}
{"level":"info","ts":"2026-06-19T10:00:00Z","msg":"Configuration loaded","file":"configs/tfo-agent.yaml"}
{"level":"info","ts":"2026-06-19T10:00:00Z","msg":"Agent started","id":"agent-001","hostname":"server-01"}
```

**Signal Handling:**

The start command handles the following signals:

- `SIGINT` (Ctrl+C): Graceful shutdown
- `SIGTERM`: Graceful shutdown
- `SIGHUP`: Configuration reload

---

### tfo-agent version

Displays version and build information.

```bash
./build/tfo-agent version
```

**Options:**

```bash
--short      Show only version number
--json       Output in JSON format
-h, --help   Help for version command
```

**Examples:**

```bash
# Full version info
./build/tfo-agent version

# Short version only
./build/tfo-agent version --short
# Output: 1.2.2

# JSON format
./build/tfo-agent version --json
```

**Output (Default):**

```
TelemetryFlow Agent v1.2.2

  Build Information
  ─────────────────────────────────────────────
  Commit:      abc1234
  Branch:      main
  Built:       2026-06-19T10:00:00Z
  Go Version:  go1.22.0
  Platform:    darwin/arm64

  Product Information
  ─────────────────────────────────────────────
  Vendor:      TelemetryFlow
  Website:     https://telemetryflow.id
  Developer:   Telemetri Data Indonesia
  License:     Apache-2.0
  Support:     https://docs.telemetryflow.id

  Copyright (c) 2024-2026 Telemetri Data Indonesia
```

**Output (JSON):**

```json
{
  "product": "TelemetryFlow Agent",
  "description": "Enterprise telemetry collection agent",
  "version": "1.2.2",
  "git_commit": "abc1234",
  "git_branch": "main",
  "build_time": "2026-06-19T10:00:00Z",
  "go_version": "go1.22.0",
  "os": "darwin",
  "arch": "arm64",
  "vendor": "TelemetryFlow",
  "vendor_url": "https://telemetryflow.id",
  "developer": "Telemetri Data Indonesia",
  "license": "Apache-2.0",
  "support_url": "https://docs.telemetryflow.id"
}
```

---

### tfo-agent config

Configuration management parent command. Subcommands validate or render the
parsed configuration.

```bash
./build/tfo-agent config --config configs/tfo-agent.yaml <subcommand>
```

Both subcommands load the file through the same three-stage preprocess
pipeline used at agent startup:

1. `migration.ApplyLatest` — schema upgrades for older configs (e.g. the
   `insecure_skip_verify → tls_skip_verify` rename handled by
   `internal/migration/v1_3/`).
2. `os.ExpandEnv` — `${VAR}` substitution.
3. `secret.Resolver` — `@{store:key}` substitution (when a secret resolver
   is wired).

This means `config validate` is a true dry-run of agent startup: a config
that validates cleanly here will parse cleanly under `tfo-agent start`.

---

### tfo-agent config validate

Validates the configuration file. Runs the migration framework on the raw
config bytes, applies env expansion and secret resolution, then unmarshals
and runs `Config.Validate()`. Returns exit code 0 only when every stage
succeeds.

```bash
./build/tfo-agent config validate --config configs/tfo-agent.yaml
```

**Options:**

```bash
--config string    Path to configuration file (required)
--log-level string Override log level from config
-h, --help         Help for validate command
```

**Examples:**

```bash
# Validate default config location
./build/tfo-agent config validate

# Validate a specific file
./build/tfo-agent config validate --config /etc/tfo-agent/tfo-agent.yaml

# Use as a CI gate
./build/tfo-agent config validate --config configs/tfo-agent.yaml && echo "Config is valid"
```

**Output (success):**

```
Configuration is valid
  Endpoint:           localhost:4317
  Hostname:           server-01
  Heartbeat Interval: 60s
```

**Output (failure):** non-zero exit code, error message from the failing
preprocess stage or from `Config.Validate()`. Migration and
secret-resolution failures are logged at WARN level but do not abort the
load — the underlying parse error from Viper is surfaced instead because
it is more actionable.

---

### tfo-agent config show

Prints the parsed configuration. Applies the same migration →
`${VAR}` → `@{store:key}` preprocess pipeline as `config validate` and
`tfo-agent start`, then renders the resolved `Config` struct.

> **Secret redaction.** Values that arrived via `@{store:key}` are
> redacted in the rendered output so credentials are not leaked into
> terminal scrollback or CI logs. Use `--format json` for machine-readable
> output.

```bash
./build/tfo-agent config show --config configs/tfo-agent.yaml
```

**Options:**

```bash
--config string    Path to configuration file (required)
--format string    Output format: yaml, json (default: yaml)
--log-level string Override log level from config
-h, --help         Help for show command
```

**Examples:**

```bash
# Render config as YAML
./build/tfo-agent config show --config configs/tfo-agent.yaml

# Render config as JSON (pipe into jq for diffs)
./build/tfo-agent config show --config configs/tfo-agent.yaml --format json | jq .

# Verify secret resolution happened without leaking the secret value
./build/tfo-agent config show --config configs/tfo-agent.yaml --log-level debug
```

**Output:**

```
TelemetryFlow Agent Configuration
==================================

Agent:
  ID:       agent-001
  Hostname: server-01
  ...

Exporter:
  OTLP: enabled=true, endpoint=http://tfo-collector:4317, compression=gzip

Buffer:
  Enabled: true, max_size=100MB, path=/var/lib/tfo-agent/buffer

Logging:
  Level: info, Format: json
```

---

### tfo-agent completion

Generates shell completion scripts for bash, zsh, fish, or PowerShell.

```bash
./build/tfo-agent completion [bash|zsh|fish|powershell]
```

**Examples:**

```bash
# Bash completion
./build/tfo-agent completion bash > /etc/bash_completion.d/tfo-agent

# Zsh completion
./build/tfo-agent completion zsh > "${fpath[1]}/_tfo-agent"

# Fish completion
./build/tfo-agent completion fish > ~/.config/fish/completions/tfo-agent.fish

# PowerShell completion
./build/tfo-agent completion powershell > tfo-agent.ps1
```

**Bash Setup:**

```bash
# Add to ~/.bashrc
source <(tfo-agent completion bash)

# Or install system-wide
sudo tfo-agent completion bash > /etc/bash_completion.d/tfo-agent
```

**Zsh Setup:**

```bash
# Add to ~/.zshrc
source <(tfo-agent completion zsh)

# Or add to fpath
echo "autoload -U compinit; compinit" >> ~/.zshrc
```

---

### tfo-agent help

Shows help for any command.

```bash
./build/tfo-agent help [command]
```

**Examples:**

```bash
# General help
./build/tfo-agent help

# Help for start command
./build/tfo-agent help start

# Alternative syntax
./build/tfo-agent start --help
```

---

## Roadmap Commands (1.4.0)

The following commands are planned for the `1.4.0` release and are tracked
in the master roadmap at
`telemetryflow-platform-monolith/docs/tfo-agent-roadmap/`. They are built on
top of the `1.3.0` plugin registry (`internal/plugin/registry.go`) and are
documented here so operators can plan automation around the expected CLI
surface. Flag names are provisional.

### tfo-agent plugins list

Lists every collector, processor, aggregator, output, parser, serializer,
and secret store registered against the in-process plugin registry. Backed
by `plugin.AllNames()` plus the per-type `*Names()` helpers.

```bash
./build/tfo-agent plugins list [--type collector|processor|aggregator|output|parser|serializer|secretstore]
```

**Planned output:**

```
TYPE        NAME                 DESCRIPTION                                   DEPRECATED
collector   system              Lightweight host metrics + SystemInfo
collector   ping                ICMP probe (rtt, loss, ttl)
collector   snmp                SNMP v1/v2c/v3 polling
processor   filter              Rule-based keep/drop by name regex + labels
processor   starlark            Embedded Starlark escape hatch
output      otlp_http          OTLP/HTTP metric sink
output      prometheus_writer   Remote-write compatible sink
...
```

### tfo-agent plugins usage \<name\>

Prints the sample configuration block for a registered plugin, sourced
from the `Info.SampleConfig` string returned by the plugin's
`PluginDescriber` implementation.

```bash
./build/tfo-agent plugins usage ping
```

**Planned output:**

```yaml
# ping — ICMP probe (rtt, loss, ttl)
[[collectors.ping]]
  targets = ["8.8.8.8", "1.1.1.1"]
  interval = "30s"
  count = 3
  timeout = "1s"
  privileged = false
```

### tfo-agent test \<collector\>

Runs a single gather cycle for the named collector and prints the emitted
metrics to stdout. Equivalent to Telegraf `--test --input-filter`. Useful
for validating collector configuration without waiting for the full agent
flush interval.

```bash
./build/tfo-agent test ping --config configs/tfo-agent.yaml
```

**Planned output:**

```
> ping,host=server-01,target=8.8.8.8 rtt_avg_ms=12.4,rtt_min_ms=11.9,rtt_max_ms=13.1,loss_percent=0,state=up 1780000000000000000
> ping,host=server-01,target=1.1.1.1 rtt_avg_ms=14.8,rtt_min_ms=14.2,rtt_max_ms=15.3,loss_percent=0,state=up 1780000000000000000
```

---

## Exit Codes

| Code | Description          |
| ---- | -------------------- |
| 0    | Success              |
| 1    | General error        |
| 2    | Configuration error  |
| 3    | Connection error     |
| 130  | Interrupted (SIGINT) |
| 143  | Terminated (SIGTERM) |

---

## Usage Patterns

### Development

```bash
# Build and run with development config
make dev

# Or manually
go run ./cmd/tfo-agent start --config configs/tfo-agent.yaml --log-level debug
```

### Production

```bash
# Start as foreground process
/usr/local/bin/tfo-agent start --config /etc/tfo-agent/tfo-agent.yaml

# Start via systemd
sudo systemctl start tfo-agent
```

### Docker

```bash
# Run in container
docker run -d telemetryflow/telemetryflow-agent:latest \
  start --config /etc/tfo-agent/config.yaml
```

### Kubernetes

```yaml
containers:
  - name: tfo-agent
    image: telemetryflow/telemetryflow-agent:latest
    args:
      - "start"
      - "--config"
      - "/etc/tfo-agent/config.yaml"
```

---

## Common Tasks

### Validate Configuration

```bash
./build/tfo-agent config validate --config configs/tfo-agent.yaml
echo $?  # 0 if valid
```

### Render Resolved Configuration

```bash
# Applies migration → ${VAR} → @{store:key} and redacts secrets in output
./build/tfo-agent config show --config configs/tfo-agent.yaml
```

### Check Version

```bash
./build/tfo-agent version --short
```

### Generate Completion

```bash
./build/tfo-agent completion bash > ~/.bash_completion.d/tfo-agent
source ~/.bash_completion.d/tfo-agent
```

### Debug Startup Issues

```bash
./build/tfo-agent start --config configs/tfo-agent.yaml --log-level debug 2>&1 | tee agent.log
```

---

**Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.**
