# TelemetryFlow Agent CLI Commands

- **Version:** 1.1.2
- **Last Updated:** January 2026

---

## Overview

TelemetryFlow Agent provides a Cobra-based CLI with multiple commands for different operations. This document describes all available commands and their options.

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
    TelemetryFlow Agent v1.1.2
    Community Enterprise Observability Platform (CEOP)
  ══════════════════════════════════════════════════════════════════════════════
    Platform     darwin/arm64
    Go Version   go1.22.0
    Commit       abc1234
    Built        2025-12-17T10:00:00Z
  ──────────────────────────────────────────────────────────────────────────────
    Vendor       TelemetryFlow (https://telemetryflow.id)
    Developer    DevOpsCorner Indonesia
    License      Apache-2.0
    Support      https://docs.telemetryflow.id
  ──────────────────────────────────────────────────────────────────────────────
    Copyright (c) 2024-2026 DevOpsCorner Indonesia
  ══════════════════════════════════════════════════════════════════════════════

{"level":"info","ts":"2025-12-17T10:00:00Z","msg":"Starting TelemetryFlow Agent","version":"1.1.2"}
{"level":"info","ts":"2025-12-17T10:00:00Z","msg":"Configuration loaded","file":"configs/tfo-agent.yaml"}
{"level":"info","ts":"2025-12-17T10:00:00Z","msg":"Agent started","id":"agent-001","hostname":"server-01"}
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
# Output: 1.1.2

# JSON format
./build/tfo-agent version --json
```

**Output (Default):**

```
TelemetryFlow Agent v1.1.2

  Build Information
  ─────────────────────────────────────────────
  Commit:      abc1234
  Branch:      main
  Built:       2025-12-17T10:00:00Z
  Go Version:  go1.22.0
  Platform:    darwin/arm64

  Product Information
  ─────────────────────────────────────────────
  Vendor:      TelemetryFlow
  Website:     https://telemetryflow.id
  Developer:   DevOpsCorner Indonesia
  License:     Apache-2.0
  Support:     https://docs.telemetryflow.id

  Copyright (c) 2024-2026 DevOpsCorner Indonesia
```

**Output (JSON):**

```json
{
  "product": "TelemetryFlow Agent",
  "description": "Enterprise telemetry collection agent",
  "version": "1.1.2",
  "git_commit": "abc1234",
  "git_branch": "main",
  "build_time": "2025-12-17T10:00:00Z",
  "go_version": "go1.22.0",
  "os": "darwin",
  "arch": "arm64",
  "vendor": "TelemetryFlow",
  "vendor_url": "https://telemetryflow.id",
  "developer": "DevOpsCorner Indonesia",
  "license": "Apache-2.0",
  "support_url": "https://docs.telemetryflow.id"
}
```

---

### tfo-agent config

Shows the parsed configuration. Useful for validating configuration files.

```bash
./build/tfo-agent config --config configs/tfo-agent.yaml
```

**Options:**

```bash
--config string  Path to configuration file (required)
--format string  Output format: yaml, json (default: yaml)
-h, --help       Help for config command
```

**Examples:**

```bash
# Show config as YAML
./build/tfo-agent config --config configs/tfo-agent.yaml

# Show config as JSON
./build/tfo-agent config --config configs/tfo-agent.yaml --format json

# Validate config (returns exit code 0 if valid)
./build/tfo-agent config --config configs/tfo-agent.yaml && echo "Config is valid"
```

**Output:**

```
Configuration File: configs/tfo-agent.yaml

Agent:
  ID: agent-001
  Hostname: server-01
  Description: TelemetryFlow Agent
  Tags: environment=production, datacenter=dc1

Collectors:
  Metrics: enabled=true, interval=60s
  Logs: enabled=true, paths=[/var/log/*.log]
  Traces: enabled=true

Receivers:
  OTLP gRPC: enabled=true, endpoint=0.0.0.0:4317
  OTLP HTTP: enabled=true, endpoint=0.0.0.0:4318

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

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Connection error |
| 130 | Interrupted (SIGINT) |
| 143 | Terminated (SIGTERM) |

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
./build/tfo-agent config --config configs/tfo-agent.yaml
echo $?  # 0 if valid
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

**Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.**
