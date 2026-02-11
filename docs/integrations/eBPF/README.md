# eBPF Collector - Documentation Index

TelemetryFlow Agent eBPF Collector provides deep kernel-level visibility using
Linux eBPF programs attached to tracepoints and kprobes.

## Documents

| Document                          | Description                                                  |
| --------------------------------- | ------------------------------------------------------------ |
| [Architecture](ARCHITECTURE.md)   | System design, data flow, BPF program lifecycle              |
| [Configuration](CONFIGURATION.md) | YAML config reference, environment variables, tuning         |
| [Metrics](METRICS.md)             | Complete metric catalog with types, labels, Prometheus names |
| [BPF Programs](BPF-PROGRAMS.md)   | BPF C source design, map strategy, tracepoint details        |
| [Hubble Integration](HUBBLE.md)   | Cilium Hubble gRPC client, L7 visibility, policy metrics     |
| [Operations](OPERATIONS.md)       | Requirements, deployment, troubleshooting, security          |

## Quick Start

1. Enable in `configs/tfo-agent.yaml`:

```yaml
collectors:
  ebpf:
    enabled: true
```

2. Run agent with `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`):

```bash
sudo ./build/tfo-agent start --config configs/tfo-agent.yaml
```

3. Verify metrics:

```bash
curl -s http://localhost:8888/metrics | grep tfo_ebpf
```

## Requirements

- Linux kernel 5.2+ (BTF/CO-RE support)
- `CAP_BPF` + `CAP_PERFMON` capabilities (or `CAP_SYS_ADMIN`)
- `/sys/fs/bpf` mounted
- Non-Linux platforms: collector returns empty metrics gracefully
