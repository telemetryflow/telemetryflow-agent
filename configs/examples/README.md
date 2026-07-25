# TelemetryFlow Agent — Example Configurations

Minimal, production-ready starting points. Each config uses **only TFO-native
collectors** — no third-party database/app integrations, no pipeline processors.
Copy, set your API keys, and go.

## Files

| File | Use Case | Collectors | ~Metrics |
|---|---|---|---|
| [`k8s-minimal.yaml`](./k8s-minimal.yaml) | Kubernetes DaemonSet / Deployment | `system` + `node_exporter` + `kubernetes` (33 sub-collectors) | ~250-500 / node |
| [`vm-minimal.yaml`](./vm-minimal.yaml) | Standalone Linux VM / bare metal | `system` + `node_exporter` | ~250 / host |

## Quick Start

### Kubernetes

```bash
# Create ConfigMap from the example
kubectl create configmap tfo-agent-config \
  --from-file=configs/examples/k8s-minimal.yaml

# Deploy (see deploy/kubernetes/daemonset.yaml for full manifest)
kubectl apply -f deploy/kubernetes/
```

Or via Helm:
```bash
helm install tfo-agent deploy/helm/telemetryflow-agent \
  --set telemetryflow.apiKeyId=$TELEMETRYFLOW_API_KEY_ID \
  --set telemetryflow.apiKeySecret=$TELEMETRYFLOW_API_KEY_SECRET
```

### VM (systemd)

```bash
# Install
sudo cp configs/examples/vm-minimal.yaml /etc/tfo-agent/tfo-agent.yaml
sudo systemctl enable tfo-agent
sudo systemctl start tfo-agent

# Check
sudo systemctl status tfo-agent
journalctl -u tfo-agent -f
```

### VM (Docker)

```bash
docker run -d \
  --name tfo-agent \
  --restart unless-stopped \
  -e TELEMETRYFLOW_API_KEY_ID=tfk_xxx \
  -e TELEMETRYFLOW_API_KEY_SECRET=tfs_xxx \
  --pid=host \
  -v /etc/tfo-agent/tfo-agent.yaml:/etc/tfo-agent/tfo-agent.yaml:ro \
  -v /var/lib/tfo-agent:/var/lib/tfo-agent \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  telemetryflow/telemetryflow-agent:1.3.0-dev
```

## Environment Variables

Both configs resolve these env vars:

| Variable | Required | Default | Description |
|---|---|---|---|
| `TELEMETRYFLOW_API_KEY_ID` | ✅ | — | API key ID (`tfk_xxx`) |
| `TELEMETRYFLOW_API_KEY_SECRET` | ✅ | — | API key secret (`tfs_xxx`) |
| `TELEMETRYFLOW_ENDPOINT` | ❌ | `https://api.telemetryflow.id` | OTLP endpoint |
| `TELEMETRYFLOW_ID` | ❌ | auto (UUIDv5 host) | Agent ID |
| `TELEMETRYFLOW_HOSTNAME` | ❌ | `os.Hostname()` | Display hostname |
| `NODE_NAME` | ❌ | — | K8s node name (set by downward API) |
| `TELEMETRYFLOW_K8S_CLUSTER_NAME` | ❌ | auto-detect | K8s cluster name |
| `TELEMETRYFLOW_K8S_CLUSTER_PROVIDER` | ❌ | auto-detect | `eks` / `gke` / `aks` / `self-managed` |

## What's NOT Included (by design)

These configs are intentionally minimal. Add collectors incrementally
when you need them:

- **Database monitoring**: MySQL, PostgreSQL, MongoDB, Redis, etc.
  → Copy from `configs/collectors-*.yaml`
- **Network monitoring**: ping, SNMP, NetFlow, syslog
  → Copy from `configs/collectors-{ping,snmp,netflow,syslog}.yaml`
- **App servers**: Nginx, Apache, HAProxy
  → Copy from `configs/collectors-{nginx,apache,haproxy}.yaml`
- **Log collection**: file tailer, journald
  → Copy from `configs/collectors-log.yaml`
- **eBPF**: kernel-level syscall + network flow observability
  → Copy from `configs/collectors-ebpf.yaml`
- **Pipeline processors**: filter, rename, starlark scripting
  → See `configs/pipeline.yaml`
- **Multi-output**: Prometheus remote write, Kafka, Loki, File
  → See `configs/outputs.yaml`

## Full Reference

For the complete config with every option documented, see
[`../tfo-agent.yaml`](../tfo-agent.yaml) (1900+ lines).
