# TFO-Agent Quick Start Guide

Get TFO-Agent running with TFO Platform in 5 minutes.

## Prerequisites

- Docker or Kubernetes cluster
- TFO-Collector running (`:4317` gRPC or `:4318` HTTP)
- TFO Platform API credentials (API Key ID + Secret)

## 1. Quick Start with Docker Compose

```bash
# Clone repository
git clone https://github.com/telemetryflow/telemetryflow-agent.git
cd telemetryflow-agent

# Copy environment template
cp .env.example .env

# Edit .env with your credentials
cat > .env << EOF
TELEMETRYFLOW_API_KEY_ID=tfk_your_key_id
TELEMETRYFLOW_API_KEY_SECRET=tfs_your_secret
TELEMETRYFLOW_ENDPOINT=localhost:4317
TELEMETRYFLOW_ENVIRONMENT=production
EOF

# Start agent
docker-compose up -d

# View logs
docker-compose logs -f tfo-agent
```

## 2. Quick Start with Kubernetes

```bash
# Create namespace
kubectl create namespace telemetryflow

# Create secret for credentials
kubectl create secret generic tfo-credentials \
  --from-literal=api-key-id=tfk_your_key_id \
  --from-literal=api-key-secret=tfs_your_secret \
  -n telemetryflow

# Apply RBAC (required for Kubernetes collector)
kubectl apply -f deploy/kubernetes/rbac.yaml

# Apply ConfigMap
kubectl apply -f deploy/kubernetes/configmap.yaml

# Deploy DaemonSet
kubectl apply -f deploy/kubernetes/daemonset.yaml

# Check status
kubectl get pods -n telemetryflow -l app=tfo-agent

# View logs
kubectl logs -n telemetryflow -l app=tfo-agent --tail=100 -f
```

## 3. Quick Start with Binary

```bash
# Download binary (Linux example)
wget https://github.com/telemetryflow/telemetryflow-agent/releases/latest/download/tfo-agent-linux-amd64
chmod +x tfo-agent-linux-amd64
sudo mv tfo-agent-linux-amd64 /usr/local/bin/tfo-agent

# Create config directory
sudo mkdir -p /etc/tfo-agent

# Create configuration
sudo tee /etc/tfo-agent/tfo-agent.yaml > /dev/null << EOF
telemetryflow:
  api_key_id: "tfk_your_key_id"
  api_key_secret: "tfs_your_secret"
  endpoint: "localhost:4317"
  protocol: grpc

agent:
  name: "my-agent"
  tags:
    environment: production

collectors:
  node_exporter:
    enabled: true
    interval: 15s

exporter:
  otlp:
    enabled: true
EOF

# Start agent
tfo-agent start --config /etc/tfo-agent/tfo-agent.yaml
```

## 4. Verify Integration

### Check Agent Registration

```bash
# TFO Platform UI
# Navigate to: Settings → Agents
# You should see your agent listed with "Online" status
```

### Check Metrics Flow

```bash
# Query TFO-Collector metrics endpoint
curl http://localhost:8888/metrics | grep tfo_ebpf

# Query Prometheus (if configured)
curl 'http://localhost:9090/api/v1/query?query=node_cpu_usage'

# Check TFO Platform dashboards
# Navigate to: Dashboards → System Metrics
```

### Check Logs

```bash
# Docker
docker logs tfo-agent

# Kubernetes
kubectl logs -n telemetryflow -l app=tfo-agent

# Binary
journalctl -u tfo-agent -f
```

## 5. Enable Additional Collectors

### Enable Kubernetes Collector

```yaml
collectors:
  kubernetes:
    enabled: true
    interval: 30s
    collect_pods: true
    collect_nodes: true
    collect_deployments: true
```

**Requirements**: RBAC permissions (see `deploy/kubernetes/rbac.yaml`)

### Enable eBPF Collector (Linux-only)

```yaml
collectors:
  ebpf:
    enabled: true
    interval: 15s
    collect_syscalls: true
    collect_network: true
```

**Requirements**:

- Linux kernel 5.2+
- `CAP_BPF` + `CAP_PERFMON` capabilities

```bash
# Set capabilities
sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/tfo-agent

# Verify
getcap /usr/local/bin/tfo-agent
```

## Configuration Profiles

### Development Profile

**Use**: Local development, testing
**Config**: `configs/tfo-agent.yaml` (minimal)

```yaml
telemetryflow:
  endpoint: "localhost:4317"
  tls:
    enabled: false

collectors:
  node_exporter:
    enabled: true
```

### Production Profile

**Use**: Production deployments
**Config**: `configs/tfo-agent.default.yaml` (full-featured)

```yaml
telemetryflow:
  endpoint: "tfo-collector:4317"
  tls:
    enabled: true
  retry:
    enabled: true
    max_attempts: 3

collectors:
  node_exporter:
    enabled: true
  kubernetes:
    enabled: true
  ebpf:
    enabled: true

buffer:
  enabled: true
  max_size_mb: 500
```

## Common Issues

### Agent Can't Connect to TFO-Collector

```bash
# Test connectivity
curl -v http://tfo-collector:4318/v1/metrics

# Check DNS
nslookup tfo-collector

# Check firewall
telnet tfo-collector 4317
```

**Fix**: Verify `telemetryflow.endpoint` in config

### No Metrics in TFO Platform

```bash
# Check agent is sending metrics
docker logs tfo-agent | grep "Exported"

# Check TFO-Collector is receiving
kubectl logs -n telemetryflow tfo-collector | grep "metrics received"

# Verify API keys
echo $TELEMETRYFLOW_API_KEY_ID
```

**Fix**: Verify API credentials and collector endpoint

### Kubernetes Collector Not Working

```bash
# Check ServiceAccount
kubectl get serviceaccount tfo-agent -n telemetryflow

# Check RBAC permissions
kubectl auth can-i get pods --as=system:serviceaccount:telemetryflow:tfo-agent

# Check kubeconfig
kubectl exec -n telemetryflow tfo-agent-xxxx -- ls /var/run/secrets/kubernetes.io/serviceaccount/
```

**Fix**: Apply RBAC resources from `deploy/kubernetes/rbac.yaml`

### eBPF Collector Not Loading

```bash
# Check kernel version
uname -r  # Should be >= 5.2

# Check BPF filesystem
mount | grep bpf

# Check capabilities
getcap /usr/local/bin/tfo-agent

# Check BTF
ls -la /sys/kernel/btf/vmlinux
```

**Fix**: Mount BPF filesystem and set capabilities

## Next Steps

1. **Configure Dashboards**: Import dashboards from TFO Platform
2. **Set Up Alerts**: Configure alerting rules in TFO Platform
3. **Scale Deployment**: Deploy as DaemonSet across all nodes
4. **Enable Advanced Collectors**: eBPF, Kubernetes, custom collectors
5. **Integrate with CI/CD**: Automate deployment via GitOps

## Resources

- **Full Configuration**: [`configs/tfo-agent.default.yaml`](../configs/tfo-agent.default.yaml)
- **Integration Guide**: [TFO-PLATFORM-INTEGRATION.md](TFO-PLATFORM-INTEGRATION.md)
- **eBPF Docs**: [docs/integrations/eBPF/](integrations/eBPF/)
- **Kubernetes Deployment**: [`deploy/kubernetes/`](../deploy/kubernetes/)
- **Docker Compose**: [`docker-compose.yml`](../docker-compose.yml)

## Support

- **Slack**: [TelemetryFlow Community](https://telemetryflow.slack.com)
- **Issues**: [GitHub Issues](https://github.com/telemetryflow/telemetryflow-platform/issues)
- **Email**: [support@telemetryflow.id](mailto:support@telemetryflow.id)
