# TelemetryFlow Agent Installation Guide

- **Version:** 1.1.2
- **OTEL SDK Version:** 1.39.0
- **Last Updated:** January 2026

---

## Prerequisites

- Go 1.24 or later (for building from source)
- Make (for build automation)
- Docker (optional, for containerized deployment)

---

## Installation Methods

### Method 1: Build from Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/telemetryflow-agent.git
cd telemetryflow-agent

# Build the binary
make build

# Verify the build
./build/tfo-agent version
```

**Expected Output:**
```
TelemetryFlow Agent v1.1.2 (OTEL SDK 1.39.0)

  Build Information
  ─────────────────────────────────────────────
  Commit:      abc1234
  Branch:      main
  Built:       2025-12-27T10:00:00Z
  Go Version:  go1.24.0
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

### Method 2: Docker Image

#### Using Docker Compose (Recommended)

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
vim .env

# Build and start
docker-compose up -d --build

# View logs
docker-compose logs -f tfo-agent

# Check health
curl http://localhost:13133/

# Stop
docker-compose down
```

**Environment Variables (.env.example):**

| Variable | Description | Default |
|----------|-------------|---------|
| `VERSION` | Build version | `1.1.2` |
| `OTEL_SDK_VERSION` | OpenTelemetry SDK version | `1.39.0` |
| `IMAGE_NAME` | Docker image name | `telemetryflow/telemetryflow-agent` |
| `OTLP_GRPC_PORT` | OTLP gRPC port | `4317` |
| `OTLP_HTTP_PORT` | OTLP HTTP port | `4318` |
| `METRICS_PORT` | Prometheus metrics port | `8888` |
| `HEALTH_PORT` | Health check port | `13133` |
| `TELEMETRYFLOW_ENDPOINT` | TelemetryFlow collector endpoint | `localhost:4317` |
| `TELEMETRYFLOW_API_KEY_ID` | API key ID | - |
| `TELEMETRYFLOW_API_KEY_SECRET` | API key secret | - |
| `LOG_LEVEL` | Log level | `info` |
| `MEMORY_LIMIT` | Container memory limit | `512M` |

#### Using Docker Directly

```bash
# Build image with version info
docker build \
  --build-arg VERSION=1.1.2 \
  --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
  --build-arg GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD) \
  --build-arg BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
  -t telemetryflow/telemetryflow-agent:1.1.2 .

# Run with configuration
docker run -d \
  --name tfo-agent \
  --hostname $(hostname) \
  -p 4317:4317 \
  -p 4318:4318 \
  -p 8888:8888 \
  -p 13133:13133 \
  -v $(pwd)/configs/tfo-agent.yaml:/etc/tfo-agent/tfo-agent.yaml:ro \
  -v /var/lib/tfo-agent:/var/lib/tfo-agent \
  telemetryflow/telemetryflow-agent:1.1.2

# Check logs
docker logs tfo-agent

# Check health
curl http://localhost:13133/
```

### Method 3: Binary Installation

```bash
# Download the latest release
VERSION=1.1.2
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

wget https://github.com/telemetryflow/telemetryflow-agent/releases/download/v${VERSION}/tfo-agent-${PLATFORM}-${ARCH}.tar.gz

# Extract
tar -xzf tfo-agent-${PLATFORM}-${ARCH}.tar.gz

# Move to system path
sudo mv tfo-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/tfo-agent

# Verify installation
tfo-agent version
```

---

## Configuration Setup

### Create Configuration Directory

```bash
sudo mkdir -p /etc/tfo-agent
sudo mkdir -p /var/lib/tfo-agent/buffer
sudo mkdir -p /var/log/tfo-agent
```

### Copy Default Configuration

```bash
# From source
sudo cp configs/tfo-agent.yaml /etc/tfo-agent/

# Or create minimal config (v1.1.2+)
cat > /etc/tfo-agent/tfo-agent.yaml <<'EOF'
# TelemetryFlow Platform Configuration
telemetryflow:
  api_key_id: "${TELEMETRYFLOW_API_KEY_ID}"
  api_key_secret: "${TELEMETRYFLOW_API_KEY_SECRET}"
  endpoint: "${TELEMETRYFLOW_ENDPOINT:-localhost:4317}"
  protocol: grpc
  tls:
    enabled: true

agent:
  id: ""
  hostname: ""
  name: "TelemetryFlow Agent"
  tags:
    environment: "production"

collector:
  system:
    enabled: true
    interval: 15s
    cpu: true
    memory: true
    disk: true
    network: true

exporter:
  otlp:
    enabled: true
    batch_size: 100
    flush_interval: 10s
    compression: gzip

buffer:
  enabled: true
  path: "/var/lib/tfo-agent/buffer"
  max_size_mb: 100

logging:
  level: "info"
  format: "json"
EOF
```

---

## Systemd Service Installation

### Create Service File

```bash
sudo tee /etc/systemd/system/tfo-agent.service > /dev/null <<'EOF'
[Unit]
Description=TelemetryFlow Agent - Community Enterprise Observability Platform
Documentation=https://docs.telemetryflow.id
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telemetryflow
Group=telemetryflow
ExecStart=/usr/local/bin/tfo-agent start --config /etc/tfo-agent/tfo-agent.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tfo-agent

# Resource limits
LimitNOFILE=65536
MemoryMax=512M

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/tfo-agent /var/log/tfo-agent

[Install]
WantedBy=multi-user.target
EOF
```

### Create Service User

```bash
# Create user and group
sudo useradd -r -s /bin/false -d /var/lib/tfo-agent telemetryflow

# Set permissions
sudo chown -R telemetryflow:telemetryflow /etc/tfo-agent
sudo chown -R telemetryflow:telemetryflow /var/lib/tfo-agent
sudo chown -R telemetryflow:telemetryflow /var/log/tfo-agent
```

### Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable tfo-agent

# Start service
sudo systemctl start tfo-agent

# Check status
sudo systemctl status tfo-agent

# View logs
sudo journalctl -u tfo-agent -f
```

---

## Kubernetes Installation

### Using Helm (Coming Soon)

```bash
# Add TelemetryFlow Helm repository
helm repo add telemetryflow https://charts.telemetryflow.id
helm repo update

# Install tfo-agent as DaemonSet
helm install tfo-agent telemetryflow/telemetryflow-agent \
  --namespace observability \
  --create-namespace \
  --set config.endpoint="http://tfo-collector:4317"
```

### Using kubectl

**1. Create Namespace and Secrets:**

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: observability
---
apiVersion: v1
kind: Secret
metadata:
  name: tfo-agent-secrets
  namespace: observability
type: Opaque
stringData:
  endpoint: "http://tfo-collector.observability.svc:4317"
```

**2. Create ConfigMap:**

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tfo-agent-config
  namespace: observability
data:
  tfo-agent.yaml: |
    agent:
      id: ""
      hostname: ""
      description: "Kubernetes Agent"
      tags:
        environment: "kubernetes"

    collectors:
      metrics:
        enabled: true
        interval: 60s
      logs:
        enabled: true
        paths:
          - /var/log/pods/**/*.log
      traces:
        enabled: true

    exporter:
      otlp:
        enabled: true
        endpoint: "${ENDPOINT}"
        compression: "gzip"

    buffer:
      enabled: true
      path: "/var/lib/tfo-agent/buffer"
      max_size_mb: 100
```

**3. Create DaemonSet:**

```yaml
# daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: tfo-agent
  namespace: observability
  labels:
    app: tfo-agent
    version: "1.1.2"
spec:
  selector:
    matchLabels:
      app: tfo-agent
  template:
    metadata:
      labels:
        app: tfo-agent
    spec:
      serviceAccountName: tfo-agent
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet

      containers:
      - name: tfo-agent
        image: telemetryflow/telemetryflow-agent:1.1.2
        args:
          - "start"
          - "--config"
          - "/etc/tfo-agent/tfo-agent.yaml"

        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: ENDPOINT
          valueFrom:
            secretKeyRef:
              name: tfo-agent-secrets
              key: endpoint

        ports:
        - name: otlp-grpc
          containerPort: 4317
          hostPort: 4317
        - name: otlp-http
          containerPort: 4318
          hostPort: 4318
        - name: health
          containerPort: 13133

        livenessProbe:
          httpGet:
            path: /
            port: 13133
          initialDelaySeconds: 30
          periodSeconds: 30

        readinessProbe:
          httpGet:
            path: /
            port: 13133
          initialDelaySeconds: 10
          periodSeconds: 10

        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"

        volumeMounts:
        - name: config
          mountPath: /etc/tfo-agent
        - name: varlog
          mountPath: /var/log
          readOnly: true
        - name: buffer
          mountPath: /var/lib/tfo-agent

      volumes:
      - name: config
        configMap:
          name: tfo-agent-config
      - name: varlog
        hostPath:
          path: /var/log
      - name: buffer
        hostPath:
          path: /var/lib/tfo-agent
          type: DirectoryOrCreate

      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
        operator: Exists
      - effect: NoSchedule
        key: node-role.kubernetes.io/control-plane
        operator: Exists
```

**4. Apply Resources:**

```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f daemonset.yaml

# Verify
kubectl get pods -n observability -l app=tfo-agent
kubectl logs -n observability -l app=tfo-agent --tail=50
```

---

## Verification

### Health Check

```bash
# HTTP health endpoint
curl http://localhost:13133/
# Expected: {"status":"healthy"}
```

### Metrics Endpoint

```bash
# Prometheus metrics
curl http://localhost:8888/metrics | head -20
```

### Send Test Data

```bash
# Send test metrics via OTLP HTTP
curl -X POST http://localhost:4318/v1/metrics \
  -H "Content-Type: application/json" \
  -d '{
    "resourceMetrics": [{
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "test-service"}}
        ]
      },
      "scopeMetrics": [{
        "metrics": [{
          "name": "test.metric",
          "sum": {
            "dataPoints": [{
              "asInt": "100",
              "timeUnixNano": "'$(date +%s)000000000'"
            }]
          }
        }]
      }]
    }]
  }'
```

---

## Upgrading

### Binary Upgrade

```bash
# Stop service
sudo systemctl stop tfo-agent

# Backup current binary
sudo cp /usr/local/bin/tfo-agent /usr/local/bin/tfo-agent.backup

# Download and install new version
# ... (same as installation steps)

# Start service
sudo systemctl start tfo-agent

# Verify
tfo-agent version
```

### Docker Upgrade

```bash
# Pull new image
docker pull telemetryflow/telemetryflow-agent:1.1.2

# Stop and remove old container
docker stop tfo-agent
docker rm tfo-agent

# Start with new image
docker run -d \
  --name tfo-agent \
  ... # same options as before
  telemetryflow/telemetryflow-agent:1.1.2 \
  start --config /etc/tfo-agent/config.yaml
```

### Kubernetes Upgrade

```bash
# Update image in DaemonSet
kubectl set image daemonset/tfo-agent \
  tfo-agent=telemetryflow/telemetryflow-agent:1.1.2 \
  -n observability

# Watch rollout
kubectl rollout status daemonset/tfo-agent -n observability
```

---

## Uninstallation

### Systemd

```bash
# Stop and disable service
sudo systemctl stop tfo-agent
sudo systemctl disable tfo-agent

# Remove service file
sudo rm /etc/systemd/system/tfo-agent.service
sudo systemctl daemon-reload

# Remove binary and config
sudo rm /usr/local/bin/tfo-agent
sudo rm -rf /etc/tfo-agent
sudo rm -rf /var/lib/tfo-agent
sudo rm -rf /var/log/tfo-agent

# Remove user
sudo userdel telemetryflow
```

### Docker

```bash
docker stop tfo-agent
docker rm tfo-agent
docker rmi telemetryflow/telemetryflow-agent:latest
```

### Kubernetes

```bash
kubectl delete daemonset tfo-agent -n observability
kubectl delete configmap tfo-agent-config -n observability
kubectl delete secret tfo-agent-secrets -n observability
```

---

**Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.**
