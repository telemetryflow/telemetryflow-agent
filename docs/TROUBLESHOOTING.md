# TelemetryFlow Agent Troubleshooting Guide

- **Version:** 1.1.2
- **Last Updated:** January 2026

---

## Overview

This guide helps diagnose and resolve common issues with TelemetryFlow Agent.

---

## Quick Diagnostics

### Check Agent Status

```bash
# Check if agent is running
ps aux | grep tfo-agent

# Check systemd status
sudo systemctl status tfo-agent

# Check agent logs
journalctl -u tfo-agent -f

# Check health endpoint
curl http://localhost:13133/
```

### Verify Configuration

```bash
# Validate configuration file
./tfo-agent config --config /etc/tfo-agent/tfo-agent.yaml

# Show parsed configuration
./tfo-agent config --config /etc/tfo-agent/tfo-agent.yaml --format yaml
```

### Check Connectivity

```bash
# Test OTLP endpoint connectivity
nc -zv localhost 4317

# Test with grpcurl (if installed)
grpcurl -plaintext localhost:4317 list

# Test HTTP endpoint
curl -v http://localhost:4318/v1/metrics
```

---

## Common Issues

### 1. Agent Fails to Start

#### Symptom
Agent exits immediately after starting with an error.

#### Possible Causes & Solutions

**Configuration file not found:**
```bash
# Error: configuration file not found
# Solution: Specify correct path
./tfo-agent start --config /path/to/tfo-agent.yaml

# Check default locations
ls -la /etc/tfo-agent/tfo-agent.yaml
ls -la ./configs/tfo-agent.yaml
```

**Invalid configuration:**
```bash
# Error: validation failed
# Solution: Validate configuration
./tfo-agent config --config /path/to/tfo-agent.yaml

# Common issues:
# - Missing telemetryflow.endpoint
# - Invalid heartbeat.interval (< 10s)
# - Invalid protocol (must be grpc or http)
```

**Permission denied:**
```bash
# Error: permission denied
# Solution: Check file permissions
ls -la /etc/tfo-agent/tfo-agent.yaml
sudo chown telemetryflow:telemetryflow /etc/tfo-agent/tfo-agent.yaml
sudo chmod 640 /etc/tfo-agent/tfo-agent.yaml

# Check buffer directory permissions
sudo mkdir -p /var/lib/tfo-agent/buffer
sudo chown -R telemetryflow:telemetryflow /var/lib/tfo-agent
```

**Port already in use:**
```bash
# Error: address already in use
# Solution: Check what's using the port
lsof -i :4317
lsof -i :4318

# Kill existing process or use different port
```

---

### 2. Connection Failures

#### Symptom
Agent starts but cannot connect to the collector/backend.

#### Solutions

**Check endpoint configuration:**
```yaml
telemetryflow:
  endpoint: "collector.example.com:4317"  # Correct format
  # endpoint: "http://collector.example.com:4317"  # Wrong for gRPC
  protocol: grpc
```

**TLS issues:**
```yaml
telemetryflow:
  endpoint: "collector.example.com:4317"
  tls:
    enabled: true
    skip_verify: false  # Set to true for self-signed certs (dev only)
```

**Network connectivity:**
```bash
# Test DNS resolution
nslookup collector.example.com

# Test TCP connectivity
telnet collector.example.com 4317
nc -zv collector.example.com 4317

# Test from container
docker exec tfo-agent nc -zv collector.example.com 4317
```

**Firewall rules:**
```bash
# Check iptables
sudo iptables -L -n | grep 4317

# Allow OTLP ports
sudo ufw allow 4317/tcp
sudo ufw allow 4318/tcp
```

---

### 3. Authentication Failures

#### Symptom
Agent connects but receives 401/403 errors.

#### Solutions

**Check API credentials:**
```yaml
telemetryflow:
  api_key_id: "tfk_your_key_id"        # Must start with tfk_
  api_key_secret: "tfs_your_secret"    # Must start with tfs_
```

**Environment variables:**
```bash
# Check if env vars are set
echo $TELEMETRYFLOW_API_KEY_ID
echo $TELEMETRYFLOW_API_KEY_SECRET

# Set environment variables
export TELEMETRYFLOW_API_KEY_ID="tfk_xxx"
export TELEMETRYFLOW_API_KEY_SECRET="tfs_xxx"
```

**Verify credentials in logs:**
```bash
# Run with debug logging to see auth headers
./tfo-agent start --config config.yaml --log-level debug 2>&1 | grep -i auth
```

---

### 4. Metrics Not Appearing

#### Symptom
Agent is running but metrics are not visible in the backend.

#### Solutions

**Check collector configuration:**
```yaml
collector:
  system:
    enabled: true      # Must be true
    interval: 15s
    cpu: true
    memory: true
    disk: true
    network: true
```

**Verify exporter is running:**
```bash
# Check logs for export messages
journalctl -u tfo-agent | grep -i "export"
journalctl -u tfo-agent | grep -i "metric"
```

**Check batch settings:**
```yaml
exporter:
  otlp:
    enabled: true
    batch_size: 100
    flush_interval: 10s    # Metrics sent every 10 seconds
```

**Verify metrics are being collected:**
```bash
# Run with debug logging
./tfo-agent start --config config.yaml --log-level debug

# Look for collection messages
# "Collected metrics" with count > 0
```

---

### 5. High Memory Usage

#### Symptom
Agent consumes excessive memory over time.

#### Solutions

**Adjust buffer settings:**
```yaml
buffer:
  enabled: true
  max_size_mb: 50      # Reduce from 100
  path: "/var/lib/tfo-agent/buffer"
```

**Reduce batch size:**
```yaml
exporter:
  otlp:
    batch_size: 50     # Reduce from 100
    flush_interval: 5s # Flush more frequently
```

**Check for memory leaks:**
```bash
# Monitor memory usage
watch -n 5 'ps -o rss,vsz,pid,cmd -p $(pgrep tfo-agent)'

# Use pprof if enabled
curl http://localhost:8888/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

---

### 6. High CPU Usage

#### Symptom
Agent consumes excessive CPU.

#### Solutions

**Increase collection interval:**
```yaml
collector:
  system:
    interval: 30s     # Increase from 15s
```

**Reduce collectors:**
```yaml
collector:
  system:
    enabled: true
    cpu: true
    memory: true
    disk: false       # Disable if not needed
    network: false    # Disable if not needed
```

**Check for busy loops:**
```bash
# Profile CPU usage
curl http://localhost:8888/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof
```

---

### 7. Disk Buffer Issues

#### Symptom
Buffer grows indefinitely or agent can't write to buffer.

#### Solutions

**Check disk space:**
```bash
df -h /var/lib/tfo-agent
du -sh /var/lib/tfo-agent/buffer
```

**Clear stale buffer:**
```bash
# Stop agent first
sudo systemctl stop tfo-agent

# Clear buffer directory
sudo rm -rf /var/lib/tfo-agent/buffer/*

# Restart agent
sudo systemctl start tfo-agent
```

**Verify buffer directory permissions:**
```bash
ls -la /var/lib/tfo-agent/buffer
sudo chown -R telemetryflow:telemetryflow /var/lib/tfo-agent
```

---

### 8. Heartbeat Failures

#### Symptom
Agent disconnects frequently or shows as offline in backend.

#### Solutions

**Adjust heartbeat settings:**
```yaml
heartbeat:
  interval: 60s        # Default is fine for most cases
  timeout: 10s         # Increase if network is slow
  include_system_info: true
```

**Check network stability:**
```bash
# Continuous ping test
ping -c 100 collector.example.com

# Check for packet loss
mtr collector.example.com
```

**Verify heartbeat in logs:**
```bash
journalctl -u tfo-agent | grep -i heartbeat
```

---

### 9. Docker-Specific Issues

#### Container fails to start

```bash
# Check container logs
docker logs tfo-agent

# Check if config is mounted correctly
docker exec tfo-agent cat /etc/tfo-agent/tfo-agent.yaml

# Verify volume mounts
docker inspect tfo-agent | jq '.[].Mounts'
```

#### Network connectivity in container

```bash
# Use host network for testing
docker run --network host telemetryflow/telemetryflow-agent:latest ...

# Or check bridge network
docker network inspect bridge
```

---

### 10. Kubernetes-Specific Issues

#### Pod not starting

```bash
# Check pod status
kubectl get pods -l app=tfo-agent

# Check pod events
kubectl describe pod <pod-name>

# Check logs
kubectl logs <pod-name>
```

#### ConfigMap issues

```bash
# Verify ConfigMap exists
kubectl get configmap tfo-agent-config -o yaml

# Check volume mount
kubectl exec <pod-name> -- cat /etc/tfo-agent/tfo-agent.yaml
```

#### Service account permissions

```bash
# Check service account
kubectl get serviceaccount tfo-agent -o yaml

# Check RBAC
kubectl auth can-i --list --as=system:serviceaccount:default:tfo-agent
```

---

## Debug Mode

### Enable Debug Logging

```bash
# Command line
./tfo-agent start --config config.yaml --log-level debug

# Environment variable
export TELEMETRYFLOW_LOG_LEVEL=debug
./tfo-agent start --config config.yaml

# In configuration
logging:
  level: debug
  format: json
```

### Useful Debug Commands

```bash
# Full debug output to file
./tfo-agent start --config config.yaml --log-level debug 2>&1 | tee agent.log

# Filter specific components
journalctl -u tfo-agent | grep -E "(exporter|collector|heartbeat)"

# Real-time log watching
tail -f /var/log/tfo-agent/agent.log
```

---

## Log Analysis

### Common Log Patterns

**Successful startup:**
```json
{"level":"info","msg":"Starting TelemetryFlow Agent","version":"1.1.2"}
{"level":"info","msg":"Configuration loaded","file":"config.yaml"}
{"level":"info","msg":"Agent started","id":"agent-001","hostname":"server-01"}
{"level":"info","msg":"Starting OTLP exporter","endpoint":"localhost:4317"}
{"level":"info","msg":"OTLP exporter started successfully"}
{"level":"info","msg":"Starting heartbeat","interval":"60s"}
```

**Connection issues:**
```json
{"level":"error","msg":"Failed to export metrics","error":"connection refused"}
{"level":"warn","msg":"Retrying export","attempt":2,"max_attempts":3}
```

**Authentication issues:**
```json
{"level":"error","msg":"Heartbeat failed","error":"status code: 401"}
```

---

## Health Checks

### HTTP Health Endpoint

```bash
# Basic health check
curl http://localhost:13133/

# Expected response
{"status":"healthy","version":"1.1.2"}
```

### Metrics Endpoint

```bash
# Prometheus metrics
curl http://localhost:8888/metrics

# Look for:
# tfo_agent_up 1
# tfo_agent_heartbeat_success_total
# tfo_agent_export_success_total
```

---

## Getting Help

### Collect Diagnostic Information

Before requesting help, collect:

```bash
# Agent version
./tfo-agent version --json > diagnostics.json

# Configuration (sanitize secrets)
./tfo-agent config --config config.yaml --format yaml | sed 's/api_key_secret:.*/api_key_secret: [REDACTED]/' >> diagnostics.txt

# Recent logs
journalctl -u tfo-agent --since "1 hour ago" >> diagnostics.txt

# System info
uname -a >> diagnostics.txt
cat /etc/os-release >> diagnostics.txt
```

### Support Channels

- **Issues**: [GitHub Issues](https://github.com/telemetryflow/telemetryflow-platform/issues)
- **Documentation**: [https://docs.telemetryflow.id](https://docs.telemetryflow.id)
- **Email**: support@telemetryflow.id

---

**Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.**
