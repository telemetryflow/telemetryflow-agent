# =============================================================================
# TelemetryFlow Agent - Dockerfile
# =============================================================================
#
# TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
# Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# =============================================================================
# Multi-stage build for minimal image size
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

# Build arguments
ARG VERSION=1.1.2
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown

# Install build dependencies
RUN apk add --no-cache git make ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary with version information
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.Version=${VERSION}' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitCommit=${GIT_COMMIT}' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitBranch=${GIT_BRANCH}' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.BuildTime=${BUILD_TIME}'" \
    -o /tfo-agent ./cmd/tfo-agent

# Verify binary
RUN /tfo-agent version

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM alpine:3.21

# =============================================================================
# TelemetryFlow Metadata Labels (OCI Image Spec)
# =============================================================================
LABEL org.opencontainers.image.title="TelemetryFlow Agent" \
    org.opencontainers.image.description="Enterprise telemetry collection agent for metrics, logs, and traces - Community Enterprise Observability Platform (CEOP)" \
    org.opencontainers.image.version="1.1.2" \
    org.opencontainers.image.vendor="TelemetryFlow" \
    org.opencontainers.image.authors="DevOpsCorner Indonesia <support@devopscorner.id>" \
    org.opencontainers.image.url="https://telemetryflow.id" \
    org.opencontainers.image.documentation="https://docs.telemetryflow.id" \
    org.opencontainers.image.source="https://github.com/telemetryflow/telemetryflow-platform" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.base.name="alpine:3.21" \
    # TelemetryFlow specific labels
    io.telemetryflow.product="TelemetryFlow Agent" \
    io.telemetryflow.component="tfo-agent" \
    io.telemetryflow.platform="CEOP" \
    io.telemetryflow.maintainer="DevOpsCorner Indonesia"

# Update packages to get security patches (CVE fixes) and install runtime dependencies
RUN apk upgrade --no-cache && \
    apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user and group
RUN addgroup -g 10001 -S telemetryflow && \
    adduser -u 10001 -S telemetryflow -G telemetryflow -h /home/telemetryflow

# Create required directories
RUN mkdir -p \
    /etc/tfo-agent \
    /var/lib/tfo-agent/buffer \
    /var/log/tfo-agent \
    && chown -R telemetryflow:telemetryflow \
    /etc/tfo-agent \
    /var/lib/tfo-agent \
    /var/log/tfo-agent

# Copy binary from builder
COPY --from=builder /tfo-agent /usr/local/bin/tfo-agent
RUN chmod +x /usr/local/bin/tfo-agent

# Copy default configuration
COPY configs/tfo-agent.yaml /etc/tfo-agent/tfo-agent.yaml
RUN chown telemetryflow:telemetryflow /etc/tfo-agent/tfo-agent.yaml

# Switch to non-root user
USER telemetryflow

# Set working directory
WORKDIR /home/telemetryflow

# =============================================================================
# Exposed Ports
# =============================================================================
# 4317 - OTLP gRPC receiver
# 4318 - OTLP HTTP receiver
# 8888 - Prometheus metrics (self-observability)
# 13133 - Health check endpoint
EXPOSE 4317 4318 8888 13133

# =============================================================================
# Health Check
# =============================================================================
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:13133/ || exit 1

# =============================================================================
# Entrypoint & Command
# =============================================================================
ENTRYPOINT ["/usr/local/bin/tfo-agent"]
CMD ["start", "--config", "/etc/tfo-agent/tfo-agent.yaml"]

# =============================================================================
# Build Information
# =============================================================================
# Build with:
#   docker build \
#     --build-arg VERSION=1.1.2 \
#     --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
#     --build-arg GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD) \
#     --build-arg BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
#     -t telemetryflow/telemetryflow-agent:1.1.2 .
#
# Run with:
#   docker run -d \
#     --name tfo-agent \
#     -p 4317:4317 \
#     -p 4318:4318 \
#     -p 8888:8888 \
#     -p 13133:13133 \
#     -v /path/to/config.yaml:/etc/tfo-agent/tfo-agent.yaml:ro \
#     -v /var/lib/tfo-agent:/var/lib/tfo-agent \
#     telemetryflow/telemetryflow-agent:1.1.2
# =============================================================================
