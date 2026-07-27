# =============================================================================
# TelemetryFlow Agent - Dockerfile
# =============================================================================
#
# TelemetryFlow Agent v1.3.0-dev (Based on OpenTelemetry SDK 1.47.0)
# AI-Powered Observability & Incident Response Management (IRM) Platform
# Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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
# Stage 1: Fluent Bit binary (from official image)
# -----------------------------------------------------------------------------
# NOTE: Fluent Bit is glibc-based — runtime MUST use glibc (Debian), not musl (Alpine).
# See: https://github.com/fluent/fluent-bit/issues/2464
FROM fluent/fluent-bit:5.0.9 AS fluent-bit

# -----------------------------------------------------------------------------
# Stage 2: Builder
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

# Build arguments
ARG VERSION=1.3.0-dev
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_TIME=unknown
ARG TARGETOS=linux
ARG TARGETARCH

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
# Uses TARGETOS/TARGETARCH for multi-arch support (amd64, arm64)
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.Version=${VERSION}' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitCommit=${GIT_COMMIT}' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitBranch=${GIT_BRANCH}' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.BuildTime=${BUILD_TIME}'" \
    -o /tfo-agent ./cmd/tfo-agent

# -----------------------------------------------------------------------------
# Stage 3: Runtime (Debian slim — glibc required for Fluent Bit compatibility)
# -----------------------------------------------------------------------------
# IMPORTANT: Do NOT switch to Alpine. Fluent Bit requires glibc and has known
# issues with musl: memory allocator (jemalloc), Golang plugin loading, and
# time format parsing. See https://github.com/fluent/fluent-bit/issues/2464
# NOTE: Fluent Bit 5.x requires GLIBC >= 2.38 — bookworm (2.36) is too old.
FROM debian:trixie-slim

ARG VERSION=1.3.0-dev

# =============================================================================
# TelemetryFlow Metadata Labels (OCI Image Spec)
# =============================================================================
LABEL org.opencontainers.image.title="TelemetryFlow Agent" \
    org.opencontainers.image.description="Enterprise telemetry collection agent for metrics, logs, and traces - AI-Powered Observability & Incident Response Management (IRM) Platform" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.vendor="TelemetryFlow" \
    org.opencontainers.image.authors="Telemetri Data Indonesia <support@telemetryflow.id>" \
    org.opencontainers.image.url="https://telemetryflow.id" \
    org.opencontainers.image.documentation="https://docs.telemetryflow.id" \
    org.opencontainers.image.source="https://github.com/telemetryflow/telemetryflow-agent" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.base.name="debian:trixie-slim" \
    # TelemetryFlow specific labels
    io.telemetryflow.product="TelemetryFlow Agent" \
    io.telemetryflow.component="tfo-agent" \
    io.telemetryflow.platform="CEOP" \
    io.telemetryflow.maintainer="Telemetri Data Indonesia"

# Install runtime dependencies and security patches
# Fluent Bit 5.x requires: libyaml, openssl3, libcurl, libsasl2, libpq
# SECURITY: dist-upgrade ensures all base packages are patched against known CVEs
# (glibc CVE-2026-5435/CVE-2026-6238, gnutls CVE-2026-42010/CVE-2026-33845,
# libssh2 CVE-2026-7598, curl CVE-2026-6276, etc.)
# NOTE: Do NOT remove libssh2-1t64 — libcurl4t64 depends on it for SCP/SFTP.
# dist-upgrade already patches libssh2; removing it cascades to libcurl removal which breaks Fluent Bit (exit status 127).
# NOTE: perl-base is required by apt/dpkg and cannot be purged. To eliminate
# CVE-2026-42496/CVE-2026-8376/CVE-2026-42497/CVE-2026-9538 (Archive::Tar),
# CVE-2026-52287 (IO::Compress), CVE-2026-52286 (IO::Uncompress::Unzip),
# CVE-2026-48961 (IO::Compress zipdetails DoS),
# CVE-2026-12087 (Socket out-of-bounds read),
# CVE-2025-4270 (HTTP::Tiny CRLF), we strip the vulnerable Perl modules after
# install — they are not needed at runtime.
# ncurses-base, ncurses-bin, tar also cannot be purged — patches from dist-upgrade.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libyaml-0-2 \
    libssl3t64 \
    libcurl4t64 \
    libsasl2-2 \
    libpq5 \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y krb5-{lib,multidev} libkrb5-3 libgssapi-krb5-2 2>/dev/null || true \
    && rm -rf /usr/share/perl5/Archive/Tar* \
              /usr/share/perl5/IO/Compress* \
              /usr/share/perl5/IO/Uncompress* \
              /usr/share/perl5/Compress/Zlib.pm \
              /usr/share/perl5/Compress/Raw* \
              /usr/share/perl5/HTTP/Tiny* \
              /usr/share/perl/5.*/HTTP/Tiny* \
              /usr/share/perl/5.*/IO/Compress* \
              /usr/share/perl/5.*/IO/Uncompress* \
              /usr/lib/*/perl/5.*/auto/Socket \
              /usr/share/perl/5.*/Socket* \
    && DEBIAN_FRONTEND=noninteractive apt-get purge -y libsqlite3-0 2>/dev/null || true \
    && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd -g 10001 telemetryflow && \
    useradd -u 10001 -g telemetryflow -m -d /home/telemetryflow -s /usr/sbin/nologin telemetryflow

# Create required directories
RUN mkdir -p \
    /etc/tfo-agent \
    /var/lib/tfo-agent/buffer \
    /var/log/tfo-agent \
    /tmp/tfo-agent-fluentbit/storage \
    && chown -R telemetryflow:telemetryflow \
    /etc/tfo-agent \
    /var/lib/tfo-agent \
    /var/log/tfo-agent \
    /tmp/tfo-agent-fluentbit

# Copy TFO-Agent binary from builder
COPY --from=builder /tfo-agent /usr/local/bin/tfo-agent
RUN chmod +x /usr/local/bin/tfo-agent

# Copy Fluent Bit binary and default configs from official image
# Enables production-grade log collection (CRI/Docker parsers, K8s metadata,
# multiline stack traces, filesystem buffering) without external sidecar.
# ~15MB addition. Activated via collectors.fluent_bit.enabled: true
COPY --from=fluent-bit /fluent-bit/bin/fluent-bit /usr/local/bin/fluent-bit
COPY --from=fluent-bit /fluent-bit/etc/fluent-bit.conf /etc/fluent-bit/fluent-bit.conf
COPY --from=fluent-bit /fluent-bit/etc/parsers.conf /etc/fluent-bit/parsers.conf
RUN chmod +x /usr/local/bin/fluent-bit

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
# 2020 - Fluent Bit health/metrics (when fluent_bit.health_check enabled)
EXPOSE 4317 4318 8888 13133 2020

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
#     --build-arg VERSION=1.3.0-dev \
#     --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
#     --build-arg GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD) \
#     --build-arg BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ') \
#     -t telemetryflow/telemetryflow-agent:1.3.0-dev .
#
# Multi-arch build:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=1.3.0-dev \
#     -t telemetryflow/telemetryflow-agent:1.3.0-dev .
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
#     telemetryflow/telemetryflow-agent:1.3.0-dev
# =============================================================================
