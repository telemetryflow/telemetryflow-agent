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
# (glibc, gnutls, krb5, curl, etc.). It also supersedes the old per-package
# krb5 upgrade line (which never expanded under dash /bin/sh).
# NOTE: Do NOT remove libssh2-1t64 — libcurl4t64 depends on it for SCP/SFTP.
# The librtmp1 -> libgnutls30t64 -> libp11-kit0 chain is likewise a hard
# dependency of libcurl4t64; removing it breaks Fluent Bit (exit status 127).
#
# MINIMAL RUNTIME STRIP:
# The agent only ever execs tfo-agent, fluent-bit and (optionally) journalctl.
# It never invokes perl, tar, or the openssl CLI, so after all package
# operations the image removes them outright:
#   - perl-base + apt (+ sqv, debian-archive-keyring, libapt-pkg7.0, ...):
#     package manager and interpreter purged with --allow-remove-essential.
#     Clears perl CVE-2026-57433 (HIGH), CVE-2026-13221 and the whole
#     perl-module CVE family that was previously mitigated by stripping
#     module files by hand.
#   - openssl CLI + openssl-provider-legacy: only needed to (re)generate CA
#     certificate hashes; /etc/ssl/certs is already populated. Removed with
#     --force-depends (ca-certificates declares the dependency) — clears the
#     CLI/provider instances of openssl CVE-2026-14456.
#   - tar: required by dpkg only; force-removed as the final dpkg operation.
#     Clears tar CVE-2026-18477 and CVE-2026-18508.
# libstdc++6 is marked manual before the purge — Fluent Bit links it and
# apt's auto-remove would otherwise take it along with apt.
# Remaining unfixable CVEs (libssl3t64 QUIC CVE-2026-14456, libssh2
# CVE-2026-58050 et al., glibc CVE-2026-6368/CVE-2026-6791, libsystemd0/
# libudev1 CVE-2026-15059/CVE-2026-16742, libp11-kit0 CVE-2026-18938 [32-bit
# only], libcurl CVE-2026-8458) have no fixed version in trixie and cannot be
# removed — evaluated and documented in .trivyignore.
# WARNING: apt/dpkg/tar are NOT available in derived images at runtime.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libyaml-0-2 \
    libssl3t64 \
    libcurl4t64 \
    libsasl2-2 \
    libpq5 \
    && DEBIAN_FRONTEND=noninteractive apt-get purge -y libsqlite3-0 2>/dev/null || true \
    && apt-mark manual libstdc++6 \
    && DEBIAN_FRONTEND=noninteractive apt-get purge -y --allow-remove-essential --auto-remove perl-base apt \
    && dpkg --remove --force-depends openssl openssl-provider-legacy \
    && dpkg --remove --force-all tar \
    && rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log* /etc/apt/sources.list.d

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
