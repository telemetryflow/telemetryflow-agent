# TelemetryFlow Agent Development Guide

- **Version:** 1.1.2
- **Last Updated:** January 2026
- **Go Version:** 1.24+
- **OTEL SDK Version:** 1.39.0

---

## Overview

This guide covers development setup, coding standards, testing practices, and contribution guidelines for TelemetryFlow Agent.

---

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.24+ | Primary language |
| Make | 3.81+ | Build automation |
| Docker | 20.10+ | Container builds |
| golangci-lint | 1.62+ | Code linting |
| Git | 2.30+ | Version control |

### Optional Tools

| Tool | Purpose |
|------|---------|
| gvm | Go version manager |
| pre-commit | Git hooks |
| goreleaser | Release automation |

---

## Getting Started

### Clone and Setup

```bash
# Clone repository
git clone https://github.com/telemetryflow/telemetryflow-agent.git
cd telemetryflow-agent

# Download dependencies
make deps

# Verify setup
make version
```

### Build

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Build with race detector (development)
make build-dev
```

### Run

```bash
# Run with default config
make run

# Run with go run (faster iteration)
make dev

# Run with custom config
./build/tfo-agent start --config configs/tfo-agent.yaml --log-level debug
```

---

## Project Structure

```
telemetryflow-agent/
├── cmd/
│   └── tfo-agent/          # CLI entry point
│       └── main.go         # Cobra commands setup
├── internal/               # Private packages
│   ├── agent/              # Core agent lifecycle
│   │   └── agent.go        # Agent struct and methods
│   ├── buffer/             # Disk-backed retry buffer
│   │   └── buffer.go       # Buffer implementation
│   ├── collector/          # Telemetry collectors
│   │   └── system/         # System metrics collector
│   │       └── host.go     # CPU, memory, disk, network
│   ├── config/             # Configuration management
│   │   ├── config.go       # Config struct definitions
│   │   └── loader.go       # Config loading with Viper
│   ├── exporter/           # Data exporters
│   │   ├── otlp.go         # OTLP exporter (gRPC/HTTP)
│   │   └── heartbeat.go    # Heartbeat sender
│   └── version/            # Version and branding
│       └── version.go      # Build info and banner
├── pkg/                    # Public packages (LEGO blocks)
│   ├── api/                # HTTP client for backend
│   │   └── client.go       # API client implementation
│   ├── banner/             # ASCII art banner
│   ├── config/             # Config utilities
│   └── plugin/             # Plugin registry
├── configs/                # Configuration templates
│   └── tfo-agent.yaml      # Default configuration
├── tests/                  # Test files
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   ├── e2e/                # End-to-end tests
│   ├── fixtures/           # Test fixtures
│   └── mocks/              # Mock implementations
├── docs/                   # Documentation
├── scripts/                # Build and utility scripts
├── build/                  # Build output directory
├── Makefile                # Build automation
├── Dockerfile              # Container build
├── docker-compose.yml      # Local development stack
├── .golangci.yml           # Linter configuration
└── go.mod                  # Go modules
```

---

## Coding Standards

### Go Style

Follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and [Effective Go](https://golang.org/doc/effective_go).

### Package Comments

Every package should have a package comment:

```go
// Package exporter provides telemetry export functionality for TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
package exporter
```

### Error Handling

```go
// Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to create resource: %w", err)
}

// Use custom error types for specific cases
var ErrMissingEndpoint = errors.New("telemetryflow endpoint is required")
```

### Logging

Use structured logging with zap:

```go
logger.Info("Starting OTLP exporter",
    zap.String("endpoint", cfg.Endpoint),
    zap.String("protocol", cfg.Protocol),
    zap.String("agentId", cfg.AgentID),
)

logger.Error("Failed to export metrics",
    zap.Error(err),
    zap.Int("batchSize", len(metrics)),
)
```

### Thread Safety

Use appropriate synchronization:

```go
type OTLPExporter struct {
    mu      sync.RWMutex
    running bool
    stats   OTLPExporterStats
}

func (e *OTLPExporter) IsRunning() bool {
    e.mu.RLock()
    defer e.mu.RUnlock()
    return e.running
}
```

### Context Usage

Always pass context for cancellation:

```go
func (e *OTLPExporter) Start(ctx context.Context) error {
    // Use context for timeouts and cancellation
    shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    // ...
}
```

---

## Testing

### Running Tests

```bash
# Run all tests
make test                    # Run unit and integration tests
make test-all                # Run unit, integration, and E2E tests
make test-unit               # Run unit tests only
make test-integration        # Run integration tests only
make test-e2e                # Run E2E tests only

# Run tests with race detector (CI mode)
make ci-test

# Run tests with coverage
make test-coverage
```

### Running Specific Tests

Use the `test-specific.sh` script or `make test-run` for targeted test execution:

```bash
# Using make targets
make test-run PKG=integrations                      # Run all integration tests
make test-run PKG=domain/agent                      # Run agent domain tests
make test-run TEST=TestPerconaCollector             # Run test by name pattern
make test-run PKG=integrations TEST=TestKafka       # Run specific test in package
make test-list                                       # List available test packages

# Using test script directly
./scripts/test-specific.sh integrations             # Run all integration tests
./scripts/test-specific.sh domain/agent             # Run agent domain tests
./scripts/test-specific.sh TestPerconaCollector     # Run test by name pattern
./scripts/test-specific.sh integrations:TestKafka   # Run specific test in package
```

### Test Script Options

| Option            | Description                               |
| ----------------- | ----------------------------------------- |
| `-h, --help`      | Show help message                         |
| `-l, --list`      | List all available test packages          |
| `-q, --quiet`     | Quiet mode (no verbose output)            |
| `-c, --coverage`  | Generate coverage report                  |
| `-r, --race`      | Enable race detector                      |
| `-s, --short`     | Run in short mode (skip long tests)       |
| `-t, --timeout`   | Set test timeout (default: 5m)            |
| `-n, --count`     | Run tests N times (default: 1)            |
| `--ci`            | CI mode (race + coverage + 10m timeout)   |

### Test Script Examples

```bash
# Run with coverage
./scripts/test-specific.sh -c infrastructure/buffer

# Run with race detector
./scripts/test-specific.sh -r TestExporter

# Run multiple times to detect flaky tests
./scripts/test-specific.sh -n 5 TestHeartbeat

# CI mode (race detection + coverage)
./scripts/test-specific.sh --ci domain

# Quiet mode with timeout
./scripts/test-specific.sh -q -t 10m integrations
```

### Test Organization

Tests are organized by layer following Domain-Driven Design (DDD):

```
tests/
├── unit/                   # Unit tests (isolated, fast)
│   ├── application/        # CLI and main tests (3 files)
│   ├── domain/             # Domain logic tests
│   │   ├── agent/          # Agent lifecycle tests (2 files)
│   │   ├── plugin/         # Plugin registry tests (1 file)
│   │   └── telemetry/      # Collector tests (2 files)
│   ├── infrastructure/     # Infrastructure tests
│   │   ├── api/            # API client tests (1 file)
│   │   ├── buffer/         # Buffer tests (1 file)
│   │   ├── config/         # Config tests (1 file)
│   │   └── exporter/       # Exporter tests (3 files)
│   ├── integrations/       # 3rd party integration tests (36 files)
│   └── presentation/       # Presentation layer tests
│       └── banner/         # Banner tests (1 file)
├── integration/            # Integration tests (with dependencies)
│   ├── agent/              # Agent integration tests (1 file)
│   └── exporter/           # Exporter integration tests (1 file)
├── e2e/                    # End-to-end tests (full system, 4 files)
├── fixtures/               # Test fixtures and data
│   ├── configs/            # Sample configuration files
│   ├── otlp/               # OTLP test data
│   └── responses/          # Mock API responses
└── mocks/                  # Mock implementations
```

### Available Test Packages

Run `make test-list` or `./scripts/test-specific.sh -l` to see all available packages:

| Package                     | Description                        | Files |
| --------------------------- | ---------------------------------- | ----- |
| `application`               | CLI commands and configuration     | 3     |
| `domain/agent`              | Agent lifecycle management         | 2     |
| `domain/plugin`             | Plugin registry system             | 1     |
| `domain/telemetry`          | Telemetry collection               | 2     |
| `infrastructure/api`        | Backend API client                 | 1     |
| `infrastructure/buffer`     | Disk-backed retry buffer           | 1     |
| `infrastructure/config`     | Configuration loader               | 1     |
| `infrastructure/exporter`   | OTLP exporters (gRPC/HTTP)         | 3     |
| `integrations`              | 3rd party integrations             | 36    |
| `presentation/banner`       | ASCII art startup banner           | 1     |

### Writing Unit Tests

```go
func TestNewOTLPExporter(t *testing.T) {
    t.Run("should create exporter with valid config", func(t *testing.T) {
        cfg := exporter.OTLPExporterConfig{
            AgentID:  "test-agent",
            Endpoint: "localhost:4317",
            Protocol: "grpc",
        }

        exp := exporter.NewOTLPExporter(cfg)
        require.NotNil(t, exp)
        assert.False(t, exp.IsRunning())
    })

    t.Run("should use default protocol when not specified", func(t *testing.T) {
        cfg := exporter.OTLPExporterConfig{
            AgentID:  "test-agent",
            Endpoint: "localhost:4317",
        }

        exp := exporter.NewOTLPExporter(cfg)
        require.NotNil(t, exp)
    })
}
```

### Race Detection

Tests must pass with the race detector:

```bash
# Run with race detection
go test -race -v ./tests/unit/...

# CI uses race detection automatically
make ci-test
```

### Test Coverage

Maintain minimum 80% coverage on critical paths:

```bash
# Generate coverage report
make test-coverage

# View HTML coverage report
go tool cover -html=coverage.out
```

---

## Linting

### Configuration

Linting is configured in `.golangci.yml`:

```yaml
version: "2"

run:
  timeout: 5m
  tests: true

linters:
  default: none
  enable:
    - staticcheck
    - govet
    - errcheck
    - ineffassign
    - unused
```

### Running Linters

```bash
# Run linter
make lint

# Run linter with auto-fix
make lint-fix

# Check formatting
make fmt-check

# Format code
make fmt
```

---

## Continuous Integration

### CI-Specific Makefile Targets

The Makefile provides optimized targets for CI/CD pipelines:

```bash
# Run complete CI pipeline
make ci                      # Runs ci-lint and ci-test

# Individual CI targets
make ci-lint                 # Run linters with CI-specific settings
make ci-test                 # Run tests with race detection and coverage
make ci-build                # Build optimized binary for CI
make ci-release              # Build all platform binaries for release
```

### CI Pipeline Workflow

| Stage   | Command           | Description                              |
| ------- | ----------------- | ---------------------------------------- |
| Lint    | `make ci-lint`    | Run golangci-lint with CI timeout        |
| Test    | `make ci-test`    | Run tests with race detector and timeout |
| Build   | `make ci-build`   | Build optimized production binary        |
| Release | `make ci-release` | Build binaries for all platforms         |

### GitHub Actions

The project uses GitHub Actions for CI/CD with three main workflows:

1. **CI Workflow** (`ci.yml`): Runs on PRs and pushes to main
   - Linting with `make ci-lint`
   - Testing with `make ci-test`
   - Building with `make ci-build`

2. **Docker Workflow** (`docker.yml`): Builds and pushes Docker images
   - Multi-platform builds (linux/amd64, linux/arm64)
   - Automatic tagging based on git tags

3. **Release Workflow** (`release.yml`): Creates releases on tags
   - Cross-platform binaries with `make ci-release`
   - Automatic changelog generation

---

## Dependencies

### Managing Dependencies

```bash
# Add a dependency
go get github.com/example/package@v1.0.0

# Update dependencies
make deps-update

# Tidy modules
make tidy
```

### Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| go.opentelemetry.io/otel | v1.39.0 | OpenTelemetry SDK |
| go.opentelemetry.io/otel/exporters/otlp | v1.39.0 | OTLP exporters |
| github.com/spf13/cobra | v1.9.1 | CLI framework |
| github.com/spf13/viper | v1.20.1 | Configuration |
| go.uber.org/zap | v1.27.0 | Structured logging |
| google.golang.org/grpc | v1.77.0 | gRPC communication |
| github.com/stretchr/testify | v1.10.0 | Testing assertions |

---

## Building

### Local Build

```bash
# Build for current platform
make build

# Output: ./build/tfo-agent
```

### Cross-Platform Build

```bash
# Build for all platforms
make build-all

# Build for specific platform
make build-linux
make build-darwin
make build-windows
```

### Docker Build

```bash
# Build Docker image
make docker-build

# Build with custom tag
docker build -t telemetryflow/telemetryflow-agent:dev .
```

### Build Flags

Version information is injected via ldflags:

```makefile
LDFLAGS := -s -w \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.Version=$(VERSION)' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitCommit=$(GIT_COMMIT)' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.GitBranch=$(GIT_BRANCH)' \
    -X 'github.com/telemetryflow/telemetryflow-agent/internal/version.BuildTime=$(BUILD_TIME)'
```

---

## Debugging

### Debug Logging

```bash
# Run with debug logging
./build/tfo-agent start --config configs/tfo-agent.yaml --log-level debug
```

### Delve Debugger

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug main
dlv debug ./cmd/tfo-agent -- start --config configs/tfo-agent.yaml

# Attach to running process
dlv attach <pid>
```

### pprof Profiling

```bash
# Enable pprof in config
# Then access:
curl http://localhost:8888/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

---

## Git Workflow

### Branch Naming

- `main` - Production-ready code
- `develop` - Integration branch
- `feature/*` - New features
- `fix/*` - Bug fixes
- `release/*` - Release preparation

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add OTLP HTTP exporter support
fix: resolve race condition in heartbeat test
docs: update development guide
test: add unit tests for buffer retry logic
refactor: extract TLS config to helper function
```

### Pull Request Process

1. Create feature branch from `develop`
2. Write code with tests
3. Run `make lint && make ci-test`
4. Create PR with description
5. Address review comments
6. Squash and merge

---

## Release Process

### Version Bumping

```bash
# Update version in internal/version/version.go
const Version = "1.1.2"

# Update CHANGELOG.md
# Create git tag
git tag -a v1.1.2 -m "Release v1.1.2"
git push origin v1.1.2
```

### Creating Release

GitHub Actions automatically builds and publishes releases when a tag is pushed.

---

## Troubleshooting Development Issues

### Common Issues

**Go module issues:**
```bash
go clean -modcache
make deps
```

**Linter cache issues:**
```bash
golangci-lint cache clean
make lint
```

**Test failures with race detector:**
- Ensure thread-safe access to shared state
- Use `sync.Mutex` or `sync/atomic` for concurrent access
- Increase timeouts for timing-sensitive tests

---

## Resources

- [Go Documentation](https://golang.org/doc/)
- [OpenTelemetry Go SDK](https://pkg.go.dev/go.opentelemetry.io/otel)
- [Cobra CLI Documentation](https://cobra.dev/)
- [Zap Logger](https://pkg.go.dev/go.uber.org/zap)

---

**Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.**
