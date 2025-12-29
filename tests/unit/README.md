# Unit Tests

Unit tests for the TelemetryFlow Agent, organized following Domain-Driven Design (DDD) patterns.

## Overview

This directory contains unit tests organized by DDD architectural layers. Each layer has specific responsibilities and tests are grouped accordingly to ensure proper separation of concerns.

All tests use external test packages (`package <name>_test`) to ensure proper encapsulation and test the public API surface.

## DDD Architecture

```text
unit/
├── domain/                 # Core business logic and entities
│   ├── agent/              # Agent lifecycle and version management
│   ├── plugin/             # Plugin registry and management
│   └── telemetry/          # Metrics, collectors, and system info
│
├── application/            # Use cases and orchestration
│   ├── cmd_test.go         # CLI commands (root, start, version, config)
│   └── config_test.go      # Configuration loading and validation
│
├── infrastructure/         # External systems and adapters
│   ├── api/                # API client and authentication
│   ├── buffer/             # Disk-backed buffering for offline mode
│   └── exporter/           # OTLP exporters (gRPC/HTTP)
│
└── presentation/           # User interface and output
    └── banner/             # Banner generation and display
```

## DDD Layers Explained

### Domain Layer (`domain/`)

Core business logic independent of external systems:

- **telemetry/** - Metric types, collectors, system information
- **agent/** - Agent lifecycle, version, stats
- **plugin/** - Plugin registry, factory pattern

### Application Layer (`application/`)

Orchestration and use cases:

- **cmd_test.go** - CLI command handling, flags, subcommands
- **config_test.go** - Configuration loading, validation, environment variables

### Infrastructure Layer (`infrastructure/`)

External system adapters:

- **api/** - HTTP client, authentication headers, heartbeat
- **buffer/** - Disk persistence, retry logic
- **exporter/** - OTLP protocol, batch sending

### Presentation Layer (`presentation/`)

User-facing output:

- **banner/** - ASCII art generation, version display

## Running Tests

```bash
# Run all unit tests
go test ./tests/unit/...

# Run by DDD layer
go test ./tests/unit/domain/...
go test ./tests/unit/application/...
go test ./tests/unit/infrastructure/...
go test ./tests/unit/presentation/...

# Run specific domain
go test ./tests/unit/domain/telemetry/...

# Run with verbose output
go test -v ./tests/unit/...

# Run with race detection
go test -race ./tests/unit/...

# Run with coverage
go test -cover ./tests/unit/...

# Run with coverage report
go test -coverprofile=coverage.out ./tests/unit/...
go tool cover -html=coverage.out -o coverage.html
```

## Coverage Targets by Layer

### Domain Layer

| Package   | Target | Description                              |
|-----------|--------|------------------------------------------|
| telemetry | 90%    | Metrics, collectors, system info         |
| agent     | 90%    | Agent lifecycle and version              |
| plugin    | 85%    | Plugin registry and management           |

### Application Layer

| Package     | Target | Description                            |
|-------------|--------|----------------------------------------|
| application | 85%    | CLI commands and configuration         |

### Infrastructure Layer

| Package  | Target | Description                              |
|----------|--------|------------------------------------------|
| api      | 85%    | API client and authentication            |
| buffer   | 85%    | Disk-backed buffering                    |
| exporter | 85%    | OTLP exporters                           |

### Presentation Layer

| Package | Target | Description                               |
|---------|--------|-------------------------------------------|
| banner  | 90%    | Banner generation and display             |

## Test Naming Convention

- Test files: `*_test.go`
- Test functions: `TestFunctionName`
- Subtests: `t.Run("should do something", func(t *testing.T) {})`

## Example Test (Domain Layer)

```go
package telemetry_test

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.uber.org/zap"

    "github.com/telemetryflow/telemetryflow-agent/internal/collector"
    "github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

func TestSystemCollector(t *testing.T) {
    t.Run("should create system collector", func(t *testing.T) {
        logger, _ := zap.NewDevelopment()
        cfg := system.HostCollectorConfig{
            Interval:    15 * time.Second,
            CollectCPU:  true,
            CollectMem:  true,
            Logger:      logger,
        }

        c := system.NewHostCollector(cfg)
        require.NotNil(t, c)
        assert.Equal(t, "system.host", c.Name())
    })

    t.Run("should collect metrics", func(t *testing.T) {
        logger, _ := zap.NewDevelopment()
        c := system.NewHostCollector(system.HostCollectorConfig{
            CollectCPU: true,
            Logger:     logger,
        })

        metrics, err := c.Collect(context.Background())
        require.NoError(t, err)
        assert.NotEmpty(t, metrics)
    })
}
```

## Best Practices

1. **Domain isolation**: Domain tests should not depend on infrastructure
2. **Mock external dependencies**: Use mocks from `tests/mocks/`
3. **Table-driven tests**: Use table-driven tests for multiple scenarios
4. **Test error paths**: Cover both success and failure scenarios
5. **Use testify**: Use `github.com/stretchr/testify` for assertions
6. **External packages**: Use `package <name>_test` pattern for black-box testing
7. **Follow DDD boundaries**: Keep tests within their architectural layer

## References

- [Testing Documentation](../../docs/TESTING.md)
- [Test Fixtures](../fixtures/)
- [Test Mocks](../mocks/)
- [DDD Architecture Guide](../../docs/ARCHITECTURE.md)
