# Integration Tests

Integration tests for the TelemetryFlow Agent testing interactions between components.

## Overview

This directory contains integration tests that verify the interaction between application layer, infrastructure, and external services (API server, network, etc.).

## Test Structure

```text
integration/
├── agent/         # Integration tests for agent lifecycle
└── exporter/      # Integration tests for data export
```

## Running Tests

```bash
# Run all integration tests
go test ./tests/integration/...

# Run specific package tests
go test ./tests/integration/agent/...

# Run with verbose output
go test -v ./tests/integration/...

# Run with coverage
go test -cover ./tests/integration/...

# Run with race detection
go test -race ./tests/integration/...
```

## Test Environment Setup

Integration tests may require external services. Use Docker Compose for consistent test environments:

```bash
# Start test services
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
go test ./tests/integration/...

# Stop test services
docker-compose -f docker-compose.test.yml down
```

## Coverage Targets

- **Agent**: 85% coverage
- **Exporter**: 85% coverage

## Example Test

```go
package agent_test

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.uber.org/zap"

    "github.com/telemetryflow/telemetryflow-agent/internal/agent"
    "github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestAgentStartStop(t *testing.T) {
    cfg := config.DefaultConfig()
    logger, _ := zap.NewDevelopment()

    ag, err := agent.New(cfg, logger)
    require.NoError(t, err)

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Start agent in goroutine
    errChan := make(chan error, 1)
    go func() {
        errChan <- ag.Run(ctx)
    }()

    // Wait a bit then cancel
    time.Sleep(100 * time.Millisecond)
    cancel()

    // Should shutdown gracefully
    err = <-errChan
    assert.NoError(t, err)
}
```

## Best Practices

1. **Test real interactions**: Use actual implementations where possible
2. **Use test containers**: Consider using testcontainers for external services
3. **Clean up**: Always clean up test resources
4. **Test happy and error paths**: Cover both success and failure scenarios
5. **Use timeouts**: Prevent tests from hanging indefinitely
6. **Parallel tests**: Use `t.Parallel()` where safe

## References

- [Testing Documentation](../../docs/TESTING.md)
- [Test Fixtures](../fixtures/)
- [Test Mocks](../mocks/)
