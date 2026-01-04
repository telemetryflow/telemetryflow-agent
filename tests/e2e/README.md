# End-to-End Tests

End-to-end tests for the TelemetryFlow Agent testing complete workflows.

## Overview

This directory contains E2E tests that verify complete agent workflows including startup, data collection, export to backend, and graceful shutdown.

## Test Structure

```text
e2e/
├── startup_test.go      # Tests for agent startup scenarios
├── collection_test.go   # Tests for metric collection workflows
├── export_test.go       # Tests for data export to backend
└── shutdown_test.go     # Tests for graceful shutdown
```

## Running Tests

```bash
# Run all E2E tests
go test ./tests/e2e/...

# Run with verbose output
go test -v ./tests/e2e/...

# Run specific test
go test -v ./tests/e2e/... -run TestStartup

# Run with timeout (E2E tests may take longer)
go test -timeout 5m ./tests/e2e/...
```

## Test Environment Setup

E2E tests require a complete test environment:

```bash
# Start all required services
docker-compose -f docker-compose.e2e.yml up -d

# Wait for services to be ready
./scripts/wait-for-services.sh

# Run E2E tests
go test -v ./tests/e2e/...

# Stop services
docker-compose -f docker-compose.e2e.yml down
```

## Required Services

- TelemetryFlow Backend API (for heartbeat/export)
- Mock OTLP receiver (for telemetry validation)

## Example Test

```go
package e2e_test

import (
    "context"
    "os/exec"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestAgentE2EWorkflow(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping E2E test in short mode")
    }

    // Build agent binary
    cmd := exec.Command("go", "build", "-o", "tfo-agent", "./cmd/tfo-agent")
    err := cmd.Run()
    require.NoError(t, err)

    // Start agent with test config
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    agentCmd := exec.CommandContext(ctx, "./tfo-agent", "start", "-c", "testdata/config.yaml")
    err = agentCmd.Start()
    require.NoError(t, err)

    // Wait for agent to start
    time.Sleep(2 * time.Second)

    // Verify agent is sending heartbeats
    // ... (check backend API for heartbeat)

    // Verify metrics are being collected
    // ... (check OTLP receiver for metrics)

    // Send shutdown signal
    agentCmd.Process.Signal(os.Interrupt)

    // Wait for graceful shutdown
    err = agentCmd.Wait()
    assert.NoError(t, err)
}
```

## Best Practices

1. **Skip in short mode**: Use `testing.Short()` to skip in CI fast runs
2. **Use real binaries**: Test the actual compiled binary
3. **Test complete workflows**: From startup to shutdown
4. **Verify external effects**: Check backend received expected data
5. **Use reasonable timeouts**: E2E tests need longer timeouts
6. **Clean up resources**: Always clean up test artifacts

## References

- [Testing Documentation](../../docs/TESTING.md)
- [Test Data](./testdata/)
