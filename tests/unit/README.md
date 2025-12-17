# Unit Tests

Unit tests for the TelemetryFlow Agent.

## Overview

This directory contains unit tests for core packages, configuration, version information, and business logic. Unit tests should be isolated from external dependencies using mocks.

## Test Structure

```text
unit/
├── agent/         # Tests for agent core logic
├── buffer/        # Tests for disk-backed buffer
├── collector/     # Tests for metric collectors
├── config/        # Tests for configuration loading and validation
├── exporter/      # Tests for data exporters
└── version/       # Tests for version package
```

## Running Tests

```bash
# Run all unit tests
go test ./tests/unit/...

# Run specific package tests
go test ./tests/unit/config/...

# Run with verbose output
go test -v ./tests/unit/...

# Run with coverage
go test -cover ./tests/unit/...

# Run with coverage report
go test -coverprofile=coverage.out ./tests/unit/...
go tool cover -html=coverage.out -o coverage.html
```

## Coverage Targets

- **Agent**: 90% coverage
- **Buffer**: 85% coverage
- **Collector**: 90% coverage
- **Config**: 95% coverage
- **Exporter**: 85% coverage
- **Version**: 100% coverage

## Test Naming Convention

- Test files: `*_test.go`
- Test functions: `TestFunctionName`
- Subtests: `t.Run("should do something", func(t *testing.T) {})`

## Example Test

```go
package config_test

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestConfigValidation(t *testing.T) {
    t.Run("should return error for missing endpoint", func(t *testing.T) {
        cfg := &config.Config{
            API: config.APIConfig{
                Endpoint: "",
            },
        }

        err := cfg.Validate()
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "endpoint")
    })

    t.Run("should accept valid config", func(t *testing.T) {
        cfg := config.DefaultConfig()

        err := cfg.Validate()
        assert.NoError(t, err)
    })
}
```

## Best Practices

1. **Test in isolation**: Use mocks for all external dependencies
2. **Table-driven tests**: Use table-driven tests for multiple scenarios
3. **Test error paths**: Cover both success and failure scenarios
4. **Use testify**: Use `github.com/stretchr/testify` for assertions
5. **Use mocks**: Import from `tests/mocks/` for mock implementations
6. **Use fixtures**: Import from `tests/fixtures/` for test data

## References

- [Testing Documentation](../../docs/TESTING.md)
- [Test Fixtures](../fixtures/)
- [Test Mocks](../mocks/)
