# Test Fixtures

Test fixtures and sample data for TelemetryFlow Agent tests.

## Overview

This directory contains test fixtures, sample configurations, and test data for use in unit, integration, and E2E tests.

## Available Fixtures

```text
fixtures/
├── configs/           # Sample configuration files
│   ├── valid.yaml     # Valid minimal configuration
│   ├── full.yaml      # Complete configuration with all options
│   └── invalid.yaml   # Invalid configuration for error testing
├── metrics/           # Sample metric data
│   ├── system.json    # Sample system metrics
│   └── process.json   # Sample process metrics
└── responses/         # Mock API responses
    ├── heartbeat.json # Heartbeat response
    └── error.json     # Error response
```

## Usage

```go
package mytest

import (
    "os"
    "testing"
    "path/filepath"
)

func TestWithFixture(t *testing.T) {
    // Load fixture file
    fixturePath := filepath.Join("testdata", "fixtures", "configs", "valid.yaml")
    data, err := os.ReadFile(fixturePath)
    if err != nil {
        t.Fatalf("failed to load fixture: %v", err)
    }

    // Use fixture data in test
    // ...
}
```

## Fixture Categories

### Configuration Fixtures

Sample YAML configuration files for testing config loading:

```yaml
# fixtures/configs/valid.yaml
agent:
  hostname: "test-host"
api:
  endpoint: "http://localhost:3100"
heartbeat:
  interval: 60s
```

### Metric Fixtures

Sample metric data for testing collectors and exporters:

```json
{
  "name": "system_cpu_usage",
  "type": "gauge",
  "value": 45.5,
  "labels": {
    "host": "test-host",
    "cpu": "0"
  }
}
```

### Response Fixtures

Mock API responses for testing client code:

```json
{
  "status": "ok",
  "server_time": "2024-01-15T10:30:00Z",
  "next_interval": 60
}
```

## Best Practices

1. **Keep fixtures minimal**: Include only necessary data
2. **Version fixtures**: Update fixtures when API changes
3. **Document fixtures**: Explain what each fixture tests
4. **Use realistic data**: Use production-like values where possible
5. **Separate by type**: Organize fixtures by their purpose

## References

- [Go Testing](https://golang.org/pkg/testing/)
- [Test Data Best Practices](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)
