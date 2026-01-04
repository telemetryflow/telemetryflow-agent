# Test Mocks

Mock implementations for testing the TelemetryFlow Agent.

## Overview

This directory contains mock implementations of interfaces and external dependencies for use in unit and integration tests.

## Available Mocks

```text
mocks/
├── api_client.go       # Mock API client
├── collector.go        # Mock metric collector
├── exporter.go         # Mock data exporter
└── logger.go           # Mock logger
```

## Usage

```go
package mytest

import (
    "testing"
    "github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

func TestWithMock(t *testing.T) {
    mockClient := mocks.NewMockAPIClient()
    mockClient.On("SendHeartbeat", mock.Anything).Return(nil)

    // Use mockClient in your test
    // ...

    mockClient.AssertExpectations(t)
}
```

## Mock Generation

Mocks are generated using `mockery`:

```bash
# Install mockery
go install github.com/vektra/mockery/v2@latest

# Generate mocks
mockery --name=APIClient --dir=pkg/api --output=tests/mocks
mockery --name=Collector --dir=internal/collector --output=tests/mocks
```

## Best Practices

1. **Use interfaces**: Mock interfaces, not concrete types
2. **Keep mocks simple**: Only mock what's needed for the test
3. **Verify expectations**: Use `AssertExpectations` to verify mock calls
4. **Reset between tests**: Reset mock state between test cases
5. **Document behavior**: Comment mock methods explaining their behavior

## Mock Types

### MockAPIClient

```go
type MockAPIClient struct {
    mock.Mock
}

func (m *MockAPIClient) SendHeartbeat(ctx context.Context, req *HeartbeatRequest) error {
    args := m.Called(ctx, req)
    return args.Error(0)
}
```

### MockCollector

```go
type MockCollector struct {
    mock.Mock
}

func (m *MockCollector) Collect(ctx context.Context) ([]Metric, error) {
    args := m.Called(ctx)
    return args.Get(0).([]Metric), args.Error(1)
}
```

## References

- [Testify Mock](https://github.com/stretchr/testify#mock-package)
- [Mockery](https://github.com/vektra/mockery)
