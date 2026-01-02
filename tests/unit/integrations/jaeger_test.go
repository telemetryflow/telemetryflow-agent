// package integrations_test provides unit tests for TelemetryFlow Agent Jaeger integration.
package integrations_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// Jaeger Exporter Tests
func TestNewJaegerExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: "http://localhost:14268",
	}

	exporter := integrations.NewJaegerExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "jaeger", exporter.Name())
	assert.Equal(t, "tracing", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestJaegerExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.JaegerConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.JaegerConfig{
				Enabled:           true,
				CollectorEndpoint: "http://localhost:14268",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.JaegerConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing collector endpoint",
			config: integrations.JaegerConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewJaegerExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestJaegerExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{Enabled: false}
	exporter := integrations.NewJaegerExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestJaegerExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: "http://localhost:14268",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestJaegerExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test traces
	traces := []integrations.Trace{
		{
			TraceID:       "abc123def456",
			SpanID:        "span001",
			OperationName: "test-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
		{
			TraceID:       "abc123def456",
			SpanID:        "span002",
			ParentSpanID:  "span001",
			OperationName: "child-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
}

func TestJaegerExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with traces
	data := &integrations.TelemetryData{
		Traces: []integrations.Trace{
			{
				TraceID:       "trace123",
				SpanID:        "span123",
				OperationName: "main-operation",
				ServiceName:   "test-service",
				StartTime:     time.Now(),
				Duration:      100 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		},
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)
}

func TestJaegerExporterExportTracesWithError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "abc123",
			SpanID:        "span001",
			OperationName: "test-op",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestJaegerExporterExportTracesWithTags(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "trace-with-tags",
			SpanID:        "span-tagged",
			OperationName: "tagged-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags: map[string]string{
				"http.method": "GET",
				"http.url":    "/api/test",
			},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)

	// Verify the body contains expected data
	assert.NotEmpty(t, receivedBody)
	assert.Contains(t, string(receivedBody), "trace-with-tags")
	assert.Contains(t, string(receivedBody), "tagged-operation")
}

func TestJaegerExporterExportEmptyTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: "http://localhost:14268",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Export with empty TelemetryData
	data := &integrations.TelemetryData{
		Traces: []integrations.Trace{},
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestJaegerExporterExportMetricsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: "http://localhost:14268",
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "test.metric.gauge",
			Value:     42.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "jaeger does not support metrics export")
}

func TestJaegerExporterExportLogsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: "http://localhost:14268",
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log message",
			Source:    "test-source",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "jaeger does not support logs export")
}

// Test Jaeger config defaults
func TestJaegerConfigDefaults(t *testing.T) {
	config := integrations.JaegerConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.CollectorEndpoint)
}

// Comprehensive Health Tests for Jaeger

func TestJaegerExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 200")
	assert.NotZero(t, status.Latency)
	assert.NotZero(t, status.LastCheck)
}

func TestJaegerExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 500")
	assert.NotZero(t, status.Latency)
	assert.NotZero(t, status.LastCheck)
}

func TestJaegerExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 503")
	assert.NotZero(t, status.Latency)
}

func TestJaegerExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
		Timeout:           100 * time.Millisecond,
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	ctx := context.Background()
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestJaegerExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: "http://localhost:59999/nonexistent",
		ServiceName:       "test-service",
		Timeout:           1 * time.Second,
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.LastCheck)
}

func TestJaegerExporterHealthAgentMode(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{
		Enabled:   true,
		AgentHost: "localhost",
		AgentPort: 6831,
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "agent configured at localhost:6831")
	assert.NotZero(t, status.LastCheck)
}

func TestJaegerExporterHealthAgentModeDefaultPort(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{
		Enabled:   true,
		AgentHost: "jaeger-agent.monitoring.svc",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "agent configured at jaeger-agent.monitoring.svc:6831")
}

func TestJaegerExporterHealthDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.JaegerConfig{Enabled: false}
	exporter := integrations.NewJaegerExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestJaegerExporterHealthWithBasicAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
		Username:          "jaeger-user",
		Password:          "jaeger-password",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 200")
}

func TestJaegerExporterHealthUnauthorized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// StatusCode 401 < 500, so it's considered healthy in terms of connectivity
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 401")
}

func TestJaegerExporterHealthForbidden(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// StatusCode 403 < 500, so it's considered healthy in terms of connectivity
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 403")
}

func TestJaegerExporterHealthBadGateway(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway"))
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 502")
}

func TestJaegerExporterHealthLatencyMeasurement(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(50))
}

func TestJaegerExporterHealthWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Tenant-ID":     "tenant-123",
		},
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
}

func TestJaegerExporterHealthContextCancellation(t *testing.T) {
	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	ctx := context.Background()
	err := exporter.Init(ctx)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
}

func TestJaegerExporterHealthAcceptedStatus(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 202")
}

func TestJaegerExporterHealthNotFound(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "test-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// StatusCode 404 < 500, so it's considered healthy in terms of connectivity
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 404")
}

// Benchmark test for Jaeger Health
func BenchmarkJaegerExporterHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.JaegerConfig{
		Enabled:           true,
		CollectorEndpoint: server.URL,
		ServiceName:       "benchmark-service",
	}

	exporter := integrations.NewJaegerExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}
