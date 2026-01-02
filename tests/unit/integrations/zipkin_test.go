// package integrations_test provides unit tests for TelemetryFlow Agent Zipkin integration.
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

// Zipkin Exporter Tests
func TestNewZipkinExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.ZipkinConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9411",
	}

	exporter := integrations.NewZipkinExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "zipkin", exporter.Name())
	assert.Equal(t, "tracing", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestZipkinExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.ZipkinConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.ZipkinConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9411",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.ZipkinConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint",
			config: integrations.ZipkinConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewZipkinExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestZipkinExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ZipkinConfig{Enabled: false}
	exporter := integrations.NewZipkinExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestZipkinExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ZipkinConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9411",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Zipkin Export Method Tests
func TestZipkinExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.URL.Path, "/api/v2/spans")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test traces
	traces := []integrations.Trace{
		{
			TraceID:       "zipkin-trace-001",
			SpanID:        "zipkin-span-001",
			OperationName: "zipkin-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
		{
			TraceID:       "zipkin-trace-001",
			SpanID:        "zipkin-span-002",
			ParentSpanID:  "zipkin-span-001",
			OperationName: "zipkin-child-operation",
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

func TestZipkinExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with traces
	data := &integrations.TelemetryData{
		Traces: []integrations.Trace{
			{
				TraceID:       "zipkin-trace-export",
				SpanID:        "zipkin-span-export",
				OperationName: "export-operation",
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

func TestZipkinExporterExportTracesWithError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "zipkin-error-trace",
			SpanID:        "zipkin-error-span",
			OperationName: "error-operation",
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

func TestZipkinExporterExportTracesWithTags(t *testing.T) {
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

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "zipkin-tagged-trace",
			SpanID:        "zipkin-tagged-span",
			OperationName: "tagged-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags: map[string]string{
				"http.method":      "POST",
				"http.status_code": "500",
			},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)

	// Verify the body contains expected data
	assert.NotEmpty(t, receivedBody)
	assert.Contains(t, string(receivedBody), "zipkin-tagged-trace")
	assert.Contains(t, string(receivedBody), "tagged-operation")
}

func TestZipkinExporterExportEmptyTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ZipkinConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9411",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
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

func TestZipkinExporterExportMetricsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    "http://localhost:9411",
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
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
	assert.Contains(t, err.Error(), "zipkin does not support metrics export")
}

func TestZipkinExporterExportLogsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    "http://localhost:9411",
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
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
	assert.Contains(t, err.Error(), "zipkin does not support logs export")
}

// Test config defaults
func TestZipkinConfigDefaults(t *testing.T) {
	t.Run("zipkin defaults", func(t *testing.T) {
		config := integrations.ZipkinConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Endpoint)
	})
}

// Comprehensive Health Tests for Zipkin

func TestZipkinExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/health")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"UP"}`))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
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

func TestZipkinExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 500")
	assert.NotZero(t, status.Latency)
}

func TestZipkinExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 503")
	assert.NotZero(t, status.Latency)
}

func TestZipkinExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
		Timeout:     100 * time.Millisecond,
	}

	exporter := integrations.NewZipkinExporter(config, logger)
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

func TestZipkinExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    "http://localhost:59998/nonexistent",
		ServiceName: "test-service",
		Timeout:     1 * time.Second,
	}

	exporter := integrations.NewZipkinExporter(config, logger)
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

func TestZipkinExporterHealthDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ZipkinConfig{Enabled: false}
	exporter := integrations.NewZipkinExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestZipkinExporterHealthUnauthorized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// StatusCode 401 != 200, so it's considered unhealthy
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 401")
}

func TestZipkinExporterHealthForbidden(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// StatusCode 403 != 200, so it's considered unhealthy
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 403")
}

func TestZipkinExporterHealthBadGateway(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 502")
}

func TestZipkinExporterHealthLatencyMeasurement(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(50))
}

func TestZipkinExporterHealthWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Trace-ID":      "trace-123",
		},
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
}

func TestZipkinExporterHealthContextCancellation(t *testing.T) {
	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
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

func TestZipkinExporterHealthNotFound(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// StatusCode 404 != 200, so it's considered unhealthy
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 404")
}

func TestZipkinExporterHealthEndpointWithTrailingSlash(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL + "/",
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
}

func TestZipkinExporterHealthEndpointWithoutTrailingSlash(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
}

func TestZipkinExporterHealthAcceptedStatus(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// Zipkin Health only considers 200 as healthy
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 202")
}

func TestZipkinExporterHealthWithServiceName(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"UP","zipkin":{"version":"2.24.0"}}`))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "my-custom-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
}

func TestZipkinExporterHealthGatewayTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte("gateway timeout"))
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 504")
}

func TestZipkinExporterHealthNoContent(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "test-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	// Zipkin Health only considers 200 as healthy
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "status: 204")
}

// Benchmark test for Zipkin Health
func BenchmarkZipkinExporterHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ZipkinConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		ServiceName: "benchmark-service",
	}

	exporter := integrations.NewZipkinExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}
