// package integrations_test provides unit tests for TelemetryFlow Agent Alloy integration.
package integrations_test

import (
	"context"
	"encoding/json"
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

// TestNewAlloyExporter tests the creation of a new Alloy exporter
func TestNewAlloyExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
		TenantID: "test-tenant",
	}

	exporter := integrations.NewAlloyExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "alloy", exporter.Name())
	assert.Equal(t, "collector", exporter.Type())
	assert.True(t, exporter.IsEnabled())
	assert.Equal(t, []integrations.DataType{
		integrations.DataTypeMetrics,
		integrations.DataTypeTraces,
		integrations.DataTypeLogs,
	}, exporter.SupportedDataTypes())
}

func TestNewAlloyExporterDisabled(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.AlloyConfig{
		Enabled: false,
	}

	exporter := integrations.NewAlloyExporter(config, logger)

	require.NotNil(t, exporter)
	assert.False(t, exporter.IsEnabled())
}

// TestAlloyExporterInit tests the initialization of the Alloy exporter
func TestAlloyExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.AlloyConfig
		expectError bool
	}{
		{
			name: "valid config with endpoint",
			config: integrations.AlloyConfig{
				Enabled:  true,
				Endpoint: "http://localhost:12345",
			},
			expectError: false,
		},
		{
			name: "valid config with all options",
			config: integrations.AlloyConfig{
				Enabled:       true,
				Endpoint:      "http://localhost:12345",
				TenantID:      "test-tenant",
				Username:      "user",
				Password:      "pass",
				Timeout:       60 * time.Second,
				BatchSize:     500,
				FlushInterval: 5 * time.Second,
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.AlloyConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint when enabled",
			config: integrations.AlloyConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAlloyExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAlloyExporterInitSetsDefaults(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Verify that the exporter was initialized
	assert.True(t, exporter.IsInitialized())
}

// TestAlloyExporterValidate tests the validation of the Alloy configuration
func TestAlloyExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.AlloyConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.AlloyConfig{
				Enabled:  true,
				Endpoint: "http://localhost:12345",
			},
			expectError: false,
		},
		{
			name: "disabled config skips validation",
			config: integrations.AlloyConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint",
			config: integrations.AlloyConfig{
				Enabled: true,
			},
			expectError: true,
		},
		{
			name: "empty endpoint",
			config: integrations.AlloyConfig{
				Enabled:  true,
				Endpoint: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAlloyExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAlloyExporterExport tests the Export method
func TestAlloyExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that accepts OTLP data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read and verify request body is valid JSON
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
		LogsEndpoint:    server.URL + "/v1/logs",
		TracesEndpoint:  server.URL + "/v1/traces",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with metrics, traces, and logs
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "system.cpu.usage",
				Value:     65.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
			},
			{
				Name:      "system.memory.used",
				Value:     4096.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
			},
		},
		Traces: []integrations.Trace{
			{
				TraceID:       "trace-001",
				SpanID:        "span-001",
				OperationName: "api.handler",
				ServiceName:   "test-service",
				StartTime:     time.Now().Add(-200 * time.Millisecond),
				Duration:      200 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"endpoint": "/api/v1/users"},
			},
		},
		Logs: []integrations.LogEntry{
			{
				Timestamp:  time.Now(),
				Level:      integrations.LogLevelInfo,
				Message:    "Request processed successfully",
				Source:     "handler.go",
				Attributes: map[string]string{"request_id": "req-123"},
			},
		},
		Timestamp: time.Now(),
		AgentID:   "agent-001",
		Hostname:  "test-host",
		Tags:      map[string]string{"environment": "test"},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	// Total items: 2 metrics + 1 trace + 1 log = 4
	assert.Equal(t, 4, result.ItemsExported)
}

func TestAlloyExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled: false,
	}

	exporter := integrations.NewAlloyExporter(config, logger)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	assert.Error(t, err)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestAlloyExporterExportOnlyMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric.1", Value: 42.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
			{Name: "test.metric.2", Value: 100.5, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
}

func TestAlloyExporterExportWithError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestAlloyExporterExportMetrics tests the ExportMetrics method
func TestAlloyExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
		ExternalLabels:  map[string]string{"cluster": "test-cluster"},
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "test.metric.cpu",
			Value:     75.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server-01", "env": "test"},
		},
		{
			Name:      "test.metric.memory",
			Value:     1024.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server-01", "env": "test"},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))

	// Verify OTLP format
	var otlpData map[string]interface{}
	err = json.Unmarshal(receivedBody, &otlpData)
	require.NoError(t, err)
	assert.Contains(t, otlpData, "resourceMetrics")
}

func TestAlloyExporterExportMetricsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled: false,
	}

	exporter := integrations.NewAlloyExporter(config, logger)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestAlloyExporterExportMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	// Do not call Init()

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.Equal(t, integrations.ErrNotInitialized, err)
	assert.Nil(t, result)
}

func TestAlloyExporterExportMetricsError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

// TestAlloyExporterExportLogs tests the ExportLogs method
func TestAlloyExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:      true,
		Endpoint:     server.URL,
		LogsEndpoint: server.URL + "/v1/logs",
		Labels:       map[string]string{"app": "test-app"},
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "Application started successfully",
			Source:     "main.go",
			Attributes: map[string]string{"version": "1.0.0", "environment": "test"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelWarn,
			Message:    "High memory usage detected",
			Source:     "monitor.go",
			Attributes: map[string]string{"memory_percent": "85"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelError,
			Message:    "Database connection timeout",
			Source:     "db.go",
			TraceID:    "trace123",
			SpanID:     "span456",
			Attributes: map[string]string{"retry_count": "3"},
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))

	// Verify OTLP format
	var otlpData map[string]interface{}
	err = json.Unmarshal(receivedBody, &otlpData)
	require.NoError(t, err)
	assert.Contains(t, otlpData, "resourceLogs")
}

func TestAlloyExporterExportLogsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled: false,
	}

	exporter := integrations.NewAlloyExporter(config, logger)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test log"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestAlloyExporterExportLogsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	// Do not call Init()

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test log"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.Equal(t, integrations.ErrNotInitialized, err)
	assert.Nil(t, result)
}

func TestAlloyExporterExportLogsError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:      true,
		Endpoint:     server.URL,
		LogsEndpoint: server.URL + "/v1/logs",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test log"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestAlloyExporterExportTraces tests the ExportTraces method
func TestAlloyExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:        true,
		Endpoint:       server.URL,
		TracesEndpoint: server.URL + "/v1/traces",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "abc123def456",
			SpanID:        "span001",
			OperationName: "http.request",
			ServiceName:   "order-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"http.method": "GET", "http.status_code": "200"},
		},
		{
			TraceID:       "abc123def456",
			SpanID:        "span002",
			ParentSpanID:  "span001",
			OperationName: "db.query",
			ServiceName:   "order-service",
			StartTime:     time.Now().Add(-50 * time.Millisecond),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"db.type": "postgresql", "db.statement": "SELECT"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))

	// Verify OTLP format
	var otlpData map[string]interface{}
	err = json.Unmarshal(receivedBody, &otlpData)
	require.NoError(t, err)
	assert.Contains(t, otlpData, "resourceSpans")
}

func TestAlloyExporterExportTracesWithErrorStatus(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:        true,
		Endpoint:       server.URL,
		TracesEndpoint: server.URL + "/v1/traces",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "error-trace-001",
			SpanID:        "error-span-001",
			OperationName: "failed.operation",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags:          map[string]string{"error": "connection timeout"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify the body contains error status
	assert.NotEmpty(t, receivedBody)
	assert.Contains(t, string(receivedBody), "failed.operation")
}

func TestAlloyExporterExportTracesDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled: false,
	}

	exporter := integrations.NewAlloyExporter(config, logger)

	traces := []integrations.Trace{
		{TraceID: "trace-1", SpanID: "span-1", OperationName: "test"},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Error(t, err)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestAlloyExporterExportTracesNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	// Do not call Init()

	traces := []integrations.Trace{
		{TraceID: "trace-1", SpanID: "span-1", OperationName: "test"},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Error(t, err)
	assert.Equal(t, integrations.ErrNotInitialized, err)
	assert.Nil(t, result)
}

func TestAlloyExporterExportTracesError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:        true,
		Endpoint:       server.URL,
		TracesEndpoint: server.URL + "/v1/traces",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{TraceID: "trace-1", SpanID: "span-1", OperationName: "test", StartTime: time.Now(), Duration: time.Millisecond},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestAlloyExporterHealth tests the Health method
func TestAlloyExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/-/healthy")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: server.URL,
		TenantID: "test-tenant",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "200")
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
	assert.Equal(t, "test-tenant", status.Details["tenant_id"])
}

func TestAlloyExporterHealthDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{Enabled: false}
	exporter := integrations.NewAlloyExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestAlloyExporterHealthUnhealthy(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "503")
}

func TestAlloyExporterHealthConnectionError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a closed server to simulate connection failure
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := server.URL
	server.Close() // Close immediately to force connection failure

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: serverURL,
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

// TestAlloyExporterClose tests the Close method
func TestAlloyExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())

	err = exporter.Close(ctx)
	assert.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

func TestAlloyExporterCloseNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	// Do not call Init()

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// TestAlloyExporterAuthHeaders tests authentication header handling
func TestAlloyExporterAuthHeadersBasicAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
		Username:        "testuser",
		Password:        "testpass",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	// Verify Basic auth header was set
	assert.Contains(t, authHeader, "Basic")
}

func TestAlloyExporterAuthHeadersBearerToken(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
		BearerToken:     "my-secret-token",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	// Verify Bearer token header was set
	assert.Equal(t, "Bearer my-secret-token", authHeader)
}

func TestAlloyExporterTenantIDHeader(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var tenantHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantHeader = r.Header.Get("X-Scope-OrgID")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
		TenantID:        "my-tenant",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	// Verify X-Scope-OrgID header was set
	assert.Equal(t, "my-tenant", tenantHeader)
}

func TestAlloyExporterCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var customHeader1, customHeader2 string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customHeader1 = r.Header.Get("X-Custom-Header-1")
		customHeader2 = r.Header.Get("X-Custom-Header-2")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
		Headers: map[string]string{
			"X-Custom-Header-1": "value1",
			"X-Custom-Header-2": "value2",
		},
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	// Verify custom headers were set
	assert.Equal(t, "value1", customHeader1)
	assert.Equal(t, "value2", customHeader2)
}

// TestAlloyExporterEndpointDefaults tests default endpoint behavior
func TestAlloyExporterEndpointDefaults(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	metricsHit := false
	logsHit := false
	tracesHit := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/metrics":
			metricsHit = true
		case "/v1/logs":
			logsHit = true
		case "/v1/traces":
			tracesHit = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Only set the base endpoint, not specific endpoints
	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Export metrics
	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}
	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	// Export logs
	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
	}
	_, err = exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)

	// Export traces
	traces := []integrations.Trace{
		{TraceID: "t1", SpanID: "s1", OperationName: "test", StartTime: time.Now(), Duration: time.Millisecond},
	}
	_, err = exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)

	// Verify all default endpoints were hit
	assert.True(t, metricsHit, "metrics endpoint should be hit")
	assert.True(t, logsHit, "logs endpoint should be hit")
	assert.True(t, tracesHit, "traces endpoint should be hit")
}

// TestAlloyConfigDefaults tests default values
func TestAlloyConfigDefaults(t *testing.T) {
	config := integrations.AlloyConfig{}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.Endpoint)
	assert.Empty(t, config.MetricsEndpoint)
	assert.Empty(t, config.LogsEndpoint)
	assert.Empty(t, config.TracesEndpoint)
	assert.Empty(t, config.TenantID)
	assert.Empty(t, config.Username)
	assert.Empty(t, config.Password)
	assert.Empty(t, config.BearerToken)
	assert.False(t, config.TLSEnabled)
	assert.False(t, config.TLSSkipVerify)
	assert.Zero(t, config.Timeout)
	assert.Zero(t, config.BatchSize)
	assert.Zero(t, config.FlushInterval)
	assert.Nil(t, config.Labels)
	assert.Nil(t, config.Headers)
	assert.Nil(t, config.ExternalLabels)
}

// Benchmark tests
func BenchmarkNewAlloyExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.AlloyConfig{
		Enabled:  true,
		Endpoint: "http://localhost:12345",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewAlloyExporter(config, logger)
	}
}

func BenchmarkAlloyExporterExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL + "/v1/metrics",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := make([]integrations.Metric, 100)
	for i := 0; i < 100; i++ {
		metrics[i] = integrations.Metric{
			Name:      "test.metric",
			Value:     float64(i),
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "test-host"},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkAlloyExporterExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:      true,
		Endpoint:     server.URL,
		LogsEndpoint: server.URL + "/v1/logs",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	_ = exporter.Init(ctx)

	logs := make([]integrations.LogEntry, 100)
	for i := 0; i < 100; i++ {
		logs[i] = integrations.LogEntry{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "test log message",
			Source:     "benchmark",
			Attributes: map[string]string{"index": "value"},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}

func BenchmarkAlloyExporterExportTraces(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.AlloyConfig{
		Enabled:        true,
		Endpoint:       server.URL,
		TracesEndpoint: server.URL + "/v1/traces",
	}

	exporter := integrations.NewAlloyExporter(config, logger)
	_ = exporter.Init(ctx)

	traces := make([]integrations.Trace, 100)
	for i := 0; i < 100; i++ {
		traces[i] = integrations.Trace{
			TraceID:       "trace-id",
			SpanID:        "span-id",
			OperationName: "benchmark.operation",
			ServiceName:   "benchmark-service",
			StartTime:     time.Now(),
			Duration:      time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"index": "value"},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportTraces(ctx, traces)
	}
}
