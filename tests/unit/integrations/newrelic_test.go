// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"compress/gzip"
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

// NewNewRelicExporter Tests
func TestNewNewRelicExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
		Region:     "US",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "newrelic", exporter.Name())
	assert.Equal(t, "apm", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestNewNewRelicExporterDisabled(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.NewRelicConfig{
		Enabled: false,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "newrelic", exporter.Name())
	assert.False(t, exporter.IsEnabled())
}

func TestNewNewRelicExporterSupportedDataTypes(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)

	supportedTypes := exporter.SupportedDataTypes()
	require.Len(t, supportedTypes, 3)
	assert.Contains(t, supportedTypes, integrations.DataTypeMetrics)
	assert.Contains(t, supportedTypes, integrations.DataTypeTraces)
	assert.Contains(t, supportedTypes, integrations.DataTypeLogs)
}

// Init Tests
func TestNewRelicExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.NewRelicConfig
		expectError bool
	}{
		{
			name: "valid config with license key",
			config: integrations.NewRelicConfig{
				Enabled:    true,
				LicenseKey: "1234567890123456789012345678901234567890",
			},
			expectError: false,
		},
		{
			name: "valid config with insights insert key",
			config: integrations.NewRelicConfig{
				Enabled:           true,
				InsightsInsertKey: "some-insights-insert-key",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.NewRelicConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing license key and insights key",
			config: integrations.NewRelicConfig{
				Enabled: true,
			},
			expectError: true,
		},
		{
			name: "license key too short",
			config: integrations.NewRelicConfig{
				Enabled:    true,
				LicenseKey: "short-key",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewNewRelicExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewRelicExporterInitSetsDefaults(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())
}

func TestNewRelicExporterInitWithEURegion(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
		Region:     "EU",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())
}

// Validate Tests
func TestNewRelicExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.NewRelicConfig
		expectError bool
	}{
		{
			name: "valid with license key",
			config: integrations.NewRelicConfig{
				Enabled:    true,
				LicenseKey: "1234567890123456789012345678901234567890",
			},
			expectError: false,
		},
		{
			name: "valid with insights insert key",
			config: integrations.NewRelicConfig{
				Enabled:           true,
				InsightsInsertKey: "any-valid-insights-key",
			},
			expectError: false,
		},
		{
			name: "disabled - skips validation",
			config: integrations.NewRelicConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing both keys",
			config: integrations.NewRelicConfig{
				Enabled: true,
			},
			expectError: true,
		},
		{
			name: "license key too short",
			config: integrations.NewRelicConfig{
				Enabled:    true,
				LicenseKey: "too-short",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewNewRelicExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Export Tests
func TestNewRelicExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that returns 202 Accepted for all endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request has correct headers
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "1234567890123456789012345678901234567890", r.Header.Get("Api-Key"))

		// Read and verify request body is valid JSON
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
		ServiceName:     "test-service",
		Environment:     "test",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
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

func TestNewRelicExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled: false,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotEnabled, err)
}

func TestNewRelicExporterExportWithError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// ExportMetrics Tests
func TestNewRelicExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has the correct headers
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "1234567890123456789012345678901234567890", r.Header.Get("Api-Key"))

		// Read request body
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, receivedBody)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
		ServiceName:     "test-service",
		Environment:     "test",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
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

	// Verify the request body contains expected metric data
	assert.Contains(t, string(receivedBody), "test.metric.cpu")
	assert.Contains(t, string(receivedBody), "test.metric.memory")
}

func TestNewRelicExporterExportMetricsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled: false,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)

	metrics := []integrations.Metric{
		{Name: "test", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotEnabled, err)
}

func TestNewRelicExporterExportMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	// Note: Not calling Init()

	metrics := []integrations.Metric{
		{Name: "test", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotInitialized, err)
}

func TestNewRelicExporterExportMetricsWithError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
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

func TestNewRelicExporterExportMetricsWithServiceNameAndEnvironment(t *testing.T) {
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

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
		ServiceName:     "my-service",
		Environment:     "production",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify service.name and environment are included in attributes
	assert.Contains(t, string(receivedBody), "service.name")
	assert.Contains(t, string(receivedBody), "my-service")
	assert.Contains(t, string(receivedBody), "environment")
	assert.Contains(t, string(receivedBody), "production")
}

// ExportLogs Tests
func TestNewRelicExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has the correct headers
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "1234567890123456789012345678901234567890", r.Header.Get("Api-Key"))

		// Read request body
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, receivedBody)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:      true,
		LicenseKey:   "1234567890123456789012345678901234567890",
		LogsEndpoint: server.URL,
		ServiceName:  "test-service",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
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

	// Verify the request body contains expected log data
	assert.Contains(t, string(receivedBody), "Application started successfully")
	assert.Contains(t, string(receivedBody), "High memory usage detected")
	assert.Contains(t, string(receivedBody), "Database connection timeout")
}

func TestNewRelicExporterExportLogsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled: false,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotEnabled, err)
}

func TestNewRelicExporterExportLogsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	// Note: Not calling Init()

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotInitialized, err)
}

func TestNewRelicExporterExportLogsWithError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:      true,
		LicenseKey:   "1234567890123456789012345678901234567890",
		LogsEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
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

// ExportTraces Tests
func TestNewRelicExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has the correct headers
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "1234567890123456789012345678901234567890", r.Header.Get("Api-Key"))

		// Read request body
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, receivedBody)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:        true,
		LicenseKey:     "1234567890123456789012345678901234567890",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
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

	// Verify the request body contains expected trace data
	assert.Contains(t, string(receivedBody), "abc123def456")
	assert.Contains(t, string(receivedBody), "http.request")
	assert.Contains(t, string(receivedBody), "db.query")
}

func TestNewRelicExporterExportTracesDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled: false,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)

	traces := []integrations.Trace{
		{
			TraceID:       "trace123",
			SpanID:        "span123",
			OperationName: "test",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotEnabled, err)
}

func TestNewRelicExporterExportTracesNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	// Note: Not calling Init()

	traces := []integrations.Trace{
		{
			TraceID:       "trace123",
			SpanID:        "span123",
			OperationName: "test",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotInitialized, err)
}

func TestNewRelicExporterExportTracesWithError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:        true,
		LicenseKey:     "1234567890123456789012345678901234567890",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "trace123",
			SpanID:        "span123",
			OperationName: "test",
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

func TestNewRelicExporterExportTracesWithParentSpanAndError(t *testing.T) {
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

	config := integrations.NewRelicConfig{
		Enabled:        true,
		LicenseKey:     "1234567890123456789012345678901234567890",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "trace-with-parent",
			SpanID:        "child-span",
			ParentSpanID:  "parent-span",
			OperationName: "child-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusError,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)

	// Verify parent.id is included for child span
	assert.Contains(t, string(receivedBody), "parent.id")
	assert.Contains(t, string(receivedBody), "parent-span")
	// Verify error is set for error status
	assert.Contains(t, string(receivedBody), "error")
}

// Health Tests
func TestNewRelicExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{Enabled: false}
	exporter := integrations.NewNewRelicExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestNewRelicExporterHealthEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that returns 200 OK for OPTIONS request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "OPTIONS", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "endpoint reachable", status.Message)
	assert.NotNil(t, status.Details)
	assert.Contains(t, status.Details, "region")
}

func TestNewRelicExporterHealthConnectionFailed(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a non-existent server URL
	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: "http://localhost:59999/non-existent",
		Timeout:         1 * time.Second,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

// Close Tests
func TestNewRelicExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())

	err = exporter.Close(ctx)
	assert.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

func TestNewRelicExporterCloseWithoutInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	// Note: Not calling Init()

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Authentication Headers Tests
func TestNewRelicExporterUsesLicenseKeyHeader(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("Api-Key")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	assert.Equal(t, "1234567890123456789012345678901234567890", receivedHeader)
}

func TestNewRelicExporterUsesInsightsInsertKeyHeader(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Insert-Key")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:           true,
		InsightsInsertKey: "my-insights-insert-key",
		MetricsEndpoint:   server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	assert.Equal(t, "my-insights-insert-key", receivedHeader)
}

// Compression Tests
func TestNewRelicExporterExportMetricsWithCompression(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	var contentEncoding string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentEncoding = r.Header.Get("Content-Encoding")

		// Read the gzipped body
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
		Compression:     true,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify Content-Encoding header is set to gzip
	assert.Equal(t, "gzip", contentEncoding)

	// Verify the body is actually gzip compressed (starts with gzip magic number)
	assert.True(t, len(receivedBody) >= 2)
	assert.Equal(t, byte(0x1f), receivedBody[0])
	assert.Equal(t, byte(0x8b), receivedBody[1])

	// Decompress and verify the content
	reader, err := gzip.NewReader(io.NopCloser(io.Reader(io.NopCloser(
		&readCloser{data: receivedBody}))))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Contains(t, string(decompressed), "test.metric")
}

// readCloser is a helper for gzip testing
type readCloser struct {
	data   []byte
	offset int
}

func (r *readCloser) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *readCloser) Close() error {
	return nil
}

// Custom Headers Tests
func TestNewRelicExporterExportMetricsWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Another":       "another-value",
		},
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "another-value", receivedHeaders.Get("X-Another"))
}

// Test config defaults
func TestNewRelicConfigDefaults(t *testing.T) {
	config := integrations.NewRelicConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.LicenseKey)
	assert.Empty(t, config.InsightsInsertKey)
	assert.Empty(t, config.AccountID)
	assert.Empty(t, config.Region)
	assert.Empty(t, config.MetricsEndpoint)
	assert.Empty(t, config.LogsEndpoint)
	assert.Empty(t, config.TracesEndpoint)
	assert.Zero(t, config.Timeout)
	assert.Zero(t, config.BatchSize)
	assert.Zero(t, config.FlushInterval)
	assert.False(t, config.Compression)
	assert.Empty(t, config.ServiceName)
	assert.Empty(t, config.Environment)
	assert.Nil(t, config.Headers)
}

// Table-driven tests for various HTTP status codes
func TestNewRelicExporterExportMetricsHTTPStatusCodes(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name         string
		statusCode   int
		responseBody string
		expectError  bool
	}{
		{
			name:         "200 OK",
			statusCode:   http.StatusOK,
			responseBody: "{}",
			expectError:  false,
		},
		{
			name:         "202 Accepted",
			statusCode:   http.StatusAccepted,
			responseBody: "{}",
			expectError:  false,
		},
		{
			name:         "400 Bad Request",
			statusCode:   http.StatusBadRequest,
			responseBody: "bad request",
			expectError:  true,
		},
		{
			name:         "401 Unauthorized",
			statusCode:   http.StatusUnauthorized,
			responseBody: "unauthorized",
			expectError:  true,
		},
		{
			name:         "403 Forbidden",
			statusCode:   http.StatusForbidden,
			responseBody: "forbidden",
			expectError:  true,
		},
		{
			name:         "429 Too Many Requests",
			statusCode:   http.StatusTooManyRequests,
			responseBody: "rate limited",
			expectError:  true,
		},
		{
			name:         "500 Internal Server Error",
			statusCode:   http.StatusInternalServerError,
			responseBody: "internal server error",
			expectError:  true,
		},
		{
			name:         "503 Service Unavailable",
			statusCode:   http.StatusServiceUnavailable,
			responseBody: "service unavailable",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			config := integrations.NewRelicConfig{
				Enabled:         true,
				LicenseKey:      "1234567890123456789012345678901234567890",
				MetricsEndpoint: server.URL,
			}

			exporter := integrations.NewNewRelicExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)

			metrics := []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
			}

			result, err := exporter.ExportMetrics(ctx, metrics)

			if tt.expectError {
				assert.Error(t, err)
				require.NotNil(t, result)
				assert.False(t, result.Success)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.True(t, result.Success)
			}
		})
	}
}

// Test JSON payload structure
func TestNewRelicExporterMetricsPayloadStructure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
		ServiceName:     "test-service",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	timestamp := time.Now()
	metrics := []integrations.Metric{
		{
			Name:      "cpu.usage",
			Value:     75.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: timestamp,
			Tags:      map[string]string{"host": "server-01"},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify payload structure
	require.Len(t, receivedPayload, 1)
	metricsWrapper := receivedPayload[0]
	metricsArray, ok := metricsWrapper["metrics"].([]interface{})
	require.True(t, ok)
	require.Len(t, metricsArray, 1)

	metric := metricsArray[0].(map[string]interface{})
	assert.Equal(t, "cpu.usage", metric["name"])
	assert.Equal(t, 75.5, metric["value"])
	assert.Equal(t, "gauge", metric["type"])
	assert.Equal(t, float64(timestamp.UnixMilli()), metric["timestamp"])

	attrs := metric["attributes"].(map[string]interface{})
	assert.Equal(t, "server-01", attrs["host"])
	assert.Equal(t, "test-service", attrs["service.name"])
}

// Test log payload structure
func TestNewRelicExporterLogsPayloadStructure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:      true,
		LicenseKey:   "1234567890123456789012345678901234567890",
		LogsEndpoint: server.URL,
		ServiceName:  "test-service",
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	timestamp := time.Now()
	logs := []integrations.LogEntry{
		{
			Timestamp:  timestamp,
			Level:      integrations.LogLevelError,
			Message:    "Test error message",
			Source:     "test.go",
			Attributes: map[string]string{"request_id": "req-123"},
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify payload structure
	require.Len(t, receivedPayload, 1)
	logsWrapper := receivedPayload[0]
	logsArray, ok := logsWrapper["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, logsArray, 1)

	log := logsArray[0].(map[string]interface{})
	assert.Equal(t, "Test error message", log["message"])
	assert.Equal(t, float64(timestamp.UnixMilli()), log["timestamp"])

	attrs := log["attributes"].(map[string]interface{})
	assert.Equal(t, "error", attrs["level"])
	assert.Equal(t, "test.go", attrs["source"])
	assert.Equal(t, "req-123", attrs["request_id"])
	assert.Equal(t, "test-service", attrs["service.name"])
}

// Test traces payload structure
func TestNewRelicExporterTracesPayloadStructure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:        true,
		LicenseKey:     "1234567890123456789012345678901234567890",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	startTime := time.Now()
	duration := 100 * time.Millisecond
	traces := []integrations.Trace{
		{
			TraceID:       "trace-abc-123",
			SpanID:        "span-xyz-789",
			ParentSpanID:  "parent-span-456",
			OperationName: "http.handler",
			ServiceName:   "api-service",
			StartTime:     startTime,
			Duration:      duration,
			Status:        integrations.TraceStatusError,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify payload structure
	require.Len(t, receivedPayload, 1)
	spansWrapper := receivedPayload[0]
	spansArray, ok := spansWrapper["spans"].([]interface{})
	require.True(t, ok)
	require.Len(t, spansArray, 1)

	span := spansArray[0].(map[string]interface{})
	assert.Equal(t, "trace-abc-123", span["trace.id"])
	assert.Equal(t, "span-xyz-789", span["id"])
	assert.Equal(t, "parent-span-456", span["parent.id"])
	assert.Equal(t, "http.handler", span["name"])
	assert.Equal(t, float64(startTime.UnixMilli()), span["timestamp"])
	assert.Equal(t, float64(duration.Milliseconds()), span["duration.ms"])
	assert.Equal(t, true, span["error"])

	attrs := span["attributes"].(map[string]interface{})
	assert.Equal(t, "api-service", attrs["service.name"])
}

// Benchmark tests
func BenchmarkNewNewRelicExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.NewRelicConfig{
		Enabled:    true,
		LicenseKey: "1234567890123456789012345678901234567890",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewNewRelicExporter(config, logger)
	}
}

func BenchmarkNewRelicExporterExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:         true,
		LicenseKey:      "1234567890123456789012345678901234567890",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := make([]integrations.Metric, 100)
	for i := 0; i < 100; i++ {
		metrics[i] = integrations.Metric{
			Name:      "test.metric",
			Value:     float64(i),
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkNewRelicExporterExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:      true,
		LicenseKey:   "1234567890123456789012345678901234567890",
		LogsEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	_ = exporter.Init(ctx)

	logs := make([]integrations.LogEntry, 100)
	for i := 0; i < 100; i++ {
		logs[i] = integrations.LogEntry{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log message",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}

func BenchmarkNewRelicExporterExportTraces(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	config := integrations.NewRelicConfig{
		Enabled:        true,
		LicenseKey:     "1234567890123456789012345678901234567890",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewNewRelicExporter(config, logger)
	_ = exporter.Init(ctx)

	traces := make([]integrations.Trace, 100)
	for i := 0; i < 100; i++ {
		traces[i] = integrations.Trace{
			TraceID:       "trace-123",
			SpanID:        "span-456",
			OperationName: "test-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportTraces(ctx, traces)
	}
}
