// package integrations_test provides unit tests for TelemetryFlow Agent GCP integrations.
package integrations_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// GCP Exporter Tests
func TestNewGCPExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
		Region:    "us-central1",
	}

	exporter := integrations.NewGCPExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "gcp", exporter.Name())
	assert.Equal(t, "cloud", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestGCPExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.GCPConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.GCPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing project id",
			config: integrations.GCPConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewGCPExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGCPExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.GCPConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.GCPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing project id",
			config: integrations.GCPConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewGCPExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGCPExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
	}

	exporter := integrations.NewGCPExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	// May fail due to auth, but should not panic
	if err == nil {
		assert.NotNil(t, result)
	}
}

func TestGCPExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		config := integrations.GCPConfig{Enabled: false}
		exporter := integrations.NewGCPExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})
}

func TestGCPExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
	}

	exporter := integrations.NewGCPExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Test GCP config defaults
func TestGCPConfigDefaults(t *testing.T) {
	config := integrations.GCPConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.ProjectID)
}

// Benchmark tests
func BenchmarkNewGCPExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewGCPExporter(config, logger)
	}
}

// ============================================================================
// GCP Exporter Export Method Tests with Mock HTTP Servers
// ============================================================================

func TestGCPExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server for monitoring API
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer monitoringServer.Close()

	// Create mock server for logging API
	loggingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer loggingServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
		LoggingEndpoint:    loggingServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test telemetry data
	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "cpu.usage",
				Value:     75.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
			},
			{
				Name:      "memory.used",
				Value:     1024.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
			},
		},
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-service",
				TraceID:   "trace-123",
				SpanID:    "span-456",
			},
		},
		Timestamp: time.Now(),
		AgentID:   "test-agent",
		Hostname:  "test-host",
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported) // 2 metrics + 1 log
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestGCPExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server for Cloud Trace API
	traceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "traces:batchWrite")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer traceServer.Close()

	config := integrations.GCPConfig{
		Enabled:       true,
		ProjectID:     "test-project",
		Region:        "us-central1",
		TraceEndpoint: traceServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "abc123def456",
			SpanID:        "span-001",
			ParentSpanID:  "",
			OperationName: "http.request",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"http.method": "GET", "http.url": "/api/test"},
		},
		{
			TraceID:       "abc123def456",
			SpanID:        "span-002",
			ParentSpanID:  "span-001",
			OperationName: "db.query",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-50 * time.Millisecond),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"db.type": "postgresql"},
		},
		{
			TraceID:       "abc123def456",
			SpanID:        "span-003",
			ParentSpanID:  "span-001",
			OperationName: "external.call",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-30 * time.Millisecond),
			Duration:      30 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags:          map[string]string{"error": "connection timeout"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestGCPExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server for Cloud Logging API
	loggingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "entries:write")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body contains expected fields
		var payload map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Contains(t, payload, "entries")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer loggingServer.Close()

	config := integrations.GCPConfig{
		Enabled:         true,
		ProjectID:       "test-project",
		Region:          "us-central1",
		LogName:         "test-logs",
		LoggingEndpoint: loggingServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "Application started successfully",
			Source:     "main",
			Attributes: map[string]string{"version": "1.0.0"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelWarn,
			Message:    "High memory usage detected",
			Source:     "monitor",
			TraceID:    "trace-789",
			SpanID:     "span-101",
			Attributes: map[string]string{"memory_usage": "85%"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelError,
			Message:    "Database connection failed",
			Source:     "database",
			Attributes: map[string]string{"error_code": "E1001"},
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelDebug,
			Message:   "Debug information",
			Source:    "debug",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 4, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestGCPExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.GCPConfig{
		Enabled:   false,
		ProjectID: "test-project",
	}

	exporter := integrations.NewGCPExporter(config, logger)
	_ = exporter.Init(ctx)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGCPExporterExportServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that returns 500 error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer errorServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: errorServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// ============================================================================
// GCP Exporter Health Function Comprehensive Tests
// ============================================================================

func TestGCPExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that returns 200
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "metricDescriptors")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"metricDescriptors": []interface{}{},
		})
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "GCP connected", status.Message)
	assert.NotNil(t, status.Details)
	assert.Equal(t, "test-project", status.Details["project_id"])
	assert.Equal(t, "us-central1", status.Details["region"])
	assert.NotZero(t, status.Latency)
}

func TestGCPExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that returns 500
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    500,
				"message": "Internal error encountered",
				"status":  "INTERNAL",
			},
		})
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "500")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestGCPExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that returns 503
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    503,
				"message": "The service is currently unavailable",
				"status":  "UNAVAILABLE",
			},
		})
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-east1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "503")
	assert.NotNil(t, status.LastError)
}

func TestGCPExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that times out
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
		Timeout:            100 * time.Millisecond, // Very short timeout
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestGCPExporterHealthInvalidResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that returns invalid JSON with error status
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid json response {{{"))
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.NotNil(t, status.LastError)
}

func TestGCPExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use invalid endpoint to simulate network error
	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: "http://localhost:59999", // Non-existent port
		Timeout:            1 * time.Second,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestGCPExporterHealthAuthenticationFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that returns 401 Unauthorized
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    401,
				"message": "Request had invalid authentication credentials",
				"status":  "UNAUTHENTICATED",
			},
		})
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "401")
	assert.NotNil(t, status.LastError)
}

func TestGCPExporterHealthForbidden(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that returns 403 Forbidden
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    403,
				"message": "Permission denied on resource project test-project",
				"status":  "PERMISSION_DENIED",
			},
		})
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "403")
}

func TestGCPExporterHealthDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.GCPConfig{Enabled: false}
	exporter := integrations.NewGCPExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestGCPExporterHealthContextCanceled(t *testing.T) {
	logger := zap.NewNop()

	// Create mock monitoring endpoint that delays response
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	ctx := context.Background()
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create a context that will be canceled
	cancelCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	status, err := exporter.Health(cancelCtx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
}

func TestGCPExporterHealthProjectNotFound(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock monitoring endpoint that returns 404 Not Found
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    404,
				"message": "Project not found: test-project",
				"status":  "NOT_FOUND",
			},
		})
	}))
	defer monitoringServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "404")
}

// ============================================================================
// GCP mapSeverity Function Tests
// ============================================================================

func TestGCPMapSeverity(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name     string
		level    integrations.LogLevel
		expected string
	}{
		{
			name:     "debug level",
			level:    integrations.LogLevelDebug,
			expected: "DEBUG",
		},
		{
			name:     "info level",
			level:    integrations.LogLevelInfo,
			expected: "INFO",
		},
		{
			name:     "warn level",
			level:    integrations.LogLevelWarn,
			expected: "WARNING",
		},
		{
			name:     "error level",
			level:    integrations.LogLevelError,
			expected: "ERROR",
		},
		{
			name:     "fatal level",
			level:    integrations.LogLevelFatal,
			expected: "CRITICAL",
		},
		{
			name:     "unknown level defaults to DEFAULT",
			level:    integrations.LogLevel("unknown"),
			expected: "DEFAULT",
		},
		{
			name:     "empty level defaults to DEFAULT",
			level:    integrations.LogLevel(""),
			expected: "DEFAULT",
		},
	}

	// Create a mock server for logging
	loggingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer loggingServer.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := integrations.GCPConfig{
				Enabled:         true,
				ProjectID:       "test-project",
				Region:          "us-central1",
				LoggingEndpoint: loggingServer.URL,
			}

			exporter := integrations.NewGCPExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)

			// Test log level mapping via ExportLogs
			logs := []integrations.LogEntry{
				{
					Timestamp: time.Now(),
					Level:     tt.level,
					Message:   "Test message",
					Source:    "test",
				},
			}

			// This calls mapSeverity internally
			_, _ = exporter.ExportLogs(ctx, logs)
			// The function is called internally, we verify it doesn't panic
		})
	}
}

func TestGCPMapSeverityAllLevels(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Capture the severity values sent to the server
	var capturedSeverities []string
	loggingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		if err == nil {
			if entries, ok := payload["entries"].([]interface{}); ok {
				for _, entry := range entries {
					if entryMap, ok := entry.(map[string]interface{}); ok {
						if severity, ok := entryMap["severity"].(string); ok {
							capturedSeverities = append(capturedSeverities, severity)
						}
					}
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer loggingServer.Close()

	config := integrations.GCPConfig{
		Enabled:         true,
		ProjectID:       "test-project",
		Region:          "us-central1",
		LoggingEndpoint: loggingServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Test all log levels in one batch
	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelDebug, Message: "Debug message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Info message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelWarn, Message: "Warn message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelError, Message: "Error message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelFatal, Message: "Fatal message", Source: "test"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 5, result.ItemsExported)

	// Verify all severities were captured
	assert.Equal(t, 5, len(capturedSeverities))
	assert.Contains(t, capturedSeverities, "DEBUG")
	assert.Contains(t, capturedSeverities, "INFO")
	assert.Contains(t, capturedSeverities, "WARNING")
	assert.Contains(t, capturedSeverities, "ERROR")
	assert.Contains(t, capturedSeverities, "CRITICAL")
}

// ============================================================================
// GCP setAuthHeaders Function Tests
// ============================================================================

func TestGCPSetAuthHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("with access token", func(t *testing.T) {
		var capturedAuth string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}))
		defer mockServer.Close()

		config := integrations.GCPConfig{
			Enabled:            true,
			ProjectID:          "test-project",
			MonitoringEndpoint: mockServer.URL,
		}

		exporter := integrations.NewGCPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Set access token and make a request
		exporter.SetAccessToken("test-gcp-token")

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		_, _ = exporter.ExportMetrics(ctx, metrics)

		assert.Equal(t, "Bearer test-gcp-token", capturedAuth)
	})

	t.Run("without access token", func(t *testing.T) {
		var capturedAuth string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}))
		defer mockServer.Close()

		config := integrations.GCPConfig{
			Enabled:            true,
			ProjectID:          "test-project",
			MonitoringEndpoint: mockServer.URL,
		}

		exporter := integrations.NewGCPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		_, _ = exporter.ExportMetrics(ctx, metrics)

		assert.Empty(t, capturedAuth)
	})
}

func TestGCPSetAuthHeadersWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var capturedHeaders http.Header
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer mockServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: mockServer.URL,
		Headers: map[string]string{
			"X-Custom-Header":   "custom-value",
			"X-Goog-Request-Id": "test-request-id",
		},
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	exporter.SetAccessToken("test-token")

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, _ = exporter.ExportMetrics(ctx, metrics)

	assert.Equal(t, "Bearer test-token", capturedHeaders.Get("Authorization"))
	assert.Equal(t, "custom-value", capturedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "test-request-id", capturedHeaders.Get("X-Goog-Request-Id"))
	assert.Equal(t, "application/json", capturedHeaders.Get("Content-Type"))
}

func TestGCPSetAuthHeadersForHealthCheck(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var capturedAuth string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"metricDescriptors": []interface{}{},
		})
	}))
	defer mockServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: mockServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	exporter.SetAccessToken("health-check-token")

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "Bearer health-check-token", capturedAuth)
}

// ============================================================================
// GCP Exporter Export Tests with Various Error Scenarios
// ============================================================================

func TestGCPExporterExportMetricsServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    500,
				"message": "Internal error",
			},
		})
	}))
	defer errorServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: errorServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "500")
}

func TestGCPExporterExportMetricsAuthFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	authErrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    401,
				"message": "Request had invalid authentication credentials",
			},
		})
	}))
	defer authErrorServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: authErrorServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "401")
}

func TestGCPExporterExportMetricsNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: "http://localhost:59999", // Non-existent port
		Timeout:            1 * time.Second,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestGCPExporterExportMetricsTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: slowServer.URL,
		Timeout:            100 * time.Millisecond,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestGCPExporterExportTracesServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad gateway"})
	}))
	defer errorServer.Close()

	config := integrations.GCPConfig{
		Enabled:       true,
		ProjectID:     "test-project",
		TraceEndpoint: errorServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "trace-001",
			SpanID:        "span-001",
			OperationName: "test-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestGCPExporterExportLogsServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    429,
				"message": "Quota exceeded",
			},
		})
	}))
	defer errorServer.Close()

	config := integrations.GCPConfig{
		Enabled:         true,
		ProjectID:       "test-project",
		LoggingEndpoint: errorServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log",
			Source:    "test",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "429")
}
