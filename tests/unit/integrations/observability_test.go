// package integrations provides unit tests for TelemetryFlow Agent integrations.
package integrations

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

// Prometheus Exporter Tests
func TestNewPrometheusExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "prometheus", exporter.Name())
	assert.Equal(t, "metrics", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestPrometheusExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.PrometheusConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.PrometheusConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9090",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.PrometheusConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint",
			config: integrations.PrometheusConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewPrometheusExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPrometheusExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{Enabled: false}
	exporter := integrations.NewPrometheusExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestPrometheusExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestPrometheusExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that accepts POST requests and returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test metrics
	metrics := []integrations.Metric{
		{Name: "test.metric.1", Value: 42.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		{Name: "test.metric.2", Value: 100.5, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		{Name: "test.metric.3", Value: 0.75, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
}

func TestPrometheusExporterExportMetricsError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns an error status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test metrics
	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

// Datadog Exporter Tests
func TestNewDatadogExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.DatadogConfig{
		Enabled: true,
		APIKey:  "12345678901234567890123456789012",
		Site:    "datadoghq.com",
	}

	exporter := integrations.NewDatadogExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "datadog", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestDatadogExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.DatadogConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.DatadogConfig{
				Enabled: true,
				APIKey:  "12345678901234567890123456789012", // 32 character API key
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.DatadogConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing api key",
			config: integrations.DatadogConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewDatadogExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDatadogExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.DatadogConfig{Enabled: false}
	exporter := integrations.NewDatadogExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestDatadogExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.DatadogConfig{
		Enabled: true,
		APIKey:  "12345678901234567890123456789012",
	}

	exporter := integrations.NewDatadogExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestDatadogExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has the correct headers
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "12345678901234567890123456789012", r.Header.Get("DD-API-KEY"))

		// Read and verify request body is valid JSON
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.DatadogConfig{
		Enabled:         true,
		APIKey:          "12345678901234567890123456789012",
		Site:            "datadoghq.com",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewDatadogExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test metrics
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
}

func TestDatadogExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has the correct headers
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "12345678901234567890123456789012", r.Header.Get("DD-API-KEY"))

		// Read and verify request body is valid JSON
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.DatadogConfig{
		Enabled:        true,
		APIKey:         "12345678901234567890123456789012",
		Site:           "datadoghq.com",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewDatadogExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test traces
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
}

func TestDatadogExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has the correct headers
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "12345678901234567890123456789012", r.Header.Get("DD-API-KEY"))

		// Read and verify request body is valid JSON
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.DatadogConfig{
		Enabled:      true,
		APIKey:       "12345678901234567890123456789012",
		Site:         "datadoghq.com",
		LogsEndpoint: server.URL,
		ServiceName:  "test-service",
	}

	exporter := integrations.NewDatadogExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test logs
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
}

func TestDatadogExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 202 Accepted for all endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request has the correct headers
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "12345678901234567890123456789012", r.Header.Get("DD-API-KEY"))

		// Read and verify request body is valid JSON
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.DatadogConfig{
		Enabled:         true,
		APIKey:          "12345678901234567890123456789012",
		Site:            "datadoghq.com",
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
		ServiceName:     "test-service",
	}

	exporter := integrations.NewDatadogExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test telemetry data with metrics, traces, and logs
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

// Splunk Exporter Tests
func TestNewSplunkExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: "https://splunk.local:8088",
		HECToken:    "test-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "splunk", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestSplunkExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.SplunkConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.SplunkConfig{
				Enabled:     true,
				HECEndpoint: "https://splunk.local:8088",
				HECToken:    "test-token",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.SplunkConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing hec endpoint",
			config: integrations.SplunkConfig{
				Enabled:  true,
				HECToken: "test-token",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSplunkExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSplunkExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "Success"})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	if err == nil {
		assert.NotNil(t, result)
	}
}

func TestSplunkExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.SplunkConfig{Enabled: false}
	exporter := integrations.NewSplunkExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestSplunkExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: "https://splunk.local:8088",
		HECToken:    "test-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestSplunkExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HEC endpoint that accepts POST and returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Splunk")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read request body to verify data was sent
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log message",
			Source:    "test-source",
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Another test log message",
			Source:    "test-source-2",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestSplunkExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HEC endpoint that accepts POST and returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Splunk")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read request body to verify data was sent
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "trace-123",
			SpanID:        "span-456",
			OperationName: "test-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
		{
			TraceID:       "trace-789",
			SpanID:        "span-012",
			OperationName: "another-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      200 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestSplunkExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HEC endpoint that accepts POST and returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Splunk")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read request body to verify data was sent
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData containing metrics, traces, and logs
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "test.metric.1",
				Value:     42.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
			{
				Name:      "test.metric.2",
				Value:     100.0,
				Type:      integrations.MetricTypeCounter,
				Timestamp: time.Now(),
			},
		},
		Traces: []integrations.Trace{
			{
				TraceID:       "trace-abc",
				SpanID:        "span-def",
				OperationName: "main-operation",
				ServiceName:   "main-service",
				StartTime:     time.Now(),
				Duration:      150 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		},
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Application started successfully",
				Source:    "app-main",
			},
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Processing request",
				Source:    "request-handler",
			},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	// Should export 2 metrics + 2 logs = 4 items (Export method handles metrics and logs, not traces)
	assert.Equal(t, 4, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

// Elasticsearch Exporter Tests
func TestNewElasticsearchExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{"http://localhost:9200"},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "elasticsearch", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestElasticsearchExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.ElasticsearchConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.ElasticsearchConfig{
				Enabled:   true,
				Addresses: []string{"http://localhost:9200"},
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.ElasticsearchConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing addresses",
			config: integrations.ElasticsearchConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewElasticsearchExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestElasticsearchExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ElasticsearchConfig{Enabled: false}
	exporter := integrations.NewElasticsearchExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestElasticsearchExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{"http://localhost:9200"},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestElasticsearchExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that handles bulk requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is a POST to /_bulk
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/_bulk")
		assert.Equal(t, "application/x-ndjson", r.Header.Get("Content-Type"))

		// Read and discard body to avoid connection issues
		_, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": false,
			"items":  []interface{}{},
		})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log message",
			Source:    "test-source",
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelError,
			Message:   "Another test log message",
			Source:    "test-source-2",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestElasticsearchExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that handles bulk requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is a POST to /_bulk
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/_bulk")
		assert.Equal(t, "application/x-ndjson", r.Header.Get("Content-Type"))

		// Read and discard body to avoid connection issues
		_, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": false,
			"items":  []interface{}{},
		})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "test.metric.gauge",
			Value:     42.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		},
		{
			Name:      "test.metric.counter",
			Value:     100.0,
			Type:      integrations.MetricTypeCounter,
			Timestamp: time.Now(),
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestElasticsearchExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that handles bulk requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is a POST to /_bulk
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/_bulk")
		assert.Equal(t, "application/x-ndjson", r.Header.Get("Content-Type"))

		// Read and discard body to avoid connection issues
		_, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": false,
			"items":  []interface{}{},
		})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with logs and metrics
	telemetryData := &integrations.TelemetryData{
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log for Export method",
				Source:    "export-test",
			},
		},
		Metrics: []integrations.Metric{
			{
				Name:      "export.test.metric",
				Value:     99.9,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported) // 1 log + 1 metric
	assert.Greater(t, result.BytesSent, int64(0))
}

// InfluxDB Exporter Tests
func TestNewInfluxDBExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          "http://localhost:8086",
		Token:        "test-token",
		Organization: "test-org",
		Bucket:       "test-bucket",
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "influxdb", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestInfluxDBExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.InfluxDBConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.InfluxDBConfig{
				Enabled:      true,
				URL:          "http://localhost:8086",
				Token:        "test-token",
				Organization: "test-org",
				Bucket:       "test-bucket",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.InfluxDBConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing url",
			config: integrations.InfluxDBConfig{
				Enabled: true,
				Token:   "test-token",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewInfluxDBExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInfluxDBExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.InfluxDBConfig{Enabled: false}
	exporter := integrations.NewInfluxDBExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestInfluxDBExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          "http://localhost:8086",
		Token:        "test-token",
		Organization: "test-org",
		Bucket:       "test-bucket",
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestInfluxDBExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that accepts line protocol
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and content type
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "text/plain; charset=utf-8", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), "Token")

		// Return 204 No Content (standard InfluxDB success response)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          server.URL,
		Token:        "test-token",
		Organization: "test-org",
		Bucket:       "test-bucket",
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "cpu.usage",
			Value:     75.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		},
		{
			Name:      "memory.used",
			Value:     1024.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server1"},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestInfluxDBExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 204 No Content
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          server.URL,
		Token:        "test-token",
		Organization: "test-org",
		Bucket:       "test-bucket",
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with metrics
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "test.metric",
				Value:     42.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

// Loki Exporter Tests
func TestNewLokiExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: "http://localhost:3100",
	}

	exporter := integrations.NewLokiExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "loki", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestLokiExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.LokiConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.LokiConfig{
				Enabled:  true,
				Endpoint: "http://localhost:3100",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.LokiConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint",
			config: integrations.LokiConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewLokiExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLokiExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.LokiConfig{Enabled: false}
	exporter := integrations.NewLokiExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestLokiExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: "http://localhost:3100",
	}

	exporter := integrations.NewLokiExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestLokiExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that accepts push requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and content type
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Return 204 No Content (standard Loki success response)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log message 1",
			Source:    "test-service",
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log message 2",
			Source:    "test-service",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestLokiExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 204 No Content
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with logs
	telemetryData := &integrations.TelemetryData{
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-service",
			},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

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

// Jaeger Export Method Tests
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

// Test config defaults
func TestObservabilityConfigDefaults(t *testing.T) {
	t.Run("prometheus defaults", func(t *testing.T) {
		config := integrations.PrometheusConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Endpoint)
	})

	t.Run("datadog defaults", func(t *testing.T) {
		config := integrations.DatadogConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.APIKey)
	})

	t.Run("splunk defaults", func(t *testing.T) {
		config := integrations.SplunkConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.HECEndpoint)
	})

	t.Run("elasticsearch defaults", func(t *testing.T) {
		config := integrations.ElasticsearchConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Addresses)
	})

	t.Run("influxdb defaults", func(t *testing.T) {
		config := integrations.InfluxDBConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.URL)
	})

	t.Run("loki defaults", func(t *testing.T) {
		config := integrations.LokiConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Endpoint)
	})

	t.Run("jaeger defaults", func(t *testing.T) {
		config := integrations.JaegerConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.CollectorEndpoint)
	})

	t.Run("zipkin defaults", func(t *testing.T) {
		config := integrations.ZipkinConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Endpoint)
	})
}

// Benchmark tests
func BenchmarkNewPrometheusExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewPrometheusExporter(config, logger)
	}
}

func BenchmarkNewDatadogExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.DatadogConfig{
		Enabled: true,
		APIKey:  "12345678901234567890123456789012",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewDatadogExporter(config, logger)
	}
}

func BenchmarkNewSplunkExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: "https://splunk.local:8088",
		HECToken:    "test-token",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewSplunkExporter(config, logger)
	}
}
