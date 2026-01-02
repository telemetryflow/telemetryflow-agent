// package integrations_test provides unit tests for TelemetryFlow Agent Elasticsearch integration.
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

func TestElasticsearchExporterExportTraces(t *testing.T) {
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

	traces := []integrations.Trace{
		{
			TraceID:       "trace-001",
			SpanID:        "span-001",
			OperationName: "test-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"env": "test"},
		},
		{
			TraceID:       "trace-001",
			SpanID:        "span-002",
			ParentSpanID:  "span-001",
			OperationName: "child-operation",
			ServiceName:   "test-service",
			StartTime:     time.Now(),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusError,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestElasticsearchExporterExportTracesNotEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ElasticsearchConfig{
		Enabled: false,
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)

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
	assert.Nil(t, result)
	assert.ErrorIs(t, err, integrations.ErrNotEnabled)
}

func TestElasticsearchExporterExportTracesNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{"http://localhost:9200"},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	// Do not call Init()

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
	assert.Nil(t, result)
	assert.ErrorIs(t, err, integrations.ErrNotInitialized)
}

func TestElasticsearchExporterExportTracesServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
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
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// Test Elasticsearch config defaults
func TestElasticsearchConfigDefaults(t *testing.T) {
	config := integrations.ElasticsearchConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.Addresses)
}

// Comprehensive Health Tests for Elasticsearch
func TestElasticsearchExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK with cluster health
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/_cluster/health")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cluster_name":                     "test-cluster",
			"status":                           "green",
			"timed_out":                        false,
			"number_of_nodes":                  3,
			"number_of_data_nodes":             3,
			"active_primary_shards":            10,
			"active_shards":                    20,
			"relocating_shards":                0,
			"initializing_shards":              0,
			"unassigned_shards":                0,
			"delayed_unassigned_shards":        0,
			"number_of_pending_tasks":          0,
			"number_of_in_flight_fetch":        0,
			"task_max_waiting_in_queue_millis": 0,
			"active_shards_percent_as_number":  100.0,
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Contains(t, status.Message, "cluster status: green")
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
	assert.NotNil(t, status.Details)
	assert.Equal(t, "green", status.Details["status"])
}

func TestElasticsearchExporterHealthYellowCluster(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK with yellow cluster health
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cluster_name": "test-cluster",
			"status":       "yellow",
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy) // Yellow is still considered healthy
	assert.Contains(t, status.Message, "cluster status: yellow")
}

func TestElasticsearchExporterHealthRedCluster(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK with red cluster health
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cluster_name": "test-cluster",
			"status":       "red",
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy) // Red is unhealthy
	assert.Contains(t, status.Message, "cluster status: red")
}

func TestElasticsearchExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "500")
	assert.NotNil(t, status.LastError)
}

func TestElasticsearchExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 503 Service Unavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "503")
}

func TestElasticsearchExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
		Timeout:   10 * time.Millisecond,
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestElasticsearchExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a non-existent server URL to simulate network error
	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{"http://localhost:59999"},
		Timeout:   100 * time.Millisecond,
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestElasticsearchExporterHealthWithAPIKey(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that verifies API key header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Contains(t, authHeader, "ApiKey")
		assert.Contains(t, authHeader, "test-api-key")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "green",
		})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestElasticsearchExporterHealthWithBasicAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that verifies Basic Auth header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "elastic", username)
		assert.Equal(t, "password123", password)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "green",
		})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
		Username:  "elastic",
		Password:  "password123",
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestElasticsearchExporterHealthUnauthorized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"security_exception","status":401}`))
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "401")
}

func TestElasticsearchExporterHealthInvalidResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK with invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	// When JSON decode fails, it returns cluster reachable
	assert.True(t, status.Healthy)
	assert.Equal(t, "cluster reachable", status.Message)
}

func TestElasticsearchExporterHealthLatencyMeasurement(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock server with a small delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "green",
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(20))
}

func TestElasticsearchExporterHealthMultipleNodes(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "green",
		})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL, server.URL, server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

// =============================================================================
// sendBulkRequest Tests - HTTP Status Codes
// =============================================================================

func TestElasticsearchSendBulkRequestHTTPStatusCodes(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name          string
		statusCode    int
		expectSuccess bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "200 OK",
			statusCode:    http.StatusOK,
			expectSuccess: true,
			expectError:   false,
		},
		{
			name:          "201 Created",
			statusCode:    http.StatusCreated,
			expectSuccess: true,
			expectError:   false,
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=400",
		},
		{
			name:          "401 Unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=401",
		},
		{
			name:          "403 Forbidden",
			statusCode:    http.StatusForbidden,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=403",
		},
		{
			name:          "404 Not Found",
			statusCode:    http.StatusNotFound,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=404",
		},
		{
			name:          "429 Too Many Requests",
			statusCode:    http.StatusTooManyRequests,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=429",
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=500",
		},
		{
			name:          "502 Bad Gateway",
			statusCode:    http.StatusBadGateway,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=502",
		},
		{
			name:          "503 Service Unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectSuccess: false,
			expectError:   true,
			errorContains: "elasticsearch bulk error: status=503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				w.WriteHeader(tt.statusCode)
				if tt.statusCode >= 400 {
					_, _ = w.Write([]byte(`{"error":"test error"}`))
				} else {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": false,
						"items":  []interface{}{},
					})
				}
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
					Source:    "test",
				},
			}

			result, err := exporter.ExportLogs(ctx, logs)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expectSuccess, result.Success)
		})
	}
}

// =============================================================================
// sendBulkRequest Tests - Network Errors and Timeouts
// =============================================================================

func TestElasticsearchSendBulkRequestNetworkErrors(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("connection refused", func(t *testing.T) {
		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{"http://127.0.0.1:59999"},
			Timeout:   1 * time.Second,
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("request timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{server.URL},
			Timeout:   100 * time.Millisecond,
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("context cancelled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{server.URL},
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(cancelCtx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("server closes connection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				if conn != nil {
					_ = conn.Close()
				}
			}
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})
}

// =============================================================================
// sendBulkRequest Tests - Response Body Handling
// =============================================================================

func TestElasticsearchSendBulkRequestResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("bulk response with errors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": true,
				"items": []map[string]interface{}{
					{
						"index": map[string]interface{}{
							"_index": "logs",
							"_id":    "1",
							"status": 400,
							"error": map[string]interface{}{
								"type":   "mapper_parsing_exception",
								"reason": "failed to parse",
							},
						},
					},
				},
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		// Even with partial errors, the request succeeds at HTTP level
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("empty response body error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusBadRequest)
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("large response body", func(t *testing.T) {
		largeBody := make([]byte, 1024*1024)
		for i := range largeBody {
			largeBody[i] = 'x'
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(largeBody)
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("malformed JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{malformed json`))
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "{malformed json")
	})
}

// =============================================================================
// sendBulkRequest Tests - Headers and Authentication
// =============================================================================

func TestElasticsearchSendBulkRequestHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("verifies required headers", func(t *testing.T) {
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)

		assert.Equal(t, "application/x-ndjson", receivedHeaders.Get("Content-Type"))
	})

	t.Run("with API key", func(t *testing.T) {
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
		}))
		defer server.Close()

		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{server.URL},
			APIKey:    "my-api-key",
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)

		assert.Contains(t, receivedHeaders.Get("Authorization"), "ApiKey")
	})

	t.Run("with basic auth", func(t *testing.T) {
		var hasBasicAuth bool
		var username, password string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, hasBasicAuth = r.BasicAuth()
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
		}))
		defer server.Close()

		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{server.URL},
			Username:  "elastic",
			Password:  "secret",
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)

		assert.True(t, hasBasicAuth)
		assert.Equal(t, "elastic", username)
		assert.Equal(t, "secret", password)
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestElasticsearchEdgeCases(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty logs slice", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
		}))
		defer server.Close()

		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{server.URL},
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		result, err := exporter.ExportLogs(ctx, []integrations.LogEntry{})
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ItemsExported)
	})

	t.Run("large payload", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
		}))
		defer server.Close()

		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{server.URL},
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Create 10000 logs
		logs := make([]integrations.LogEntry, 10000)
		for i := 0; i < 10000; i++ {
			logs[i] = integrations.LogEntry{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-source",
			}
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 10000, result.ItemsExported)
		assert.Greater(t, len(receivedBody), 0)
	})

	t.Run("special characters in log message", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
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
				Message:   "Log with special chars: \n\t\r\"'\\<>&{}[]",
				Source:    "test",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Greater(t, len(receivedBody), 0)
	})

	t.Run("unicode in log message", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
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
				Message:   "Unicode message: Hello World",
				Source:    "test",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
	})

	t.Run("with custom index", func(t *testing.T) {
		var receivedURL string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedURL = r.URL.String()
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
		}))
		defer server.Close()

		config := integrations.ElasticsearchConfig{
			Enabled:     true,
			Addresses:   []string{server.URL},
			IndexPrefix: "custom-logs",
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)

		// Bulk request goes to /_bulk endpoint
		assert.Contains(t, receivedURL, "/_bulk")
	})
}

// =============================================================================
// Not Initialized/Enabled Tests
// =============================================================================

func TestElasticsearchNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export logs not initialized", func(t *testing.T) {
		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{"http://localhost:9200"},
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)
		// Do NOT call Init()

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export logs not enabled", func(t *testing.T) {
		config := integrations.ElasticsearchConfig{
			Enabled:   false,
			Addresses: []string{"http://localhost:9200"},
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.ElasticsearchConfig{
			Enabled:   true,
			Addresses: []string{"http://localhost:9200"},
		}

		exporter := integrations.NewElasticsearchExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})
}

// Benchmark tests
func BenchmarkElasticsearchHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "green",
		})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}

func BenchmarkElasticsearchExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": false, "items": []interface{}{}})
	}))
	defer server.Close()

	config := integrations.ElasticsearchConfig{
		Enabled:   true,
		Addresses: []string{server.URL},
	}

	exporter := integrations.NewElasticsearchExporter(config, logger)
	_ = exporter.Init(ctx)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}
