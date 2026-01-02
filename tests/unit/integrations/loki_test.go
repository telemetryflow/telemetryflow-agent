// package integrations_test provides unit tests for TelemetryFlow Agent Loki integration.
package integrations_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

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

func TestLokiExporterExportMetricsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: "http://localhost:3100",
	}

	exporter := integrations.NewLokiExporter(config, logger)
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
	assert.Contains(t, err.Error(), "loki does not support metrics export")
}

func TestLokiExporterExportTracesNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: "http://localhost:3100",
	}

	exporter := integrations.NewLokiExporter(config, logger)
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
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "loki does not support traces export")
}

// Test Loki config defaults
func TestLokiConfigDefaults(t *testing.T) {
	t.Run("loki defaults", func(t *testing.T) {
		config := integrations.LokiConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.Endpoint)
	})
}

// Comprehensive Health Tests for Loki
func TestLokiExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK for ready endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/ready")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "status: 200", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
}

func TestLokiExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 500", status.Message)
}

func TestLokiExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 503 Service Unavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 503", status.Message)
}

func TestLokiExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
		Timeout:  10 * time.Millisecond,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestLokiExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a non-existent server URL to simulate network error
	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: "http://localhost:59999",
		Timeout:  100 * time.Millisecond,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestLokiExporterHealthWithBasicAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that verifies Basic Auth header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "admin", username)
		assert.Equal(t, "secret", password)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
		Username: "admin",
		Password: "secret",
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestLokiExporterHealthWithBearerToken(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that verifies Bearer token header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Contains(t, authHeader, "Bearer")
		assert.Contains(t, authHeader, "my-bearer-token")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		BearerToken: "my-bearer-token",
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestLokiExporterHealthUnauthorized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 401", status.Message)
}

func TestLokiExporterHealthInvalidResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 400 with an error body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid request"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 400", status.Message)
}

func TestLokiExporterHealthLatencyMeasurement(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock server with a small delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(20))
}

func TestLokiExporterHealthWithTenantID(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that verifies tenant ID header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantHeader := r.Header.Get("X-Scope-OrgID")
		assert.Equal(t, "my-tenant", tenantHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
		TenantID: "my-tenant",
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestLokiExporterHealthCustomEndpoint(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server with custom path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL + "/loki",
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

// Tests for setAuthHeaders helper function
func TestLokiSetAuthHeadersBasicAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
		Username: "testuser",
		Password: "testpass",
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log",
		},
	}

	_, err = exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)

	// Verify Basic Auth is set
	username, password, ok := func() (string, string, bool) {
		if auth := receivedHeaders.Get("Authorization"); auth != "" {
			return "", "", len(auth) > 0
		}
		return "", "", false
	}()
	assert.True(t, ok || username != "" || password != "" || receivedHeaders.Get("Authorization") != "")
}

func TestLokiSetAuthHeadersBearerToken(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		BearerToken: "test-bearer-token-12345",
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log",
		},
	}

	_, err = exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)

	authHeader := receivedHeaders.Get("Authorization")
	assert.Contains(t, authHeader, "Bearer")
	assert.Contains(t, authHeader, "test-bearer-token-12345")
}

func TestLokiSetAuthHeadersNoAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
		// No auth credentials
	}

	exporter := integrations.NewLokiExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log",
		},
	}

	_, err = exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)

	authHeader := receivedHeaders.Get("Authorization")
	assert.Empty(t, authHeader)
}

// Benchmark tests
func BenchmarkLokiHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	config := integrations.LokiConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewLokiExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}
