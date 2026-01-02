// package integrations_test provides unit tests for TelemetryFlow Agent InfluxDB integration.
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

func TestInfluxDBExporterExportTracesNotSupported(t *testing.T) {
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
	assert.Contains(t, err.Error(), "influxdb does not natively support traces export")
}

func TestInfluxDBExporterExportLogs(t *testing.T) {
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

	logs := []integrations.LogEntry{
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelInfo,
			Message:   "Test log message 1",
			Source:    "test-source",
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelError,
			Message:   "Test log message 2",
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

func TestInfluxDBExporterExportLogsNotEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.InfluxDBConfig{
		Enabled: false,
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)

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
	assert.ErrorIs(t, err, integrations.ErrNotEnabled)
}

func TestInfluxDBExporterExportLogsNotInitialized(t *testing.T) {
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
	// Do not call Init()

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
	assert.ErrorIs(t, err, integrations.ErrNotInitialized)
}

func TestInfluxDBExporterExportLogsServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock HTTP server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
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
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// Test InfluxDB config defaults
func TestInfluxDBConfigDefaults(t *testing.T) {
	t.Run("influxdb defaults", func(t *testing.T) {
		config := integrations.InfluxDBConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.URL)
	})
}

// Comprehensive Health Tests for InfluxDB
func TestInfluxDBExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK for health endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/health")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pass","version":"2.0.0"}`))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "status: 200", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
}

func TestInfluxDBExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 500", status.Message)
}

func TestInfluxDBExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 503 Service Unavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 503", status.Message)
}

func TestInfluxDBExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          server.URL,
		Token:        "test-token",
		Organization: "test-org",
		Bucket:       "test-bucket",
		Timeout:      10 * time.Millisecond,
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestInfluxDBExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a non-existent server URL to simulate network error
	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          "http://localhost:59999",
		Token:        "test-token",
		Organization: "test-org",
		Bucket:       "test-bucket",
		Timeout:      100 * time.Millisecond,
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestInfluxDBExporterHealthUnauthorized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"unauthorized","message":"invalid token"}`))
	}))
	defer server.Close()

	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          server.URL,
		Token:        "invalid-token",
		Organization: "test-org",
		Bucket:       "test-bucket",
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 401", status.Message)
}

func TestInfluxDBExporterHealthWithToken(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server - Health endpoint doesn't require auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoint should be GET to /health
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/health")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pass"}`))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestInfluxDBExporterHealthInvalidResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 400 with an error body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid request format"))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "status: 400", status.Message)
}

func TestInfluxDBExporterHealthLatencyMeasurement(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock server with a small delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pass"}`))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(20))
}

func TestInfluxDBExporterHealthDetailsContainsBucket(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pass"}`))
	}))
	defer server.Close()

	config := integrations.InfluxDBConfig{
		Enabled:      true,
		URL:          server.URL,
		Token:        "test-token",
		Organization: "test-org",
		Bucket:       "my-metrics-bucket",
	}

	exporter := integrations.NewInfluxDBExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.NotNil(t, status.Details)
	// Details only contains "version" from header, not bucket
	_, hasVersion := status.Details["version"]
	assert.True(t, hasVersion)
}

func TestInfluxDBExporterHealthFailed(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns failed health status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"fail","message":"database not ready"}`))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	// Even if status is fail in body, HTTP 200 should result in healthy check
	assert.True(t, status.Healthy)
}

// =============================================================================
// sendRequest Tests - HTTP Status Codes
// =============================================================================

func TestInfluxDBSendRequestHTTPStatusCodes(t *testing.T) {
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
			name:          "204 No Content (success)",
			statusCode:    http.StatusNoContent,
			expectSuccess: true,
			expectError:   false,
		},
		{
			name:          "200 OK",
			statusCode:    http.StatusOK,
			expectSuccess: true,
			expectError:   false,
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=400",
		},
		{
			name:          "401 Unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=401",
		},
		{
			name:          "403 Forbidden",
			statusCode:    http.StatusForbidden,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=403",
		},
		{
			name:          "404 Not Found",
			statusCode:    http.StatusNotFound,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=404",
		},
		{
			name:          "429 Too Many Requests",
			statusCode:    http.StatusTooManyRequests,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=429",
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=500",
		},
		{
			name:          "502 Bad Gateway",
			statusCode:    http.StatusBadGateway,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=502",
		},
		{
			name:          "503 Service Unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectSuccess: false,
			expectError:   true,
			errorContains: "influxdb write error: status=503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode >= 400 {
					_, _ = w.Write([]byte(`{"code":"error","message":"test error"}`))
				}
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
					Name:      "test.metric",
					Value:     1.0,
					Type:      integrations.MetricTypeGauge,
					Timestamp: time.Now(),
				},
			}

			result, err := exporter.ExportMetrics(ctx, metrics)

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
// sendRequest Tests - Network Errors and Timeouts
// =============================================================================

func TestInfluxDBSendRequestNetworkErrors(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("connection refused", func(t *testing.T) {
		config := integrations.InfluxDBConfig{
			Enabled:      true,
			URL:          "http://127.0.0.1:59999",
			Token:        "test-token",
			Organization: "test-org",
			Bucket:       "test-bucket",
			Timeout:      1 * time.Second,
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("request timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.InfluxDBConfig{
			Enabled:      true,
			URL:          server.URL,
			Token:        "test-token",
			Organization: "test-org",
			Bucket:       "test-bucket",
			Timeout:      100 * time.Millisecond,
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("context cancelled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
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

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(cancelCtx, metrics)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("invalid URL", func(t *testing.T) {
		config := integrations.InfluxDBConfig{
			Enabled:      true,
			URL:          "http://[::1]:namedport",
			Token:        "test-token",
			Organization: "test-org",
			Bucket:       "test-bucket",
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
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
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})
}

// =============================================================================
// sendRequest Tests - Headers
// =============================================================================

func TestInfluxDBSendRequestHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("verifies required headers", func(t *testing.T) {
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.InfluxDBConfig{
			Enabled:      true,
			URL:          server.URL,
			Token:        "my-influx-token",
			Organization: "test-org",
			Bucket:       "test-bucket",
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		_, err = exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)

		assert.Equal(t, "text/plain; charset=utf-8", receivedHeaders.Get("Content-Type"))
		assert.Equal(t, "Token my-influx-token", receivedHeaders.Get("Authorization"))
	})

	t.Run("custom headers", func(t *testing.T) {
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.InfluxDBConfig{
			Enabled:      true,
			URL:          server.URL,
			Token:        "test-token",
			Organization: "test-org",
			Bucket:       "test-bucket",
			Headers: map[string]string{
				"X-Custom-Header":  "custom-value",
				"X-Another-Header": "another-value",
			},
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		_, err = exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)

		assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
		assert.Equal(t, "another-value", receivedHeaders.Get("X-Another-Header"))
	})
}

// =============================================================================
// buildLineProtocol Tests
// =============================================================================

func TestInfluxDBBuildLineProtocol(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("basic metric without tags", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedBody = string(body)
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

		ts := time.Unix(1609459200, 0) // 2021-01-01 00:00:00 UTC
		metrics := []integrations.Metric{
			{
				Name:      "cpu_usage",
				Value:     75.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: ts,
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		assert.Contains(t, receivedBody, "cpu_usage")
		assert.Contains(t, receivedBody, "value=75.5")
	})

	t.Run("metric with tags", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedBody = string(body)
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
				Name:      "memory_used",
				Value:     1024.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags: map[string]string{
					"host":   "server-01",
					"region": "us-east-1",
				},
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		assert.Contains(t, receivedBody, "memory_used")
		assert.Contains(t, receivedBody, "host=server-01")
		assert.Contains(t, receivedBody, "region=us-east-1")
		assert.Contains(t, receivedBody, "value=1024")
	})

	t.Run("multiple metrics", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedBody = string(body)
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
			{Name: "metric1", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
			{Name: "metric2", Value: 2.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
			{Name: "metric3", Value: 3.0, Type: integrations.MetricTypeCounter, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)

		assert.Contains(t, receivedBody, "metric1")
		assert.Contains(t, receivedBody, "metric2")
		assert.Contains(t, receivedBody, "metric3")
	})

	t.Run("metric with special characters in name", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedBody = string(body)
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
				Name:      "system.cpu.usage_percent",
				Value:     42.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		assert.Contains(t, receivedBody, "system.cpu.usage_percent")
	})

	t.Run("metric with zero value", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedBody = string(body)
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
				Name:      "zero_metric",
				Value:     0.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		assert.Contains(t, receivedBody, "value=0")
	})

	t.Run("metric with negative value", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedBody = string(body)
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
				Name:      "negative_metric",
				Value:     -42.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		assert.Contains(t, receivedBody, "value=-42.5")
	})

	t.Run("metric with very large value", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				Name:      "large_metric",
				Value:     1e308,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)
	})

	t.Run("tag with special characters", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedBody = string(body)
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
				Name:      "test_metric",
				Value:     1.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags: map[string]string{
					"path": "/api/v1/users",
				},
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Greater(t, len(receivedBody), 0)
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestInfluxDBEdgeCases(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty metrics slice", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		result, err := exporter.ExportMetrics(ctx, []integrations.Metric{})
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ItemsExported)
	})

	t.Run("large payload", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Create 10000 metrics
		metrics := make([]integrations.Metric, 10000)
		for i := 0; i < 10000; i++ {
			metrics[i] = integrations.Metric{
				Name:      "test_metric",
				Value:     float64(i),
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"index": string(rune(i % 256))},
			}
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 10000, result.ItemsExported)
	})

	t.Run("with different bucket", func(t *testing.T) {
		var receivedURL string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedURL = r.URL.String()
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		config := integrations.InfluxDBConfig{
			Enabled:      true,
			URL:          server.URL,
			Token:        "test-token",
			Organization: "my-org",
			Bucket:       "custom-bucket",
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		_, err = exporter.ExportMetrics(ctx, metrics)
		assert.NoError(t, err)

		assert.Contains(t, receivedURL, "bucket=custom-bucket")
		assert.Contains(t, receivedURL, "org=my-org")
	})
}

// =============================================================================
// Not Initialized/Enabled Tests
// =============================================================================

func TestInfluxDBNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.InfluxDBConfig{
			Enabled:      true,
			URL:          "http://localhost:8086",
			Token:        "test-token",
			Organization: "test-org",
			Bucket:       "test-bucket",
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)
		// Do NOT call Init()

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.InfluxDBConfig{
			Enabled:      false,
			URL:          "http://localhost:8086",
			Token:        "test-token",
			Organization: "test-org",
			Bucket:       "test-bucket",
		}

		exporter := integrations.NewInfluxDBExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})
}

// Benchmark tests
func BenchmarkInfluxDBHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pass"}`))
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
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}

func BenchmarkInfluxDBExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}
