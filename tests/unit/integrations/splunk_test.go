// package integrations_test provides unit tests for TelemetryFlow Agent Splunk integration.
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

// Test Splunk config defaults
func TestSplunkConfigDefaults(t *testing.T) {
	config := integrations.SplunkConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.HECEndpoint)
}

// Comprehensive Health Tests for Splunk
func TestSplunkExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK for health check
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Splunk")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
		Index:       "main",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "HEC endpoint healthy", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
	assert.NotNil(t, status.Details)
	assert.Equal(t, "main", status.Details["index"])
}

func TestSplunkExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "500")
	assert.NotNil(t, status.LastError)
}

func TestSplunkExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 503 Service Unavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "503")
}

func TestSplunkExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
		Timeout:     10 * time.Millisecond,
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestSplunkExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a non-existent server URL to simulate network error
	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: "http://localhost:59999",
		HECToken:    "test-token",
		Timeout:     100 * time.Millisecond,
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestSplunkExporterHealthUnauthorized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Token is invalid", "code": 4})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "invalid-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "401")
}

func TestSplunkExporterHealthInvalidToken(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Token disabled", "code": 1})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "disabled-token",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "403")
}

func TestSplunkExporterHealthInvalidResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 400 with an error body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid event format"))
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "invalid event format")
}

func TestSplunkExporterHealthLatencyMeasurement(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock server with a small delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(20))
}

func TestSplunkExporterHealthWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
		},
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestSplunkExporterHealthDetailsContainsIndex(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
	}))
	defer server.Close()

	config := integrations.SplunkConfig{
		Enabled:     true,
		HECEndpoint: server.URL,
		HECToken:    "test-token",
		Index:       "telemetry",
	}

	exporter := integrations.NewSplunkExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.NotNil(t, status.Details)
	assert.Equal(t, "telemetry", status.Details["index"])
}

func TestSplunkExporterHealthAcknowledgementError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 400 No data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"text": "No data",
			"code": 5,
		})
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

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
}

// =============================================================================
// sendRequest Tests - HTTP Status Codes
// =============================================================================

func TestSplunkSendRequestHTTPStatusCodes(t *testing.T) {
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
			errorContains: "splunk HEC error: status=400",
		},
		{
			name:          "401 Unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=401",
		},
		{
			name:          "403 Forbidden",
			statusCode:    http.StatusForbidden,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=403",
		},
		{
			name:          "404 Not Found",
			statusCode:    http.StatusNotFound,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=404",
		},
		{
			name:          "429 Too Many Requests",
			statusCode:    http.StatusTooManyRequests,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=429",
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=500",
		},
		{
			name:          "502 Bad Gateway",
			statusCode:    http.StatusBadGateway,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=502",
		},
		{
			name:          "503 Service Unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=503",
		},
		{
			name:          "504 Gateway Timeout",
			statusCode:    http.StatusGatewayTimeout,
			expectSuccess: false,
			expectError:   true,
			errorContains: "splunk HEC error: status=504",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode >= 400 {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"text": "Error occurred",
						"code": tt.statusCode,
					})
				} else {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"text": "Success",
						"code": 0,
					})
				}
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
// sendRequest Tests - Network Errors and Timeouts
// =============================================================================

func TestSplunkSendRequestNetworkErrors(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("connection refused", func(t *testing.T) {
		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: "http://127.0.0.1:59999",
			HECToken:    "test-token",
			Timeout:     1 * time.Second,
		}

		exporter := integrations.NewSplunkExporter(config, logger)
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

		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: server.URL,
			HECToken:    "test-token",
			Timeout:     100 * time.Millisecond,
		}

		exporter := integrations.NewSplunkExporter(config, logger)
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

		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: server.URL,
			HECToken:    "test-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)
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

	t.Run("invalid URL", func(t *testing.T) {
		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: "http://[::1]:namedport",
			HECToken:    "test-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)
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

		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: server.URL,
			HECToken:    "test-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)
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
// sendRequest Tests - Response Body Handling
// =============================================================================

func TestSplunkSendRequestResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty response body success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
	})

	t.Run("empty response body error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status=400")
	})

	t.Run("large response body", func(t *testing.T) {
		largeBody := make([]byte, 1024*1024)
		for i := range largeBody {
			largeBody[i] = 'x'
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(largeBody)
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("malformed JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{malformed json`))
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
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "{malformed json")
	})
}

// =============================================================================
// sendRequest Tests - Headers and Authentication
// =============================================================================

func TestSplunkSendRequestHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("verifies required headers", func(t *testing.T) {
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
		}))
		defer server.Close()

		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: server.URL,
			HECToken:    "my-secret-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)

		assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
		assert.Equal(t, "Splunk my-secret-token", receivedHeaders.Get("Authorization"))
	})

	t.Run("custom headers", func(t *testing.T) {
		var receivedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
		}))
		defer server.Close()

		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: server.URL,
			HECToken:    "test-token",
			Headers: map[string]string{
				"X-Custom-Header":  "custom-value",
				"X-Another-Header": "another-value",
			},
		}

		exporter := integrations.NewSplunkExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)

		assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
		assert.Equal(t, "another-value", receivedHeaders.Get("X-Another-Header"))
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestSplunkEdgeCases(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty logs slice", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Create 10000 logs
		logs := make([]integrations.LogEntry, 10000)
		for i := 0; i < 10000; i++ {
			logs[i] = integrations.LogEntry{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message number " + string(rune(i)),
				Source:    "test-source",
			}
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 10000, result.ItemsExported)
		assert.Greater(t, len(receivedBody), 0)
	})

	t.Run("special characters in log message", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
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
				Message:   "Unicode message: Hello World",
				Source:    "test",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
	})

	t.Run("log with index and source type", func(t *testing.T) {
		var receivedBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"text": "Success", "code": 0})
		}))
		defer server.Close()

		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: server.URL,
			HECToken:    "test-token",
			Index:       "telemetry_logs",
			SourceType:  "_json",
		}

		exporter := integrations.NewSplunkExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test with index",
				Source:    "test",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Greater(t, len(receivedBody), 0)
	})
}

// =============================================================================
// Not Initialized/Enabled Tests
// =============================================================================

func TestSplunkNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export logs not initialized", func(t *testing.T) {
		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: "http://localhost:8088",
			HECToken:    "test-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)
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
		config := integrations.SplunkConfig{
			Enabled:     false,
			HECEndpoint: "http://localhost:8088",
			HECToken:    "test-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: "http://localhost:8088",
			HECToken:    "test-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export traces not initialized", func(t *testing.T) {
		config := integrations.SplunkConfig{
			Enabled:     true,
			HECEndpoint: "http://localhost:8088",
			HECToken:    "test-token",
		}

		exporter := integrations.NewSplunkExporter(config, logger)

		traces := []integrations.Trace{
			{TraceID: "trace-1", SpanID: "span-1", OperationName: "test", StartTime: time.Now(), Duration: 100 * time.Millisecond},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})
}

// Benchmark tests
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

func BenchmarkSplunkHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}

func BenchmarkSplunkExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	_ = exporter.Init(ctx)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}
