// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// Webhook Exporter Tests

func TestNewWebhookExporter(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name           string
		config         integrations.WebhookConfig
		expectedName   string
		expectedType   string
		expectedEnable bool
	}{
		{
			name: "enabled exporter",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "POST",
			},
			expectedName:   "webhook",
			expectedType:   "custom",
			expectedEnable: true,
		},
		{
			name: "disabled exporter",
			config: integrations.WebhookConfig{
				Enabled: false,
				URL:     "https://example.com/webhook",
			},
			expectedName:   "webhook",
			expectedType:   "custom",
			expectedEnable: false,
		},
		{
			name: "exporter with all options",
			config: integrations.WebhookConfig{
				Enabled:         true,
				URL:             "https://example.com/webhook",
				Method:          "PUT",
				Secret:          "my-secret",
				SignatureHeader: "X-Custom-Signature",
				ContentType:     "application/json",
				Timeout:         60 * time.Second,
				RetryCount:      5,
				RetryDelay:      2 * time.Second,
				BatchSize:       200,
				FlushInterval:   20 * time.Second,
				Headers: map[string]string{
					"X-Custom-Header": "custom-value",
				},
			},
			expectedName:   "webhook",
			expectedType:   "custom",
			expectedEnable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewWebhookExporter(tt.config, logger)

			require.NotNil(t, exporter)
			assert.Equal(t, tt.expectedName, exporter.Name())
			assert.Equal(t, tt.expectedType, exporter.Type())
			assert.Equal(t, tt.expectedEnable, exporter.IsEnabled())

			// Verify supported data types
			supportedTypes := exporter.SupportedDataTypes()
			assert.Contains(t, supportedTypes, integrations.DataTypeMetrics)
			assert.Contains(t, supportedTypes, integrations.DataTypeTraces)
			assert.Contains(t, supportedTypes, integrations.DataTypeLogs)
		})
	}
}

func TestNewWebhookExporterWithNilLogger(t *testing.T) {
	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     "https://example.com/webhook",
	}

	exporter := integrations.NewWebhookExporter(config, nil)

	require.NotNil(t, exporter)
	assert.Equal(t, "webhook", exporter.Name())
}

func TestWebhookExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.WebhookConfig
		expectError bool
	}{
		{
			name: "valid config with URL",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
			},
			expectError: false,
		},
		{
			name: "valid config with POST method",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "POST",
			},
			expectError: false,
		},
		{
			name: "valid config with PUT method",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "PUT",
			},
			expectError: false,
		},
		{
			name: "valid config with PATCH method",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "PATCH",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.WebhookConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing URL when enabled",
			config: integrations.WebhookConfig{
				Enabled: true,
			},
			expectError: true,
		},
		{
			name: "invalid method",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "GET",
			},
			expectError: true,
		},
		{
			name: "invalid method DELETE",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "DELETE",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewWebhookExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWebhookExporterInitDefaults(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock server to receive the webhook
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify default content type
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		// Verify default method
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     server.URL,
		// Leave Method, ContentType, SignatureHeader empty to test defaults
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Verify initialized state
	assert.True(t, exporter.IsInitialized())
}

func TestWebhookExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.WebhookConfig
		expectError bool
		errorField  string
	}{
		{
			name: "valid config",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "POST",
			},
			expectError: false,
		},
		{
			name: "disabled config skips validation",
			config: integrations.WebhookConfig{
				Enabled: false,
				URL:     "", // empty URL is OK when disabled
			},
			expectError: false,
		},
		{
			name: "missing URL",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "",
			},
			expectError: true,
			errorField:  "url",
		},
		{
			name: "invalid HTTP method",
			config: integrations.WebhookConfig{
				Enabled: true,
				URL:     "https://example.com/webhook",
				Method:  "INVALID",
			},
			expectError: true,
			errorField:  "method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewWebhookExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorField != "" {
					validationErr, ok := err.(*integrations.ValidationError)
					if ok {
						assert.Equal(t, tt.errorField, validationErr.Field)
					}
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWebhookExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that accepts all telemetry types
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify body is valid JSON
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		var payload integrations.WebhookPayload
		err = json.Unmarshal(body, &payload)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		Method:     "POST",
		RetryCount: 0, // Disable retries for faster tests
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create telemetry data with all types
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "test.metric.1",
				Value:     42.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
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
				TraceID:       "trace-001",
				SpanID:        "span-001",
				OperationName: "test-operation",
				ServiceName:   "test-service",
				StartTime:     time.Now(),
				Duration:      100 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		},
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-source",
			},
		},
		Timestamp: time.Now(),
		AgentID:   "agent-001",
		Hostname:  "test-host",
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	// 2 metrics + 1 trace + 1 log = 4 items (but sent in 3 requests: metrics, traces, logs)
	assert.Equal(t, 4, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestWebhookExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: false,
		URL:     "https://example.com/webhook",
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	_ = exporter.Init(ctx)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestWebhookExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload integrations.WebhookPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "TelemetryFlow-Agent/1.0", r.Header.Get("User-Agent"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "cpu.usage",
			Value:     75.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server-01", "region": "us-east-1"},
			Unit:      "percent",
		},
		{
			Name:      "memory.used",
			Value:     4096.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server-01"},
			Unit:      "MB",
		},
		{
			Name:      "requests.total",
			Value:     1000.0,
			Type:      integrations.MetricTypeCounter,
			Timestamp: time.Now(),
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))

	// Verify payload structure
	assert.Equal(t, "metrics", receivedPayload.Type)
	assert.NotZero(t, receivedPayload.Timestamp)
}

func TestWebhookExporterExportMetricsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: false,
		URL:     "https://example.com/webhook",
	}

	exporter := integrations.NewWebhookExporter(config, logger)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestWebhookExporterExportMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     "https://example.com/webhook",
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	// Don't call Init()

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Equal(t, integrations.ErrNotInitialized, err)
	assert.Nil(t, result)
}

func TestWebhookExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload integrations.WebhookPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "Application started successfully",
			Source:     "main.go",
			Attributes: map[string]string{"version": "1.0.0"},
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
			TraceID:    "trace-123",
			SpanID:     "span-456",
			Attributes: map[string]string{"retry_count": "3"},
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))

	// Verify payload structure
	assert.Equal(t, "logs", receivedPayload.Type)
}

func TestWebhookExporterExportLogsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: false,
	}

	exporter := integrations.NewWebhookExporter(config, logger)

	logs := []integrations.LogEntry{
		{Level: integrations.LogLevelInfo, Message: "test"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestWebhookExporterExportLogsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     "https://example.com/webhook",
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	// Don't call Init()

	logs := []integrations.LogEntry{
		{Level: integrations.LogLevelInfo, Message: "test"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Equal(t, integrations.ErrNotInitialized, err)
	assert.Nil(t, result)
}

func TestWebhookExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload integrations.WebhookPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "trace-abc123",
			SpanID:        "span-001",
			OperationName: "http.request",
			ServiceName:   "api-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"http.method": "GET", "http.status_code": "200"},
		},
		{
			TraceID:       "trace-abc123",
			SpanID:        "span-002",
			ParentSpanID:  "span-001",
			OperationName: "db.query",
			ServiceName:   "api-service",
			StartTime:     time.Now().Add(-50 * time.Millisecond),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"db.type": "postgresql"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))

	// Verify payload structure
	assert.Equal(t, "traces", receivedPayload.Type)
}

func TestWebhookExporterExportTracesDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: false,
	}

	exporter := integrations.NewWebhookExporter(config, logger)

	traces := []integrations.Trace{
		{TraceID: "trace-1", SpanID: "span-1", OperationName: "test"},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Equal(t, integrations.ErrNotEnabled, err)
	assert.Nil(t, result)
}

func TestWebhookExporterExportTracesNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     "https://example.com/webhook",
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	// Don't call Init()

	traces := []integrations.Trace{
		{TraceID: "trace-1", SpanID: "span-1", OperationName: "test"},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	assert.Equal(t, integrations.ErrNotInitialized, err)
	assert.Nil(t, result)
}

func TestWebhookExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name           string
		serverStatus   int
		enabled        bool
		expectHealthy  bool
		expectMessage  string
		serverResponse bool
	}{
		{
			name:           "healthy server",
			serverStatus:   http.StatusOK,
			enabled:        true,
			expectHealthy:  true,
			expectMessage:  "status: 200",
			serverResponse: true,
		},
		{
			name:           "unhealthy server (500)",
			serverStatus:   http.StatusInternalServerError,
			enabled:        true,
			expectHealthy:  false,
			expectMessage:  "status: 500",
			serverResponse: true,
		},
		{
			name:           "not found (404) still healthy",
			serverStatus:   http.StatusNotFound,
			enabled:        true,
			expectHealthy:  true,
			expectMessage:  "status: 404",
			serverResponse: true,
		},
		{
			name:          "disabled integration",
			enabled:       false,
			expectHealthy: false,
			expectMessage: "integration disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			if tt.serverResponse {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "HEAD", r.Method)
					w.WriteHeader(tt.serverStatus)
				}))
				defer server.Close()
			}

			config := integrations.WebhookConfig{
				Enabled: tt.enabled,
			}
			if server != nil {
				config.URL = server.URL
			}

			exporter := integrations.NewWebhookExporter(config, logger)
			if tt.enabled {
				err := exporter.Init(ctx)
				require.NoError(t, err)
			}

			status, err := exporter.Health(ctx)
			require.NoError(t, err)
			require.NotNil(t, status)
			assert.Equal(t, tt.expectHealthy, status.Healthy)
			assert.Contains(t, status.Message, tt.expectMessage)
			// LastCheck is only set when a real health check is performed (enabled integrations)
			if tt.enabled {
				assert.NotZero(t, status.LastCheck)
			}
		})
	}
}

func TestWebhookExporterHealthConnectionFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     "http://localhost:59999", // Non-existent server
		Timeout: 1 * time.Second,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestWebhookExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     server.URL,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())

	err = exporter.Close(ctx)
	assert.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

func TestWebhookExporterCloseWithoutInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     "https://example.com/webhook",
	}

	exporter := integrations.NewWebhookExporter(config, logger)

	// Close without initializing should not error
	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestWebhookExporterWithSignature(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	secret := "my-webhook-secret"
	signatureHeader := "X-Webhook-Signature"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		// Verify signature header is present
		signature := r.Header.Get(signatureHeader)
		assert.NotEmpty(t, signature)
		assert.True(t, len(signature) > 0)

		// Verify signature format (sha256=...)
		assert.Contains(t, signature, "sha256=")

		// Verify signature is correct
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		assert.Equal(t, expectedSignature, signature)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:         true,
		URL:             server.URL,
		Secret:          secret,
		SignatureHeader: signatureHeader,
		RetryCount:      0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 42.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestWebhookExporterWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	customHeaders := map[string]string{
		"X-Custom-Header-1": "value-1",
		"X-Custom-Header-2": "value-2",
		"Authorization":     "Bearer test-token",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify all custom headers are present
		for key, expectedValue := range customHeaders {
			assert.Equal(t, expectedValue, r.Header.Get(key), "Header %s mismatch", key)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		Headers:    customHeaders,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)
}

func TestWebhookExporterWithDifferentMethods(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	methods := []string{"POST", "PUT", "PATCH"}

	for _, method := range methods {
		t.Run("method_"+method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, method, r.Method)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			config := integrations.WebhookConfig{
				Enabled:    true,
				URL:        server.URL,
				Method:     method,
				RetryCount: 0,
			}

			exporter := integrations.NewWebhookExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)

			metrics := []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
			}

			result, err := exporter.ExportMetrics(ctx, metrics)
			require.NoError(t, err)
			assert.True(t, result.Success)
		})
	}
}

func TestWebhookExporterRetryOnError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count < 3 {
			// Fail first 2 requests
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed on 3rd request
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 3,
		RetryDelay: 10 * time.Millisecond, // Short delay for tests
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.RetryCount) // Should have retried twice before succeeding
}

func TestWebhookExporterRetryExhausted(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always fail
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 2,
		RetryDelay: 10 * time.Millisecond,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
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
	assert.Equal(t, 2, result.RetryCount)
}

func TestWebhookExporterContextCancellation(t *testing.T) {
	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay response to allow context cancellation
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 3,
		RetryDelay: 100 * time.Millisecond,
		Timeout:    5 * time.Second,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	ctx := context.Background()
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create a context that will be cancelled quickly
	cancelCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(cancelCtx, metrics)
	// Should fail due to context timeout/cancellation
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestWebhookExporterExportWithEmptyData(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Empty telemetry data
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{},
		Traces:  []integrations.Trace{},
		Logs:    []integrations.LogEntry{},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ItemsExported)
}

func TestWebhookExporterStats(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Export some data
	metrics := []integrations.Metric{
		{Name: "test.metric.1", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		{Name: "test.metric.2", Value: 2.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, _ = exporter.ExportMetrics(ctx, metrics)
	_, _ = exporter.ExportMetrics(ctx, metrics)

	stats := exporter.Stats()
	assert.Equal(t, "webhook", stats.Name)
	assert.Equal(t, "custom", stats.Type)
	assert.True(t, stats.Enabled)
	assert.True(t, stats.Initialized)
	assert.Equal(t, int64(2), stats.ExportCount)
	assert.Greater(t, stats.BytesExported, int64(0))
}

func TestWebhookExporterErrorStats(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0, // No retries
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, _ = exporter.ExportMetrics(ctx, metrics)

	stats := exporter.Stats()
	assert.Equal(t, int64(1), stats.ErrorCount)
	assert.NotNil(t, stats.LastError)
}

func TestWebhookConfigDefaults(t *testing.T) {
	config := integrations.WebhookConfig{}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.URL)
	assert.Empty(t, config.Method)
	assert.Empty(t, config.Secret)
	assert.Empty(t, config.SignatureHeader)
	assert.Empty(t, config.ContentType)
	assert.Zero(t, config.Timeout)
	assert.Zero(t, config.RetryCount)
	assert.Zero(t, config.RetryDelay)
	assert.Zero(t, config.BatchSize)
	assert.Zero(t, config.FlushInterval)
	assert.Nil(t, config.Headers)
}

func TestWebhookPayloadStruct(t *testing.T) {
	payload := integrations.WebhookPayload{
		Type:      "metrics",
		Timestamp: time.Now(),
		AgentID:   "agent-001",
		Hostname:  "test-host",
		Data:      []integrations.Metric{{Name: "test", Value: 1.0}},
		Metadata: map[string]interface{}{
			"version": "1.0.0",
		},
	}

	assert.Equal(t, "metrics", payload.Type)
	assert.NotZero(t, payload.Timestamp)
	assert.Equal(t, "agent-001", payload.AgentID)
	assert.Equal(t, "test-host", payload.Hostname)
	assert.NotNil(t, payload.Data)
	assert.NotEmpty(t, payload.Metadata)

	// Test JSON marshaling
	jsonData, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), "metrics")
	assert.Contains(t, string(jsonData), "agent-001")
}

func TestWebhookExporterPartialExportFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			// First request (metrics) succeeds
			w.WriteHeader(http.StatusOK)
		} else {
			// Subsequent requests fail
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
		Traces: []integrations.Trace{
			{TraceID: "trace-1", SpanID: "span-1", OperationName: "test", StartTime: time.Now()},
		},
		Logs: []integrations.LogEntry{
			{Level: integrations.LogLevelInfo, Message: "test", Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	// Should have an error from one of the exports
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	// First export succeeded, so we should have some items exported
	assert.Greater(t, result.ItemsExported, 0)
}

// Benchmark tests
func BenchmarkNewWebhookExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.WebhookConfig{
		Enabled: true,
		URL:     "https://example.com/webhook",
		Method:  "POST",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewWebhookExporter(config, logger)
	}
}

func BenchmarkWebhookExporterExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric.1", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		{Name: "test.metric.2", Value: 2.0, Type: integrations.MetricTypeCounter, Timestamp: time.Now()},
		{Name: "test.metric.3", Value: 3.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkWebhookExporterExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	_ = exporter.Init(ctx)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test log 1", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelWarn, Message: "Test log 2", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelError, Message: "Test log 3", Source: "test"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}

func BenchmarkWebhookExporterExportTraces(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.WebhookConfig{
		Enabled:    true,
		URL:        server.URL,
		RetryCount: 0,
	}

	exporter := integrations.NewWebhookExporter(config, logger)
	_ = exporter.Init(ctx)

	traces := []integrations.Trace{
		{TraceID: "trace-1", SpanID: "span-1", OperationName: "op-1", StartTime: time.Now(), Duration: 100 * time.Millisecond},
		{TraceID: "trace-2", SpanID: "span-2", OperationName: "op-2", StartTime: time.Now(), Duration: 200 * time.Millisecond},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportTraces(ctx, traces)
	}
}
