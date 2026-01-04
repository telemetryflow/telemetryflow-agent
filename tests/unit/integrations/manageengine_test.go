// package integrations_test provides unit tests for TelemetryFlow Agent ManageEngine integration.
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

// ManageEngine Exporter Tests
func TestNewManageEngineExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.ManageEngineConfig{
		Enabled: true,
		APIKey:  "test-api-key-12345",
		BaseURL: "https://opmanager.local:8060",
		Product: "opmanager",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "manageengine", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestManageEngineExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.ManageEngineConfig
		expectError bool
	}{
		{
			name: "valid config opmanager",
			config: integrations.ManageEngineConfig{
				Enabled: true,
				APIKey:  "test-api-key-12345",
				BaseURL: "https://opmanager.local:8060",
				Product: "opmanager",
			},
			expectError: false,
		},
		{
			name: "valid config site24x7",
			config: integrations.ManageEngineConfig{
				Enabled: true,
				APIKey:  "test-api-key-12345",
				Product: "site24x7",
			},
			expectError: false,
		},
		{
			name: "valid config applications_manager",
			config: integrations.ManageEngineConfig{
				Enabled: true,
				APIKey:  "test-api-key-12345",
				Product: "applications_manager",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.ManageEngineConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing api key",
			config: integrations.ManageEngineConfig{
				Enabled: true,
				BaseURL: "https://opmanager.local:8060",
			},
			expectError: true,
		},
		{
			name: "invalid product",
			config: integrations.ManageEngineConfig{
				Enabled: true,
				APIKey:  "test-api-key-12345",
				Product: "invalid_product",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewManageEngineExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManageEngineExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ManageEngineConfig{Enabled: false}
	exporter := integrations.NewManageEngineExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestManageEngineExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ManageEngineConfig{
		Enabled: true,
		APIKey:  "test-api-key-12345",
		BaseURL: "https://opmanager.local:8060",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestManageEngineExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Apikey")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled:         true,
		APIKey:          "test-api-key-12345",
		BaseURL:         server.URL,
		MetricsEndpoint: server.URL,
		Product:         "opmanager",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "cpu.usage",
			Value:     75.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server-01"},
		},
		{
			Name:      "memory.used",
			Value:     1024.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"host": "server-01"},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
}

func TestManageEngineExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Apikey")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled:        true,
		APIKey:         "test-api-key-12345",
		BaseURL:        server.URL,
		AlertsEndpoint: server.URL,
		Product:        "opmanager",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Only error traces are exported as alerts
	traces := []integrations.Trace{
		{
			TraceID:       "abc123def456",
			SpanID:        "span001",
			OperationName: "http.request",
			ServiceName:   "order-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags:          map[string]string{"error": "timeout"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)
}

func TestManageEngineExporterExportTracesNoErrors(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ManageEngineConfig{
		Enabled: true,
		APIKey:  "test-api-key-12345",
		BaseURL: "https://opmanager.local:8060",
		Product: "opmanager",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Only OK traces - should not generate alerts
	traces := []integrations.Trace{
		{
			TraceID:       "abc123def456",
			SpanID:        "span001",
			OperationName: "http.request",
			ServiceName:   "order-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ItemsExported)
}

func TestManageEngineExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Apikey")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled:      true,
		APIKey:       "test-api-key-12345",
		BaseURL:      server.URL,
		LogsEndpoint: server.URL,
		Product:      "opmanager",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
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
			Level:      integrations.LogLevelError,
			Message:    "Connection timeout",
			Source:     "db.go",
			Attributes: map[string]string{"retry_count": "3"},
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
}

func TestManageEngineExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled:         true,
		APIKey:          "test-api-key-12345",
		BaseURL:         server.URL,
		MetricsEndpoint: server.URL,
		LogsEndpoint:    server.URL,
		Product:         "opmanager",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 42.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
		Logs: []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test log", Source: "test"},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
}

func TestManageEngineConfigDefaults(t *testing.T) {
	config := integrations.ManageEngineConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.APIKey)
}

func TestManageEngineExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Apikey")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled: true,
		APIKey:  "test-api-key-12345",
		BaseURL: server.URL,
		Product: "opmanager",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "ManageEngine API accessible", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
}

func TestManageEngineExporterHealthServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled: true,
		APIKey:  "test-api-key-12345",
		BaseURL: server.URL,
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "500")
}

func TestManageEngineExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.ManageEngineConfig{
		Enabled: true,
		APIKey:  "test-api-key-12345",
		BaseURL: "http://localhost:59999",
		Timeout: 100 * time.Millisecond,
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
}

func TestManageEngineExporterWithAccountID(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled:         true,
		APIKey:          "test-api-key-12345",
		AccountID:       "account-123",
		BaseURL:         server.URL,
		MetricsEndpoint: server.URL,
		Product:         "site24x7",
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	assert.NoError(t, err)
	assert.Equal(t, "account-123", receivedHeaders.Get("X-Account-ID"))
}

func TestManageEngineSendRequestHTTPStatusCodes(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name          string
		statusCode    int
		expectSuccess bool
		expectError   bool
	}{
		{"200 OK", http.StatusOK, true, false},
		{"201 Created", http.StatusCreated, true, false},
		{"400 Bad Request", http.StatusBadRequest, false, true},
		{"401 Unauthorized", http.StatusUnauthorized, false, true},
		{"403 Forbidden", http.StatusForbidden, false, true},
		{"500 Internal Server Error", http.StatusInternalServerError, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			config := integrations.ManageEngineConfig{
				Enabled:         true,
				APIKey:          "test-api-key-12345",
				BaseURL:         server.URL,
				MetricsEndpoint: server.URL,
			}

			exporter := integrations.NewManageEngineExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)

			metrics := []integrations.Metric{
				{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
			}

			result, err := exporter.ExportMetrics(ctx, metrics)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expectSuccess, result.Success)
		})
	}
}

func TestManageEngineNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.ManageEngineConfig{
			Enabled: true,
			APIKey:  "test-api-key-12345",
			BaseURL: "https://opmanager.local:8060",
		}

		exporter := integrations.NewManageEngineExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.ManageEngineConfig{
			Enabled: false,
			APIKey:  "test-api-key-12345",
			BaseURL: "https://opmanager.local:8060",
		}

		exporter := integrations.NewManageEngineExporter(config, logger)

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
func BenchmarkNewManageEngineExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.ManageEngineConfig{
		Enabled: true,
		APIKey:  "test-api-key-12345",
		BaseURL: "https://opmanager.local:8060",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewManageEngineExporter(config, logger)
	}
}

func BenchmarkManageEngineExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.ManageEngineConfig{
		Enabled:         true,
		APIKey:          "test-api-key-12345",
		BaseURL:         server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewManageEngineExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}
