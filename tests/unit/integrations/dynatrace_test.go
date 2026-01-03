// package integrations_test provides unit tests for TelemetryFlow Agent Dynatrace integration.
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

// Dynatrace Exporter Tests
func TestNewDynatraceExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentID:  "abc12345",
		EnvironmentURL: "https://abc12345.live.dynatrace.com",
	}

	exporter := integrations.NewDynatraceExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "dynatrace", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestDynatraceExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.DynatraceConfig
		expectError bool
	}{
		{
			name: "valid config with environment URL",
			config: integrations.DynatraceConfig{
				Enabled:        true,
				APIToken:       "dt0c01.test-token",
				EnvironmentURL: "https://abc12345.live.dynatrace.com",
			},
			expectError: false,
		},
		{
			name: "valid config with environment ID",
			config: integrations.DynatraceConfig{
				Enabled:       true,
				APIToken:      "dt0c01.test-token",
				EnvironmentID: "abc12345",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.DynatraceConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing api token",
			config: integrations.DynatraceConfig{
				Enabled:        true,
				EnvironmentURL: "https://abc12345.live.dynatrace.com",
			},
			expectError: true,
		},
		{
			name: "missing environment",
			config: integrations.DynatraceConfig{
				Enabled:  true,
				APIToken: "dt0c01.test-token",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewDynatraceExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDynatraceExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.DynatraceConfig{Enabled: false}
	exporter := integrations.NewDynatraceExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestDynatraceExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentURL: "https://abc12345.live.dynatrace.com",
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestDynatraceExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Api-Token")
		assert.Equal(t, "text/plain; charset=utf-8", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.DynatraceConfig{
		Enabled:         true,
		APIToken:        "dt0c01.test-token",
		EnvironmentURL:  server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
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

func TestDynatraceExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Api-Token")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentURL: server.URL,
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
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
			Tags:          map[string]string{"http.method": "GET"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)
}

func TestDynatraceExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Api-Token")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentURL: server.URL,
		LogsEndpoint:   server.URL,
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
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

func TestDynatraceExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.DynatraceConfig{
		Enabled:         true,
		APIToken:        "dt0c01.test-token",
		EnvironmentURL:  server.URL,
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 42.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
		Traces: []integrations.Trace{
			{TraceID: "trace-001", SpanID: "span-001", OperationName: "test", ServiceName: "test-svc", StartTime: time.Now(), Duration: 100 * time.Millisecond, Status: integrations.TraceStatusOK},
		},
		Logs: []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test log", Source: "test"},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
}

func TestDynatraceConfigDefaults(t *testing.T) {
	config := integrations.DynatraceConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.APIToken)
}

func TestDynatraceExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Api-Token")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "1.234"})
	}))
	defer server.Close()

	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentURL: server.URL,
		EnvironmentID:  "test-env",
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "Dynatrace API accessible", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
}

func TestDynatraceExporterHealthServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentURL: server.URL,
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "500")
}

func TestDynatraceExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentURL: "http://localhost:59999",
		Timeout:        100 * time.Millisecond,
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
}

func TestDynatraceSendRequestHTTPStatusCodes(t *testing.T) {
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

			config := integrations.DynatraceConfig{
				Enabled:         true,
				APIToken:        "dt0c01.test-token",
				EnvironmentURL:  server.URL,
				MetricsEndpoint: server.URL,
			}

			exporter := integrations.NewDynatraceExporter(config, logger)
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

func TestDynatraceNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.DynatraceConfig{
			Enabled:        true,
			APIToken:       "dt0c01.test-token",
			EnvironmentURL: "https://test.dynatrace.com",
		}

		exporter := integrations.NewDynatraceExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.DynatraceConfig{
			Enabled:        false,
			APIToken:       "dt0c01.test-token",
			EnvironmentURL: "https://test.dynatrace.com",
		}

		exporter := integrations.NewDynatraceExporter(config, logger)

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
func BenchmarkNewDynatraceExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.DynatraceConfig{
		Enabled:        true,
		APIToken:       "dt0c01.test-token",
		EnvironmentURL: "https://test.dynatrace.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewDynatraceExporter(config, logger)
	}
}

func BenchmarkDynatraceExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.DynatraceConfig{
		Enabled:         true,
		APIToken:        "dt0c01.test-token",
		EnvironmentURL:  server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewDynatraceExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}
