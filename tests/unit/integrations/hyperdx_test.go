// Package integrations_test provides unit tests for TelemetryFlow Agent HyperDX integration.
package integrations_test

import (
	"context"
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

func TestNewHyperDXExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.HyperDXConfig{
		Enabled:     true,
		Endpoint:    "https://in-otel.hyperdx.io",
		APIKey:      "test-api-key",
		ServiceName: "test-service",
	}

	exporter := integrations.NewHyperDXExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "hyperdx", exporter.Name())
	assert.Equal(t, "observability", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestHyperDXExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.HyperDXConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.HyperDXConfig{
				Enabled:  true,
				Endpoint: "https://in-otel.hyperdx.io",
				APIKey:   "test-api-key",
			},
			expectError: false,
		},
		{
			name: "valid config with all endpoints",
			config: integrations.HyperDXConfig{
				Enabled:         true,
				Endpoint:        "https://in-otel.hyperdx.io",
				APIKey:          "test-api-key",
				MetricsEndpoint: "https://in-otel.hyperdx.io/v1/metrics",
				TracesEndpoint:  "https://in-otel.hyperdx.io/v1/traces",
				LogsEndpoint:    "https://in-otel.hyperdx.io/v1/logs",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.HyperDXConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing API key",
			config: integrations.HyperDXConfig{
				Enabled:  true,
				Endpoint: "https://in-otel.hyperdx.io",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewHyperDXExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHyperDXExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.HyperDXConfig{Enabled: false}
	exporter := integrations.NewHyperDXExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestHyperDXExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.HyperDXConfig{
		Enabled:  true,
		Endpoint: "https://in-otel.hyperdx.io",
		APIKey:   "test-api-key",
	}

	exporter := integrations.NewHyperDXExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestHyperDXExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get("Authorization"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.HyperDXConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		APIKey:          "test-api-key",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewHyperDXExporter(config, logger)
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
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)
}

func TestHyperDXExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.HyperDXConfig{
		Enabled:        true,
		Endpoint:       server.URL,
		APIKey:         "test-api-key",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewHyperDXExporter(config, logger)
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
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestHyperDXExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.HyperDXConfig{
		Enabled:      true,
		Endpoint:     server.URL,
		APIKey:       "test-api-key",
		LogsEndpoint: server.URL,
	}

	exporter := integrations.NewHyperDXExporter(config, logger)
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
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestHyperDXExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.HyperDXConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		APIKey:          "test-api-key",
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
	}

	exporter := integrations.NewHyperDXExporter(config, logger)
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

func TestHyperDXNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.HyperDXConfig{
			Enabled:  true,
			Endpoint: "https://in-otel.hyperdx.io",
			APIKey:   "test-api-key",
		}

		exporter := integrations.NewHyperDXExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.HyperDXConfig{
			Enabled:  false,
			Endpoint: "https://in-otel.hyperdx.io",
			APIKey:   "test-api-key",
		}

		exporter := integrations.NewHyperDXExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})
}

func TestHyperDXConfigDefaults(t *testing.T) {
	config := integrations.HyperDXConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.APIKey)
}

func BenchmarkNewHyperDXExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.HyperDXConfig{
		Enabled:  true,
		Endpoint: "https://in-otel.hyperdx.io",
		APIKey:   "test-api-key",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewHyperDXExporter(config, logger)
	}
}
