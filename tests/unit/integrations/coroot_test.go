// Package integrations_test provides unit tests for TelemetryFlow Agent Coroot integration.
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

func TestNewCorootExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.CorootConfig{
		Enabled:     true,
		Endpoint:    "http://localhost:8080",
		ServiceName: "test-service",
	}

	exporter := integrations.NewCorootExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "coroot", exporter.Name())
	assert.Equal(t, "observability", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestCorootExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.CorootConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.CorootConfig{
				Enabled:  true,
				Endpoint: "http://localhost:8080",
			},
			expectError: false,
		},
		{
			name: "valid config with API key",
			config: integrations.CorootConfig{
				Enabled:  true,
				Endpoint: "https://coroot.example.com",
				APIKey:   "coroot-api-key-123",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.CorootConfig{
				Enabled: false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewCorootExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCorootExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CorootConfig{Enabled: false}
	exporter := integrations.NewCorootExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestCorootExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CorootConfig{
		Enabled:  true,
		Endpoint: "http://localhost:8080",
	}

	exporter := integrations.NewCorootExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestCorootExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.CorootConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewCorootExporter(config, logger)
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

func TestCorootExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.CorootConfig{
		Enabled:        true,
		Endpoint:       server.URL,
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewCorootExporter(config, logger)
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

func TestCorootExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.CorootConfig{
		Enabled:      true,
		Endpoint:     server.URL,
		LogsEndpoint: server.URL,
	}

	exporter := integrations.NewCorootExporter(config, logger)
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

func TestCorootExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.CorootConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
	}

	exporter := integrations.NewCorootExporter(config, logger)
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

func TestCorootNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.CorootConfig{
			Enabled:  true,
			Endpoint: "http://localhost:8080",
		}

		exporter := integrations.NewCorootExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.CorootConfig{
			Enabled:  false,
			Endpoint: "http://localhost:8080",
		}

		exporter := integrations.NewCorootExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})
}

func TestCorootConfigDefaults(t *testing.T) {
	config := integrations.CorootConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.APIKey)
}

func BenchmarkNewCorootExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.CorootConfig{
		Enabled:  true,
		Endpoint: "http://localhost:8080",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewCorootExporter(config, logger)
	}
}
