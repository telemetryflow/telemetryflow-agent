// Package integrations_test provides unit tests for TelemetryFlow Agent OpenObserve integration.
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

func TestNewOpenObserveExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.OpenObserveConfig{
		Enabled:      true,
		Endpoint:     "http://localhost:5080",
		Username:     "admin",
		Password:     "admin-password",
		Organization: "default",
		StreamName:   "default",
	}

	exporter := integrations.NewOpenObserveExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "openobserve", exporter.Name())
	assert.Equal(t, "observability", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestOpenObserveExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.OpenObserveConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.OpenObserveConfig{
				Enabled:      true,
				Endpoint:     "http://localhost:5080",
				Username:     "admin",
				Password:     "admin-password",
				Organization: "default",
			},
			expectError: false,
		},
		{
			name: "valid config with all endpoints",
			config: integrations.OpenObserveConfig{
				Enabled:         true,
				Endpoint:        "http://localhost:5080",
				Username:        "admin",
				Password:        "admin-password",
				Organization:    "default",
				StreamName:      "telemetry",
				MetricsEndpoint: "http://localhost:5080/api/default/v1/metrics",
				TracesEndpoint:  "http://localhost:5080/api/default/v1/traces",
				LogsEndpoint:    "http://localhost:5080/api/default/v1/logs",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.OpenObserveConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing credentials",
			config: integrations.OpenObserveConfig{
				Enabled:  true,
				Endpoint: "http://localhost:5080",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewOpenObserveExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOpenObserveExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.OpenObserveConfig{Enabled: false}
	exporter := integrations.NewOpenObserveExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestOpenObserveExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.OpenObserveConfig{
		Enabled:      true,
		Endpoint:     "http://localhost:5080",
		Username:     "admin",
		Password:     "admin-password",
		Organization: "default",
	}

	exporter := integrations.NewOpenObserveExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestOpenObserveExporterExportMetrics(t *testing.T) {
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

	config := integrations.OpenObserveConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		Username:        "admin",
		Password:        "admin-password",
		Organization:    "default",
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewOpenObserveExporter(config, logger)
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

func TestOpenObserveExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.OpenObserveConfig{
		Enabled:        true,
		Endpoint:       server.URL,
		Username:       "admin",
		Password:       "admin-password",
		Organization:   "default",
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewOpenObserveExporter(config, logger)
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

func TestOpenObserveExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.OpenObserveConfig{
		Enabled:      true,
		Endpoint:     server.URL,
		Username:     "admin",
		Password:     "admin-password",
		Organization: "default",
		LogsEndpoint: server.URL,
	}

	exporter := integrations.NewOpenObserveExporter(config, logger)
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

func TestOpenObserveExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.OpenObserveConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		Username:        "admin",
		Password:        "admin-password",
		Organization:    "default",
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		LogsEndpoint:    server.URL,
	}

	exporter := integrations.NewOpenObserveExporter(config, logger)
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

func TestOpenObserveNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.OpenObserveConfig{
			Enabled:      true,
			Endpoint:     "http://localhost:5080",
			Username:     "admin",
			Password:     "admin-password",
			Organization: "default",
		}

		exporter := integrations.NewOpenObserveExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.OpenObserveConfig{
			Enabled:      false,
			Endpoint:     "http://localhost:5080",
			Username:     "admin",
			Password:     "admin-password",
			Organization: "default",
		}

		exporter := integrations.NewOpenObserveExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})
}

func TestOpenObserveConfigDefaults(t *testing.T) {
	config := integrations.OpenObserveConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.Username)
	assert.Empty(t, config.Password)
	assert.Empty(t, config.Organization)
}

func BenchmarkNewOpenObserveExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.OpenObserveConfig{
		Enabled:      true,
		Endpoint:     "http://localhost:5080",
		Username:     "admin",
		Password:     "admin-password",
		Organization: "default",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewOpenObserveExporter(config, logger)
	}
}
