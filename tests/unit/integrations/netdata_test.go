// Package integrations_test provides unit tests for TelemetryFlow Agent Netdata integration.
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

func TestNewNetdataExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.NetdataConfig{
		Enabled:  true,
		Endpoint: "https://api.netdata.cloud",
		APIToken: "test-token",
		SpaceID:  "space-123",
	}

	exporter := integrations.NewNetdataExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "netdata", exporter.Name())
	assert.Equal(t, "monitoring", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestNetdataExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.NetdataConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.NetdataConfig{
				Enabled:  true,
				Endpoint: "https://api.netdata.cloud",
			},
			expectError: false,
		},
		{
			name: "valid config with API token",
			config: integrations.NetdataConfig{
				Enabled:  true,
				Endpoint: "https://api.netdata.cloud",
				APIToken: "netdata-token-123",
				SpaceID:  "space-001",
				RoomID:   "room-001",
			},
			expectError: false,
		},
		{
			name: "valid self-hosted config",
			config: integrations.NetdataConfig{
				Enabled:  true,
				Endpoint: "http://localhost:19999",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.NetdataConfig{
				Enabled: false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewNetdataExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNetdataExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NetdataConfig{Enabled: false}
	exporter := integrations.NewNetdataExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestNetdataExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NetdataConfig{
		Enabled:  true,
		Endpoint: "https://api.netdata.cloud",
	}

	exporter := integrations.NewNetdataExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestNetdataExporterExportMetrics(t *testing.T) {
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

	config := integrations.NetdataConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewNetdataExporter(config, logger)
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

func TestNetdataExporterExportTracesNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NetdataConfig{
		Enabled:  true,
		Endpoint: "https://api.netdata.cloud",
	}

	exporter := integrations.NewNetdataExporter(config, logger)
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
	require.NoError(t, err) // Method returns error within result, not as err
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "traces not supported")
}

func TestNetdataExporterExportLogsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.NetdataConfig{
		Enabled:  true,
		Endpoint: "https://api.netdata.cloud",
	}

	exporter := integrations.NewNetdataExporter(config, logger)
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
	require.NoError(t, err) // Method returns error within result, not as err
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "logs not supported")
}

func TestNetdataExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.NetdataConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewNetdataExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 42.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)
}

func TestNetdataExporterExportWithTags(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.NetdataConfig{
		Enabled:         true,
		Endpoint:        server.URL,
		MetricsEndpoint: server.URL,
		SpaceID:         "space-001",
		RoomID:          "room-001",
		Tags: map[string]string{
			"environment": "production",
			"region":      "us-east-1",
		},
	}

	exporter := integrations.NewNetdataExporter(config, logger)
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
}

func TestNetdataNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.NetdataConfig{
			Enabled:  true,
			Endpoint: "https://api.netdata.cloud",
		}

		exporter := integrations.NewNetdataExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.NetdataConfig{
			Enabled:  false,
			Endpoint: "https://api.netdata.cloud",
		}

		exporter := integrations.NewNetdataExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})
}

func TestNetdataConfigDefaults(t *testing.T) {
	config := integrations.NetdataConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.APIToken)
	assert.Empty(t, config.SpaceID)
	assert.Empty(t, config.RoomID)
}

func TestNetdataExporterHealthWithServer(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "/api/v1/health")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.NetdataConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewNetdataExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "Netdata API accessible", status.Message)
}

func BenchmarkNewNetdataExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.NetdataConfig{
		Enabled:  true,
		Endpoint: "https://api.netdata.cloud",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewNetdataExporter(config, logger)
	}
}
