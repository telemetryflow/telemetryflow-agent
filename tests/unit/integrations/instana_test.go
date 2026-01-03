// package integrations_test provides unit tests for TelemetryFlow Agent IBM Instana integration.
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

// Instana Exporter Tests
func TestNewInstanaExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.InstanaConfig{
		Enabled:     true,
		AgentKey:    "test-agent-key-12345",
		EndpointURL: "https://serverless-us-west-2.instana.io",
		Zone:        "us-west-2",
	}

	exporter := integrations.NewInstanaExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "instana", exporter.Name())
	assert.NotEmpty(t, exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestInstanaExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.InstanaConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.InstanaConfig{
				Enabled:     true,
				AgentKey:    "test-agent-key-12345",
				EndpointURL: "https://serverless-us-west-2.instana.io",
			},
			expectError: false,
		},
		{
			name: "valid config with zone",
			config: integrations.InstanaConfig{
				Enabled:     true,
				AgentKey:    "test-agent-key-12345",
				EndpointURL: "https://serverless-us-west-2.instana.io",
				Zone:        "us-west-2",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.InstanaConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing agent key",
			config: integrations.InstanaConfig{
				Enabled:     true,
				EndpointURL: "https://serverless-us-west-2.instana.io",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewInstanaExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInstanaExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.InstanaConfig{Enabled: false}
	exporter := integrations.NewInstanaExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestInstanaExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.InstanaConfig{
		Enabled:     true,
		AgentKey:    "test-agent-key-12345",
		EndpointURL: "https://serverless-us-west-2.instana.io",
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestInstanaExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("X-INSTANA-KEY"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:         true,
		AgentKey:        "test-agent-key-12345",
		EndpointURL:     server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
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

func TestInstanaExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("X-INSTANA-KEY"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:        true,
		AgentKey:       "test-agent-key-12345",
		EndpointURL:    server.URL,
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
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
		{
			TraceID:       "abc123def456",
			SpanID:        "span002",
			ParentSpanID:  "span001",
			OperationName: "db.query",
			ServiceName:   "order-service",
			StartTime:     time.Now().Add(-50 * time.Millisecond),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags:          map[string]string{"db.type": "postgresql"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
}

func TestInstanaExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NotEmpty(t, r.Header.Get("X-INSTANA-KEY"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Greater(t, len(body), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:        true,
		AgentKey:       "test-agent-key-12345",
		EndpointURL:    server.URL,
		EventsEndpoint: server.URL,
		ServiceName:    "test-service",
	}

	exporter := integrations.NewInstanaExporter(config, logger)
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
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelWarn,
			Message:    "High memory usage",
			Source:     "monitor.go",
			Attributes: map[string]string{"memory_percent": "85"},
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
}

func TestInstanaExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:         true,
		AgentKey:        "test-agent-key-12345",
		EndpointURL:     server.URL,
		MetricsEndpoint: server.URL,
		TracesEndpoint:  server.URL,
		EventsEndpoint:  server.URL,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
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

func TestInstanaConfigDefaults(t *testing.T) {
	config := integrations.InstanaConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.AgentKey)
}

func TestInstanaExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.NotEmpty(t, r.Header.Get("X-INSTANA-KEY"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:     true,
		AgentKey:    "test-agent-key-12345",
		EndpointURL: server.URL,
		Zone:        "us-west-2",
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "IBM Instana API accessible", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
}

func TestInstanaExporterHealthServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:     true,
		AgentKey:    "test-agent-key-12345",
		EndpointURL: server.URL,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "500")
}

func TestInstanaExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.InstanaConfig{
		Enabled:     true,
		AgentKey:    "test-agent-key-12345",
		EndpointURL: "http://localhost:59999",
		Timeout:     100 * time.Millisecond,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
}

func TestInstanaExporterWithZoneHeader(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:         true,
		AgentKey:        "test-agent-key-12345",
		EndpointURL:     server.URL,
		MetricsEndpoint: server.URL,
		Zone:            "eu-west-1",
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	assert.NoError(t, err)
	assert.Equal(t, "eu-west-1", receivedHeaders.Get("X-INSTANA-ZONE"))
}

func TestInstanaSendRequestHTTPStatusCodes(t *testing.T) {
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

			config := integrations.InstanaConfig{
				Enabled:         true,
				AgentKey:        "test-agent-key-12345",
				EndpointURL:     server.URL,
				MetricsEndpoint: server.URL,
			}

			exporter := integrations.NewInstanaExporter(config, logger)
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

func TestInstanaNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.InstanaConfig{
			Enabled:     true,
			AgentKey:    "test-agent-key-12345",
			EndpointURL: "https://serverless-us-west-2.instana.io",
		}

		exporter := integrations.NewInstanaExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export metrics not enabled", func(t *testing.T) {
		config := integrations.InstanaConfig{
			Enabled:     false,
			AgentKey:    "test-agent-key-12345",
			EndpointURL: "https://serverless-us-west-2.instana.io",
		}

		exporter := integrations.NewInstanaExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})

	t.Run("export traces not initialized", func(t *testing.T) {
		config := integrations.InstanaConfig{
			Enabled:     true,
			AgentKey:    "test-agent-key-12345",
			EndpointURL: "https://serverless-us-west-2.instana.io",
		}

		exporter := integrations.NewInstanaExporter(config, logger)

		traces := []integrations.Trace{
			{TraceID: "trace-1", SpanID: "span-1", OperationName: "test", StartTime: time.Now(), Duration: 100 * time.Millisecond},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export logs not initialized", func(t *testing.T) {
		config := integrations.InstanaConfig{
			Enabled:     true,
			AgentKey:    "test-agent-key-12345",
			EndpointURL: "https://serverless-us-west-2.instana.io",
		}

		exporter := integrations.NewInstanaExporter(config, logger)

		logs := []integrations.LogEntry{
			{Level: integrations.LogLevelInfo, Message: "test", Timestamp: time.Now()},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})
}

func TestInstanaTraceErrorFlag(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:        true,
		AgentKey:       "test-agent-key-12345",
		EndpointURL:    server.URL,
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "trace-error",
			SpanID:        "span-error",
			OperationName: "failing.operation",
			ServiceName:   "error-service",
			StartTime:     time.Now(),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusError,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify error flag is set in the payload
	var payload map[string]interface{}
	err = json.Unmarshal(receivedBody, &payload)
	require.NoError(t, err)

	spans := payload["spans"].([]interface{})
	span := spans[0].(map[string]interface{})
	assert.Equal(t, true, span["error"])
	assert.Equal(t, float64(1), span["ec"])
}

// Benchmark tests
func BenchmarkNewInstanaExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.InstanaConfig{
		Enabled:     true,
		AgentKey:    "test-agent-key-12345",
		EndpointURL: "https://serverless-us-west-2.instana.io",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewInstanaExporter(config, logger)
	}
}

func BenchmarkInstanaExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:         true,
		AgentKey:        "test-agent-key-12345",
		EndpointURL:     server.URL,
		MetricsEndpoint: server.URL,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkInstanaExportTraces(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.InstanaConfig{
		Enabled:        true,
		AgentKey:       "test-agent-key-12345",
		EndpointURL:    server.URL,
		TracesEndpoint: server.URL,
	}

	exporter := integrations.NewInstanaExporter(config, logger)
	_ = exporter.Init(ctx)

	traces := []integrations.Trace{
		{TraceID: "trace-1", SpanID: "span-1", OperationName: "test", StartTime: time.Now(), Duration: 100 * time.Millisecond},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportTraces(ctx, traces)
	}
}
