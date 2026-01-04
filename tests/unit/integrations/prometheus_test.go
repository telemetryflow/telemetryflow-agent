// package integrations_test provides unit tests for TelemetryFlow Agent Prometheus integration.
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

// Prometheus Exporter Tests
func TestNewPrometheusExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "prometheus", exporter.Name())
	assert.Equal(t, "metrics", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestPrometheusExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.PrometheusConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.PrometheusConfig{
				Enabled:  true,
				Endpoint: "http://localhost:9090",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.PrometheusConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing endpoint",
			config: integrations.PrometheusConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewPrometheusExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPrometheusExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{Enabled: false}
	exporter := integrations.NewPrometheusExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestPrometheusExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestPrometheusExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that accepts POST requests and returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test metrics
	metrics := []integrations.Metric{
		{Name: "test.metric.1", Value: 42.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		{Name: "test.metric.2", Value: 100.5, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		{Name: "test.metric.3", Value: 0.75, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
}

func TestPrometheusExporterExportMetricsError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns an error status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test metrics
	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

// Test config defaults for Prometheus
func TestPrometheusConfigDefaults(t *testing.T) {
	config := integrations.PrometheusConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.Endpoint)
}

// Comprehensive Health Tests for Prometheus
func TestPrometheusExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 200 OK for HEAD requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "HEAD", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "connected", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.NotZero(t, status.Latency)
	assert.NotNil(t, status.Details)
	assert.Equal(t, http.StatusOK, status.Details["status_code"])
}

func TestPrometheusExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	// Prometheus Health returns true even for 500 status since it checks connectivity
	assert.True(t, status.Healthy)
	assert.NotNil(t, status.Details)
	assert.Equal(t, http.StatusInternalServerError, status.Details["status_code"])
}

func TestPrometheusExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that returns 503 Service Unavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.NotNil(t, status.Details)
	assert.Equal(t, http.StatusServiceUnavailable, status.Details["status_code"])
}

func TestPrometheusExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Create a mock HTTP server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
		Timeout:  5 * time.Millisecond,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestPrometheusExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a non-existent server URL to simulate network error
	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:59999", // Unlikely to be in use
		Timeout:  100 * time.Millisecond,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestPrometheusExporterHealthCustomEndpoint(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server with custom endpoint path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL + "/custom/health/path",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

func TestPrometheusExporterHealthWithAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:     true,
		Endpoint:    server.URL,
		Username:    "user",
		Password:    "pass",
		BearerToken: "token123",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

// Tests for escapePrometheusName helper function
func TestEscapePrometheusName(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a test server to capture the payload
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
		JobName:  "test-job",
		ExternalLabels: map[string]string{
			"label-with-dash":  "value1",
			"label.with.dot":   "value2",
			"label with space": "value3",
			"123startsWithNum": "value4",
			"valid_label":      "value5",
			"special!@#$chars": "value6",
		},
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "test.metric",
			Value:     42.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags: map[string]string{
				"tag-with-dash":  "tagvalue1",
				"tag.with.dot":   "tagvalue2",
				"tag with space": "tagvalue3",
				"9startsWithNum": "tagvalue4",
			},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify that invalid characters are escaped to underscores
	bodyStr := string(receivedBody)
	assert.Contains(t, bodyStr, "label_with_dash")
	assert.Contains(t, bodyStr, "label_with_dot")
	assert.Contains(t, bodyStr, "label_with_space")
	assert.Contains(t, bodyStr, "_123startsWithNum")
	assert.Contains(t, bodyStr, "valid_label")
	assert.Contains(t, bodyStr, "special____chars")
	assert.Contains(t, bodyStr, "tag_with_dash")
	assert.Contains(t, bodyStr, "tag_with_dot")
	assert.Contains(t, bodyStr, "tag_with_space")
	assert.Contains(t, bodyStr, "_9startsWithNum")
}

func TestEscapePrometheusNameStartsWithDigit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
		ExternalLabels: map[string]string{
			"0label": "value0",
			"1label": "value1",
			"9label": "value9",
		},
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "test_metric",
			Value:     1.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	bodyStr := string(receivedBody)
	// Labels starting with digits should be prefixed with underscore
	assert.Contains(t, bodyStr, "_0label")
	assert.Contains(t, bodyStr, "_1label")
	assert.Contains(t, bodyStr, "_9label")
}

func TestEscapePrometheusNameEmptyAndSpecialCases(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
		ExternalLabels: map[string]string{
			"___":       "underscores",
			"a_b_c":     "mixed",
			"UPPERCASE": "upper",
			"MixedCase": "mixed_case",
		},
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "test",
			Value:     1.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	bodyStr := string(receivedBody)
	assert.Contains(t, bodyStr, "___")
	assert.Contains(t, bodyStr, "a_b_c")
	assert.Contains(t, bodyStr, "UPPERCASE")
	assert.Contains(t, bodyStr, "MixedCase")
}

func TestPrometheusExporterHealthLatencyMeasurement(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock server with a small delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.GreaterOrEqual(t, status.Latency.Milliseconds(), int64(10))
}

// Benchmark tests
func BenchmarkNewPrometheusExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewPrometheusExporter(config, logger)
	}

}

func BenchmarkPrometheusHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}

func TestPrometheusExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create a mock HTTP server that accepts POST requests and returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: server.URL,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with metrics
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "test.metric.gauge",
				Value:     42.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
			{
				Name:      "test.metric.counter",
				Value:     100.0,
				Type:      integrations.MetricTypeCounter,
				Timestamp: time.Now(),
			},
		},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
}

func TestPrometheusExporterExportEmptyMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with no metrics
	telemetryData := &integrations.TelemetryData{
		Metrics: []integrations.Metric{},
	}

	result, err := exporter.Export(ctx, telemetryData)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func TestPrometheusExporterExportNotEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{
		Enabled: false,
	}

	exporter := integrations.NewPrometheusExporter(config, logger)

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
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, integrations.ErrNotEnabled)
}

func TestPrometheusExporterExportTracesNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
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
	assert.Contains(t, err.Error(), "prometheus does not support traces export")
}

func TestPrometheusExporterExportLogsNotSupported(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PrometheusConfig{
		Enabled:  true,
		Endpoint: "http://localhost:9090",
	}

	exporter := integrations.NewPrometheusExporter(config, logger)
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
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "prometheus does not support logs export")
}
