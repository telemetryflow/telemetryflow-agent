// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"context"
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

// TestNewPerconaExporter tests the NewPerconaExporter constructor
func TestNewPerconaExporter(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name           string
		config         integrations.PerconaConfig
		expectedName   string
		expectedType   string
		expectedEnable bool
	}{
		{
			name: "enabled config with API key",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://localhost:9090",
				APIKey:    "test-api-key",
				NodeID:    "node-001",
			},
			expectedName:   "percona",
			expectedType:   "database",
			expectedEnable: true,
		},
		{
			name: "enabled config with username/password",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://localhost:9090",
				Username:  "admin",
				Password:  "password",
				NodeID:    "node-001",
			},
			expectedName:   "percona",
			expectedType:   "database",
			expectedEnable: true,
		},
		{
			name: "disabled config",
			config: integrations.PerconaConfig{
				Enabled: false,
			},
			expectedName:   "percona",
			expectedType:   "database",
			expectedEnable: false,
		},
		{
			name: "config with all options",
			config: integrations.PerconaConfig{
				Enabled:        true,
				ServerURL:      "https://pmm.example.com",
				APIKey:         "full-api-key",
				NodeID:         "node-full",
				NodeName:       "production-node",
				NodeType:       "mysql",
				Environment:    "production",
				Cluster:        "main-cluster",
				ReplicationSet: "rs0",
				CustomLabels:   map[string]string{"team": "platform"},
				TLSEnabled:     true,
				TLSSkipVerify:  false,
				Timeout:        60 * time.Second,
				BatchSize:      500,
				FlushInterval:  5 * time.Second,
				Headers:        map[string]string{"X-Custom-Header": "value"},
			},
			expectedName:   "percona",
			expectedType:   "database",
			expectedEnable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewPerconaExporter(tt.config, logger)

			require.NotNil(t, exporter)
			assert.Equal(t, tt.expectedName, exporter.Name())
			assert.Equal(t, tt.expectedType, exporter.Type())
			assert.Equal(t, tt.expectedEnable, exporter.IsEnabled())
			assert.Contains(t, exporter.SupportedDataTypes(), integrations.DataTypeMetrics)
		})
	}
}

// TestNewPerconaExporterWithNilLogger tests constructor with nil logger
func TestNewPerconaExporterWithNilLogger(t *testing.T) {
	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, nil)

	require.NotNil(t, exporter)
	assert.Equal(t, "percona", exporter.Name())
}

// TestPerconaExporterInit tests the Init method
func TestPerconaExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.PerconaConfig
		expectError bool
	}{
		{
			name: "valid config with API key",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://localhost:9090",
				APIKey:    "test-api-key",
			},
			expectError: false,
		},
		{
			name: "valid config with username/password",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://localhost:9090",
				Username:  "admin",
				Password:  "password",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.PerconaConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing server_url",
			config: integrations.PerconaConfig{
				Enabled: true,
				APIKey:  "test-api-key",
			},
			expectError: true,
		},
		{
			name: "missing auth",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://localhost:9090",
			},
			expectError: true,
		},
		{
			name: "missing password with username",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://localhost:9090",
				Username:  "admin",
			},
			expectError: true,
		},
		{
			name: "missing username with password",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://localhost:9090",
				Password:  "password",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewPerconaExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPerconaExporterInitDefaults tests that Init sets proper defaults
func TestPerconaExporterInitDefaults(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
		// NodeType, Timeout, BatchSize, FlushInterval intentionally not set
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())
}

// TestPerconaExporterValidate tests the Validate method
func TestPerconaExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.PerconaConfig
		expectError bool
	}{
		{
			name: "valid config with API key",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://pmm.example.com",
				APIKey:    "valid-api-key",
			},
			expectError: false,
		},
		{
			name: "valid config with basic auth",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://pmm.example.com",
				Username:  "admin",
				Password:  "secret",
			},
			expectError: false,
		},
		{
			name: "disabled - should skip validation",
			config: integrations.PerconaConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing server_url",
			config: integrations.PerconaConfig{
				Enabled: true,
				APIKey:  "some-key",
			},
			expectError: true,
		},
		{
			name: "missing authentication",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://pmm.example.com",
			},
			expectError: true,
		},
		{
			name: "partial basic auth - missing password",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://pmm.example.com",
				Username:  "admin",
			},
			expectError: true,
		},
		{
			name: "partial basic auth - missing username",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://pmm.example.com",
				Password:  "secret",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewPerconaExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
				var validationErr *integrations.ValidationError
				assert.ErrorAs(t, err, &validationErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPerconaConfigValidate tests the PerconaConfig.Validate method directly
func TestPerconaConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      integrations.PerconaConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "http://pmm.example.com",
				APIKey:    "valid-key",
			},
			expectError: false,
		},
		{
			name: "disabled config skips validation",
			config: integrations.PerconaConfig{
				Enabled: false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPerconaExporterExport tests the Export method
func TestPerconaExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/metrics", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer")

		// Read body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)

		// Verify JSON structure
		var batch map[string]interface{}
		err = json.Unmarshal(body, &batch)
		require.NoError(t, err)
		assert.Contains(t, batch, "metrics")

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
		NodeID:    "node-001",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create TelemetryData with metrics
	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "mysql.queries_per_second",
				Value:     1234.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"db": "production"},
			},
			{
				Name:      "mysql.connections_active",
				Value:     42.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		},
		Timestamp: time.Now(),
		AgentID:   "agent-001",
		Hostname:  "db-server-01",
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 2, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

// TestPerconaExporterExportDisabled tests Export when disabled
func TestPerconaExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled: false,
	}

	exporter := integrations.NewPerconaExporter(config, logger)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	assert.Nil(t, result)
}

// TestPerconaExporterExportEmptyData tests Export with empty metrics
func TestPerconaExporterExportEmptyData(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Export with empty metrics
	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{},
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

// TestPerconaExporterExportMetrics tests the ExportMetrics method
func TestPerconaExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/metrics", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:        true,
		ServerURL:      server.URL,
		APIKey:         "test-api-key",
		NodeID:         "node-001",
		NodeName:       "test-node",
		NodeType:       "mysql",
		Environment:    "testing",
		Cluster:        "test-cluster",
		ReplicationSet: "rs0",
		CustomLabels:   map[string]string{"team": "platform", "region": "us-east"},
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "mysql.queries_per_second",
			Value:     1234.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"db": "production", "table": "users"},
		},
		{
			Name:      "mysql.connections_active",
			Value:     42.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		},
		{
			Name:      "mysql.bytes_received",
			Value:     1024000.0,
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
	assert.Greater(t, result.Duration, time.Duration(0))

	// Verify the payload structure
	var batch map[string]interface{}
	err = json.Unmarshal(receivedBody, &batch)
	require.NoError(t, err)
	assert.Contains(t, batch, "metrics")

	metricsArr := batch["metrics"].([]interface{})
	assert.Len(t, metricsArr, 3)

	// Verify first metric has expected labels
	firstMetric := metricsArr[0].(map[string]interface{})
	assert.Equal(t, "mysql.queries_per_second", firstMetric["metric_name"])
	labels := firstMetric["labels"].(map[string]interface{})
	assert.Equal(t, "node-001", labels["node_id"])
	assert.Equal(t, "test-node", labels["node_name"])
	assert.Equal(t, "mysql", labels["node_type"])
	assert.Equal(t, "testing", labels["environment"])
	assert.Equal(t, "test-cluster", labels["cluster"])
	assert.Equal(t, "rs0", labels["replication_set"])
	assert.Equal(t, "platform", labels["team"])
	assert.Equal(t, "production", labels["db"])
}

// TestPerconaExporterExportMetricsDisabled tests ExportMetrics when disabled
func TestPerconaExporterExportMetricsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled: false,
	}

	exporter := integrations.NewPerconaExporter(config, logger)

	metrics := []integrations.Metric{
		{Name: "test", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	assert.Nil(t, result)
}

// TestPerconaExporterExportMetricsNotInitialized tests ExportMetrics when not initialized
func TestPerconaExporterExportMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	// Don't call Init()

	metrics := []integrations.Metric{
		{Name: "test", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	assert.Nil(t, result)
}

// TestPerconaExporterExportMetricsServerError tests ExportMetrics with server error
func TestPerconaExporterExportMetricsServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
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
	assert.Greater(t, result.BytesSent, int64(0))
}

// TestPerconaExporterExportMetricsUnauthorized tests ExportMetrics with 401 response
func TestPerconaExporterExportMetricsUnauthorized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "invalid-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestPerconaExporterExportMetricsWithBasicAuth tests ExportMetrics with basic auth
func TestPerconaExporterExportMetricsWithBasicAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify basic auth header
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "admin", username)
		assert.Equal(t, "secret", password)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		Username:  "admin",
		Password:  "secret",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

// TestPerconaExporterExportMetricsWithCustomHeaders tests ExportMetrics with custom headers
func TestPerconaExporterExportMetricsWithCustomHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom headers
		assert.Equal(t, "custom-value", r.Header.Get("X-Custom-Header"))
		assert.Equal(t, "another-value", r.Header.Get("X-Another-Header"))

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
		Headers: map[string]string{
			"X-Custom-Header":  "custom-value",
			"X-Another-Header": "another-value",
		},
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

// TestPerconaExporterExportLogs tests the ExportLogs method (unsupported)
func TestPerconaExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)

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
	assert.Contains(t, err.Error(), "does not directly support logs export")
}

// TestPerconaExporterExportTraces tests the ExportTraces method (unsupported)
func TestPerconaExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)

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
	assert.Contains(t, err.Error(), "does not support traces export")
}

// TestPerconaExporterHealth tests the Health method
func TestPerconaExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name           string
		config         integrations.PerconaConfig
		serverHandler  http.HandlerFunc
		expectHealthy  bool
		expectContains string
	}{
		{
			name: "disabled integration",
			config: integrations.PerconaConfig{
				Enabled: false,
			},
			serverHandler:  nil,
			expectHealthy:  false,
			expectContains: "integration disabled",
		},
		{
			name: "healthy server",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "", // Will be set to server URL
				APIKey:    "test-api-key",
				NodeID:    "node-001",
				NodeType:  "mysql",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/v1/Settings/Get", r.URL.Path)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"settings": {}}`))
			},
			expectHealthy:  true,
			expectContains: "status: 200",
		},
		{
			name: "unhealthy server - 500 error",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "", // Will be set to server URL
				APIKey:    "test-api-key",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectHealthy:  false,
			expectContains: "status: 500",
		},
		{
			name: "unhealthy server - 401 unauthorized",
			config: integrations.PerconaConfig{
				Enabled:   true,
				ServerURL: "", // Will be set to server URL
				APIKey:    "invalid-key",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectHealthy:  false,
			expectContains: "status: 401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			config := tt.config

			if tt.serverHandler != nil {
				server = httptest.NewServer(tt.serverHandler)
				defer server.Close()
				config.ServerURL = server.URL
			}

			exporter := integrations.NewPerconaExporter(config, logger)
			if config.Enabled {
				err := exporter.Init(ctx)
				require.NoError(t, err)
			}

			status, err := exporter.Health(ctx)
			require.NoError(t, err)
			require.NotNil(t, status)
			assert.Equal(t, tt.expectHealthy, status.Healthy)
			assert.Contains(t, status.Message, tt.expectContains)

			// LastCheck is only set for enabled integrations that make a request
			if config.Enabled {
				assert.False(t, status.LastCheck.IsZero())
			}

			// Verify details for enabled integrations
			if config.Enabled && config.NodeID != "" {
				assert.NotNil(t, status.Details)
				assert.Equal(t, config.NodeID, status.Details["node_id"])
			}
		})
	}
}

// TestPerconaExporterHealthWithBasicAuth tests Health with basic auth
func TestPerconaExporterHealthWithBasicAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "admin", username)
		assert.Equal(t, "secret", password)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		Username:  "admin",
		Password:  "secret",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
}

// TestPerconaExporterHealthConnectionError tests Health with connection error
func TestPerconaExporterHealthConnectionError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:99999", // Invalid port
		APIKey:    "test-api-key",
		Timeout:   1 * time.Second,
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

// TestPerconaExporterClose tests the Close method
func TestPerconaExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())

	err = exporter.Close(ctx)
	assert.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

// TestPerconaExporterCloseNotInitialized tests Close when not initialized
func TestPerconaExporterCloseNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	// Don't call Init()

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// TestPerconaExporterCloseDisabled tests Close when disabled
func TestPerconaExporterCloseDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.PerconaConfig{
		Enabled: false,
	}

	exporter := integrations.NewPerconaExporter(config, logger)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// TestPerconaExporterMetricLabels tests that all configured labels are properly added to metrics
func TestPerconaExporterMetricLabels(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:        true,
		ServerURL:      server.URL,
		APIKey:         "test-api-key",
		NodeID:         "node-123",
		NodeName:       "mysql-primary",
		NodeType:       "mysql",
		Environment:    "production",
		Cluster:        "main",
		ReplicationSet: "rs0",
		CustomLabels: map[string]string{
			"datacenter": "dc1",
			"team":       "dba",
		},
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "test.metric",
			Value:     1.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"custom_tag": "custom_value"},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify labels
	metricsArr := receivedPayload["metrics"].([]interface{})
	metric := metricsArr[0].(map[string]interface{})
	labels := metric["labels"].(map[string]interface{})

	// Node labels
	assert.Equal(t, "node-123", labels["node_id"])
	assert.Equal(t, "mysql-primary", labels["node_name"])
	assert.Equal(t, "mysql", labels["node_type"])
	assert.Equal(t, "production", labels["environment"])
	assert.Equal(t, "main", labels["cluster"])
	assert.Equal(t, "rs0", labels["replication_set"])

	// Custom labels
	assert.Equal(t, "dc1", labels["datacenter"])
	assert.Equal(t, "dba", labels["team"])

	// Metric tags
	assert.Equal(t, "custom_value", labels["custom_tag"])
}

// TestPerconaExporterMetricPayloadFormat tests the format of the metric payload
func TestPerconaExporterMetricPayloadFormat(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &receivedPayload)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	timestamp := time.Now()
	metrics := []integrations.Metric{
		{
			Name:      "mysql.queries",
			Value:     12345.67,
			Type:      integrations.MetricTypeGauge,
			Timestamp: timestamp,
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, result.Success)

	// Verify payload format
	metricsArr := receivedPayload["metrics"].([]interface{})
	assert.Len(t, metricsArr, 1)

	metric := metricsArr[0].(map[string]interface{})
	assert.Equal(t, "mysql.queries", metric["metric_name"])
	assert.Equal(t, "gauge", metric["type"])
	assert.Equal(t, 12345.67, metric["value"])
	assert.Equal(t, float64(timestamp.UnixMilli()), metric["timestamp"])
}

// TestPerconaExporterSupportedDataTypes tests the SupportedDataTypes method
func TestPerconaExporterSupportedDataTypes(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)

	dataTypes := exporter.SupportedDataTypes()
	assert.Len(t, dataTypes, 1)
	assert.Contains(t, dataTypes, integrations.DataTypeMetrics)
	assert.NotContains(t, dataTypes, integrations.DataTypeLogs)
	assert.NotContains(t, dataTypes, integrations.DataTypeTraces)
}

// TestPerconaExporterContextCancellation tests behavior when context is cancelled
func TestPerconaExporterContextCancellation(t *testing.T) {
	logger := zap.NewNop()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay response to allow context cancellation
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
		Timeout:   5 * time.Second,
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	ctx := context.Background()
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create a context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestPerconaConfigDefaults tests the default values of PerconaConfig
func TestPerconaConfigDefaults(t *testing.T) {
	config := integrations.PerconaConfig{}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.ServerURL)
	assert.Empty(t, config.APIKey)
	assert.Empty(t, config.Username)
	assert.Empty(t, config.Password)
	assert.Empty(t, config.NodeID)
	assert.Empty(t, config.NodeName)
	assert.Empty(t, config.NodeType)
	assert.Empty(t, config.Environment)
	assert.Empty(t, config.Cluster)
	assert.Empty(t, config.ReplicationSet)
	assert.Nil(t, config.CustomLabels)
	assert.False(t, config.TLSEnabled)
	assert.False(t, config.TLSSkipVerify)
	assert.Equal(t, time.Duration(0), config.Timeout)
	assert.Equal(t, 0, config.BatchSize)
	assert.Equal(t, time.Duration(0), config.FlushInterval)
	assert.Nil(t, config.Headers)
}

// TestPerconaExporterConcurrentExports tests concurrent export operations
func TestPerconaExporterConcurrentExports(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Run concurrent exports
	concurrency := 10
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			metrics := []integrations.Metric{
				{
					Name:      "concurrent.metric",
					Value:     float64(idx),
					Type:      integrations.MetricTypeGauge,
					Timestamp: time.Now(),
				},
			}
			result, err := exporter.ExportMetrics(ctx, metrics)
			assert.NoError(t, err)
			assert.True(t, result.Success)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < concurrency; i++ {
		<-done
	}

	assert.Equal(t, int32(concurrency), atomic.LoadInt32(&requestCount))
}

// Benchmark tests
func BenchmarkNewPerconaExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewPerconaExporter(config, logger)
	}
}

func BenchmarkPerconaExporterInit(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: "http://localhost:9090",
		APIKey:    "test-api-key",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter := integrations.NewPerconaExporter(config, logger)
		_ = exporter.Init(ctx)
	}
}

func BenchmarkPerconaExporterExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := make([]integrations.Metric, 100)
	for i := range metrics {
		metrics[i] = integrations.Metric{
			Name:      "benchmark.metric",
			Value:     float64(i),
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkPerconaExporterHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := integrations.PerconaConfig{
		Enabled:   true,
		ServerURL: server.URL,
		APIKey:    "test-api-key",
	}

	exporter := integrations.NewPerconaExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}
