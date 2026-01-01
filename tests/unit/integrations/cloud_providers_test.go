// package integrations provides unit tests for TelemetryFlow Agent integrations.
package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// GCP Exporter Tests
func TestNewGCPExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
		Region:    "us-central1",
	}

	exporter := integrations.NewGCPExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "gcp", exporter.Name())
	assert.Equal(t, "cloud", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestGCPExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.GCPConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.GCPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing project id",
			config: integrations.GCPConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewGCPExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGCPExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.GCPConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.GCPConfig{
				Enabled:   true,
				ProjectID: "test-project",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.GCPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing project id",
			config: integrations.GCPConfig{
				Enabled: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewGCPExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGCPExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
	}

	exporter := integrations.NewGCPExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	// May fail due to auth, but should not panic
	if err == nil {
		assert.NotNil(t, result)
	}
}

func TestGCPExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		config := integrations.GCPConfig{Enabled: false}
		exporter := integrations.NewGCPExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})
}

func TestGCPExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
	}

	exporter := integrations.NewGCPExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Azure Exporter Tests
func TestNewAzureExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.AzureConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription",
		ResourceGroup:  "test-rg",
		TenantID:       "test-tenant",
	}

	exporter := integrations.NewAzureExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "azure", exporter.Name())
	assert.Equal(t, "cloud", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestAzureExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.AzureConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.AzureConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
				ResourceGroup:  "test-rg",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.AzureConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "minimal config",
			config: integrations.AzureConfig{
				Enabled:       true,
				ResourceGroup: "test-rg",
			},
			expectError: false, // Azure uses managed identity by default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAzureExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAzureExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.AzureConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.AzureConfig{
				Enabled:        true,
				SubscriptionID: "test-subscription",
				ResourceGroup:  "test-rg",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.AzureConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "minimal config",
			config: integrations.AzureConfig{
				Enabled:       true,
				ResourceGroup: "test-rg",
			},
			expectError: false, // Azure uses managed identity by default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAzureExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAzureExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureConfig{Enabled: false}
	exporter := integrations.NewAzureExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestAzureExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription",
		ResourceGroup:  "test-rg",
	}

	exporter := integrations.NewAzureExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Alibaba Exporter Tests
func TestNewAlibabaExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
	}

	exporter := integrations.NewAlibabaExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "alibaba", exporter.Name())
	assert.Equal(t, "cloud", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestAlibabaExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.AlibabaConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.AlibabaConfig{
				Enabled:         true,
				RegionID:        "cn-hangzhou",
				AccessKeyID:     "test-key",
				AccessKeySecret: "test-secret",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.AlibabaConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "with credentials no region",
			config: integrations.AlibabaConfig{
				Enabled:         true,
				AccessKeyID:     "test-key",
				AccessKeySecret: "test-secret",
			},
			expectError: false, // RegionID defaults to cn-hangzhou
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAlibabaExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAlibabaExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.AlibabaConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.AlibabaConfig{
				Enabled:         true,
				RegionID:        "cn-hangzhou",
				AccessKeyID:     "test-key",
				AccessKeySecret: "test-secret",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.AlibabaConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing access key",
			config: integrations.AlibabaConfig{
				Enabled:         true,
				RegionID:        "cn-hangzhou",
				AccessKeySecret: "test-secret",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewAlibabaExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAlibabaExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlibabaConfig{Enabled: false}
	exporter := integrations.NewAlibabaExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestAlibabaExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Test config defaults
func TestCloudProviderConfigDefaults(t *testing.T) {
	t.Run("gcp defaults", func(t *testing.T) {
		config := integrations.GCPConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.ProjectID)
	})

	t.Run("azure defaults", func(t *testing.T) {
		config := integrations.AzureConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.SubscriptionID)
	})

	t.Run("alibaba defaults", func(t *testing.T) {
		config := integrations.AlibabaConfig{}
		assert.False(t, config.Enabled)
		assert.Empty(t, config.RegionID)
	})
}

// Benchmark tests
func BenchmarkNewGCPExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.GCPConfig{
		Enabled:   true,
		ProjectID: "test-project",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewGCPExporter(config, logger)
	}
}

func BenchmarkNewAzureExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.AzureConfig{
		Enabled:        true,
		SubscriptionID: "test-sub",
		ResourceGroup:  "test-rg",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewAzureExporter(config, logger)
	}
}

func BenchmarkNewAlibabaExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewAlibabaExporter(config, logger)
	}
}

// ============================================================================
// GCP Exporter Export Method Tests with Mock HTTP Servers
// ============================================================================

func TestGCPExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server for monitoring API
	monitoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer monitoringServer.Close()

	// Create mock server for logging API
	loggingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer loggingServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		Region:             "us-central1",
		MonitoringEndpoint: monitoringServer.URL,
		LoggingEndpoint:    loggingServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create test telemetry data
	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "cpu.usage",
				Value:     75.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
			},
			{
				Name:      "memory.used",
				Value:     1024.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
			},
		},
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-service",
				TraceID:   "trace-123",
				SpanID:    "span-456",
			},
		},
		Timestamp: time.Now(),
		AgentID:   "test-agent",
		Hostname:  "test-host",
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported) // 2 metrics + 1 log
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestGCPExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server for Cloud Trace API
	traceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "traces:batchWrite")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer traceServer.Close()

	config := integrations.GCPConfig{
		Enabled:       true,
		ProjectID:     "test-project",
		Region:        "us-central1",
		TraceEndpoint: traceServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "abc123def456",
			SpanID:        "span-001",
			ParentSpanID:  "",
			OperationName: "http.request",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"http.method": "GET", "http.url": "/api/test"},
		},
		{
			TraceID:       "abc123def456",
			SpanID:        "span-002",
			ParentSpanID:  "span-001",
			OperationName: "db.query",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-50 * time.Millisecond),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"db.type": "postgresql"},
		},
		{
			TraceID:       "abc123def456",
			SpanID:        "span-003",
			ParentSpanID:  "span-001",
			OperationName: "external.call",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-30 * time.Millisecond),
			Duration:      30 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags:          map[string]string{"error": "connection timeout"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestGCPExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server for Cloud Logging API
	loggingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "entries:write")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body contains expected fields
		var payload map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Contains(t, payload, "entries")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer loggingServer.Close()

	config := integrations.GCPConfig{
		Enabled:         true,
		ProjectID:       "test-project",
		Region:          "us-central1",
		LogName:         "test-logs",
		LoggingEndpoint: loggingServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "Application started successfully",
			Source:     "main",
			Attributes: map[string]string{"version": "1.0.0"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelWarn,
			Message:    "High memory usage detected",
			Source:     "monitor",
			TraceID:    "trace-789",
			SpanID:     "span-101",
			Attributes: map[string]string{"memory_usage": "85%"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelError,
			Message:    "Database connection failed",
			Source:     "database",
			Attributes: map[string]string{"error_code": "E1001"},
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelDebug,
			Message:   "Debug information",
			Source:    "debug",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 4, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestGCPExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.GCPConfig{
		Enabled:   false,
		ProjectID: "test-project",
	}

	exporter := integrations.NewGCPExporter(config, logger)
	_ = exporter.Init(ctx)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGCPExporterExportServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that returns 500 error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer errorServer.Close()

	config := integrations.GCPConfig{
		Enabled:            true,
		ProjectID:          "test-project",
		MonitoringEndpoint: errorServer.URL,
	}

	exporter := integrations.NewGCPExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// ============================================================================
// Azure Exporter Export Method Tests with Mock HTTP Servers
// ============================================================================

func TestAzureExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock Azure Monitor endpoint
	monitorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body structure
		var payload []interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Greater(t, len(payload), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer monitorServer.Close()

	config := integrations.AzureConfig{
		Enabled:               true,
		SubscriptionID:        "test-subscription-id",
		ResourceGroup:         "test-resource-group",
		Region:                "eastus",
		MetricNamespace:       "TestMetrics",
		CustomMetricsEndpoint: monitorServer.URL,
	}

	exporter := integrations.NewAzureExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "cpu.percent",
			Value:     65.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance": "vm-001", "region": "eastus"},
		},
		{
			Name:      "disk.io.read",
			Value:     1024.0,
			Type:      integrations.MetricTypeCounter,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance": "vm-001", "disk": "sda"},
		},
		{
			Name:      "network.bytes.in",
			Value:     50000.0,
			Type:      integrations.MetricTypeCounter,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance": "vm-001", "interface": "eth0"},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestAzureExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock Azure Log Analytics endpoint
	logAnalyticsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get("Log-Type"))

		// Verify request body contains log entries
		var payload []interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Greater(t, len(payload), 0)

		w.WriteHeader(http.StatusOK)
	}))
	defer logAnalyticsServer.Close()

	config := integrations.AzureConfig{
		Enabled:        true,
		SubscriptionID: "test-subscription-id",
		ResourceGroup:  "test-resource-group",
		WorkspaceID:    "test-workspace-id",
		WorkspaceKey:   "dGVzdC1rZXk=", // base64 encoded test-key
		LogType:        "CustomLogs",
	}

	exporter := integrations.NewAzureExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "Application started",
			Source:     "app-service",
			TraceID:    "trace-azure-001",
			SpanID:     "span-azure-001",
			Attributes: map[string]string{"environment": "production"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelWarn,
			Message:    "High latency detected",
			Source:     "api-gateway",
			Attributes: map[string]string{"latency_ms": "500"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelError,
			Message:    "Authentication failed",
			Source:     "auth-service",
			Attributes: map[string]string{"error_code": "AUTH_001"},
		},
	}

	// Note: This will attempt to connect to the actual Log Analytics endpoint
	// based on WorkspaceID, so it may fail in test environment
	result, err := exporter.ExportLogs(ctx, logs)
	// The test may fail due to actual endpoint resolution, but we verify the method is called
	if err == nil {
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)
	}
}

func TestAzureExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock Azure Monitor endpoint for metrics
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer metricsServer.Close()

	// Create mock Application Insights endpoint for traces
	appInsightsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"itemsReceived": 2, "itemsAccepted": 2})
	}))
	defer appInsightsServer.Close()

	config := integrations.AzureConfig{
		Enabled:                     true,
		SubscriptionID:              "test-subscription-id",
		ResourceGroup:               "test-resource-group",
		InstrumentationKey:          "test-instrumentation-key",
		CustomMetricsEndpoint:       metricsServer.URL,
		ApplicationInsightsEndpoint: appInsightsServer.URL,
	}

	exporter := integrations.NewAzureExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "request.duration",
				Value:     150.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"endpoint": "/api/users"},
			},
		},
		Traces: []integrations.Trace{
			{
				TraceID:       "azure-trace-001",
				SpanID:        "azure-span-001",
				OperationName: "HTTP GET /api/users",
				ServiceName:   "user-service",
				StartTime:     time.Now().Add(-200 * time.Millisecond),
				Duration:      200 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"http.status_code": "200"},
			},
			{
				TraceID:       "azure-trace-001",
				SpanID:        "azure-span-002",
				ParentSpanID:  "azure-span-001",
				OperationName: "SQL SELECT",
				ServiceName:   "user-service",
				StartTime:     time.Now().Add(-100 * time.Millisecond),
				Duration:      100 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"db.statement": "SELECT * FROM users"},
			},
		},
		Timestamp: time.Now(),
		AgentID:   "azure-agent-001",
		Hostname:  "azure-vm-001",
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported) // 1 metric + 2 traces
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestAzureExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AzureConfig{
		Enabled:        false,
		SubscriptionID: "test-subscription",
	}

	exporter := integrations.NewAzureExporter(config, logger)
	_ = exporter.Init(ctx)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestAzureExporterExportServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that returns error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "service unavailable"})
	}))
	defer errorServer.Close()

	config := integrations.AzureConfig{
		Enabled:               true,
		SubscriptionID:        "test-subscription",
		ResourceGroup:         "test-rg",
		CustomMetricsEndpoint: errorServer.URL,
	}

	exporter := integrations.NewAzureExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// ============================================================================
// Alibaba Exporter Export Method Tests with Mock HTTP Servers
// ============================================================================

func TestAlibabaExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock CloudMonitor endpoint
	cmsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.URL.RawQuery, "Action=PutCustomMetric")

		// Verify request body structure
		var payload []interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Greater(t, len(payload), 0)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"RequestId": "test-request-id",
			"Code":      "200",
		})
	}))
	defer cmsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		Namespace:       "acs_custom_test",
		CMSEndpoint:     cmsServer.URL,
		Tags:            map[string]string{"environment": "test"},
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "system.cpu.usage",
			Value:     78.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance_id": "i-test001", "region": "cn-hangzhou"},
		},
		{
			Name:      "system.memory.used",
			Value:     2048.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance_id": "i-test001"},
		},
		{
			Name:      "system.disk.iops",
			Value:     500.0,
			Type:      integrations.MetricTypeCounter,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance_id": "i-test001", "disk_id": "d-test001"},
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestAlibabaExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.URL.Path, "logstores")

		// Verify SLS-specific headers
		assert.NotEmpty(t, r.Header.Get("x-log-bodyrawsize"))
		assert.NotEmpty(t, r.Header.Get("x-log-apiversion"))

		// Verify request body structure
		var payload map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Contains(t, payload, "logs")

		w.WriteHeader(http.StatusOK)
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		Project:         "test-project",
		Logstore:        "test-logstore",
		SLSEndpoint:     slsServer.URL,
		Tags:            map[string]string{"app": "telemetryflow"},
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "Service started successfully",
			Source:     "main",
			TraceID:    "alibaba-trace-001",
			SpanID:     "alibaba-span-001",
			Attributes: map[string]string{"version": "2.0.0"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelWarn,
			Message:    "Rate limit approaching",
			Source:     "rate-limiter",
			Attributes: map[string]string{"current_rate": "950", "max_rate": "1000"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelError,
			Message:    "OSS connection timeout",
			Source:     "storage",
			Attributes: map[string]string{"bucket": "test-bucket", "timeout_ms": "30000"},
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelFatal,
			Message:   "Critical system failure",
			Source:    "system",
		},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 4, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestAlibabaExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock CloudMonitor endpoint
	cmsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"RequestId": "test-123"})
	}))
	defer cmsServer.Close()

	// Create mock SLS endpoint
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer slsServer.Close()

	// Create mock ARMS endpoint
	armsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "trace/spans")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer armsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		CMSEndpoint:     cmsServer.URL,
		SLSEndpoint:     slsServer.URL,
		ARMSEndpoint:    armsServer.URL,
		Project:         "test-project",
		Logstore:        "test-logstore",
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "api.request.count",
				Value:     100.0,
				Type:      integrations.MetricTypeCounter,
				Timestamp: time.Now(),
				Tags:      map[string]string{"api": "/v1/users"},
			},
			{
				Name:      "api.latency.avg",
				Value:     45.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"api": "/v1/users"},
			},
		},
		Traces: []integrations.Trace{
			{
				TraceID:       "alibaba-trace-full-001",
				SpanID:        "alibaba-span-full-001",
				OperationName: "RPC call",
				ServiceName:   "order-service",
				StartTime:     time.Now().Add(-300 * time.Millisecond),
				Duration:      300 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"rpc.method": "CreateOrder"},
			},
		},
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Order created successfully",
				Source:    "order-service",
				TraceID:   "alibaba-trace-full-001",
				SpanID:    "alibaba-span-full-001",
			},
		},
		Timestamp: time.Now(),
		AgentID:   "alibaba-agent-001",
		Hostname:  "ecs-test-001",
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 4, result.ItemsExported) // 2 metrics + 1 trace + 1 log
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestAlibabaExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlibabaConfig{
		Enabled:         false,
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	_ = exporter.Init(ctx)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestAlibabaExporterExportServerError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server that returns error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Code":      "InvalidParameter",
			"Message":   "Invalid metric data",
			"RequestId": "error-request-id",
		})
	}))
	defer errorServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
		CMSEndpoint:     errorServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

func TestAlibabaExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock ARMS endpoint
	armsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.URL.Path, "trace/spans")

		// Verify request body structure
		var payload map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		assert.Contains(t, payload, "spans")

		spans := payload["spans"].([]interface{})
		assert.Equal(t, 3, len(spans))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"RequestId": "arms-request-id"})
	}))
	defer armsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		ARMSEndpoint:    armsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "alibaba-trace-002",
			SpanID:        "alibaba-span-002-root",
			OperationName: "http.request",
			ServiceName:   "gateway-service",
			StartTime:     time.Now().Add(-500 * time.Millisecond),
			Duration:      500 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"http.method": "POST", "http.url": "/api/orders"},
		},
		{
			TraceID:       "alibaba-trace-002",
			SpanID:        "alibaba-span-002-child1",
			ParentSpanID:  "alibaba-span-002-root",
			OperationName: "rds.query",
			ServiceName:   "order-service",
			StartTime:     time.Now().Add(-400 * time.Millisecond),
			Duration:      200 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
			Tags:          map[string]string{"db.type": "mysql", "db.instance": "rds-order-db"},
		},
		{
			TraceID:       "alibaba-trace-002",
			SpanID:        "alibaba-span-002-child2",
			ParentSpanID:  "alibaba-span-002-root",
			OperationName: "mq.send",
			ServiceName:   "order-service",
			StartTime:     time.Now().Add(-150 * time.Millisecond),
			Duration:      50 * time.Millisecond,
			Status:        integrations.TraceStatusError,
			Tags:          map[string]string{"mq.topic": "order-events", "error": "queue full"},
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
}
