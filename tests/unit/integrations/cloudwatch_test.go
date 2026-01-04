// package integrations_test provides unit tests for TelemetryFlow Agent CloudWatch integration.
package integrations_test

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

// ============================================================================
// NewCloudWatchExporter Tests
// ============================================================================

func TestNewCloudWatchExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "cloudwatch", exporter.Name())
	assert.Equal(t, "cloud", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestNewCloudWatchExporterDisabled(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.CloudWatchConfig{
		Enabled: false,
		Region:  "us-west-2",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "cloudwatch", exporter.Name())
	assert.False(t, exporter.IsEnabled())
}

func TestNewCloudWatchExporterWithNilLogger(t *testing.T) {
	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "eu-west-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, nil)

	require.NotNil(t, exporter)
	assert.Equal(t, "cloudwatch", exporter.Name())
}

func TestNewCloudWatchExporterSupportedDataTypes(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)

	supportedTypes := exporter.SupportedDataTypes()
	assert.Contains(t, supportedTypes, integrations.DataTypeMetrics)
	assert.Contains(t, supportedTypes, integrations.DataTypeLogs)
	assert.NotContains(t, supportedTypes, integrations.DataTypeTraces)
}

// ============================================================================
// Init Tests
// ============================================================================

func TestCloudWatchExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name          string
		config        integrations.CloudWatchConfig
		expectError   bool
		expectInit    bool
		errorContains string
	}{
		{
			name: "valid config with explicit credentials",
			config: integrations.CloudWatchConfig{
				Enabled:         true,
				Region:          "us-east-1",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				Namespace:       "TelemetryFlow",
			},
			expectError: false,
			expectInit:  true,
		},
		{
			name: "valid config with role ARN",
			config: integrations.CloudWatchConfig{
				Enabled:   true,
				Region:    "us-west-2",
				RoleARN:   "arn:aws:iam::123456789012:role/TelemetryFlowRole",
				Namespace: "CustomNamespace",
			},
			expectError: false,
			expectInit:  true,
		},
		{
			name: "valid config with no explicit credentials (IAM role assumed)",
			config: integrations.CloudWatchConfig{
				Enabled:   true,
				Region:    "ap-southeast-1",
				Namespace: "TelemetryFlow",
			},
			expectError: false,
			expectInit:  true,
		},
		{
			name: "disabled config",
			config: integrations.CloudWatchConfig{
				Enabled: false,
			},
			expectError: false,
			expectInit:  false,
		},
		{
			name: "missing region - should fail validation",
			config: integrations.CloudWatchConfig{
				Enabled:         true,
				AccessKeyID:     "test-key",
				SecretAccessKey: "test-secret",
			},
			expectError:   true,
			expectInit:    false,
			errorContains: "region",
		},
		{
			name: "valid config with endpoint override",
			config: integrations.CloudWatchConfig{
				Enabled:          true,
				Region:           "us-east-1",
				EndpointOverride: "http://localhost:4566",
			},
			expectError: false,
			expectInit:  true,
		},
		{
			name: "valid config with custom log group and stream",
			config: integrations.CloudWatchConfig{
				Enabled:       true,
				Region:        "eu-central-1",
				LogGroupName:  "/custom/log-group",
				LogStreamName: "custom-stream",
			},
			expectError: false,
			expectInit:  true,
		},
		{
			name: "valid config with session token",
			config: integrations.CloudWatchConfig{
				Enabled:         true,
				Region:          "us-east-1",
				AccessKeyID:     "ASIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "FwoGZXIvYXdzEBYaDK/example/session/token==",
			},
			expectError: false,
			expectInit:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewCloudWatchExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}

			if tt.config.Enabled {
				assert.Equal(t, tt.expectInit, exporter.IsInitialized())
			}
		})
	}
}

func TestCloudWatchExporterInitDefaults(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())
}

func TestCloudWatchExporterInitWithContext(t *testing.T) {
	logger := zap.NewNop()

	// Test with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)

	// Init should succeed regardless of context state for this implementation
	assert.NoError(t, err)
}

// ============================================================================
// Validate Tests
// ============================================================================

func TestCloudWatchExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name          string
		config        integrations.CloudWatchConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config with credentials",
			config: integrations.CloudWatchConfig{
				Enabled:         true,
				Region:          "us-east-1",
				AccessKeyID:     "test-key",
				SecretAccessKey: "test-secret",
			},
			expectError: false,
		},
		{
			name: "valid config with role ARN",
			config: integrations.CloudWatchConfig{
				Enabled: true,
				Region:  "us-west-2",
				RoleARN: "arn:aws:iam::123456789012:role/TestRole",
			},
			expectError: false,
		},
		{
			name: "valid config no explicit credentials",
			config: integrations.CloudWatchConfig{
				Enabled: true,
				Region:  "eu-west-1",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.CloudWatchConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing region when enabled",
			config: integrations.CloudWatchConfig{
				Enabled:         true,
				AccessKeyID:     "test-key",
				SecretAccessKey: "test-secret",
			},
			expectError:   true,
			errorContains: "region",
		},
		{
			name: "partial credentials - only access key",
			config: integrations.CloudWatchConfig{
				Enabled:     true,
				Region:      "us-east-1",
				AccessKeyID: "test-key",
			},
			expectError: false, // Will use IAM role
		},
		{
			name: "partial credentials - only secret key",
			config: integrations.CloudWatchConfig{
				Enabled:         true,
				Region:          "us-east-1",
				SecretAccessKey: "test-secret",
			},
			expectError: false, // Will use IAM role
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewCloudWatchExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// Export Tests with Mock HTTP Server
// ============================================================================

func TestCloudWatchExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock CloudWatch Metrics API endpoint
	metricsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ResponseMetadata": map[string]string{
				"RequestId": "test-request-id",
			},
		})
	}))
	defer metricsServer.Close()

	// Create mock CloudWatch Logs API endpoint
	logsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nextSequenceToken": "test-sequence-token",
		})
	}))
	defer logsServer.Close()

	config := integrations.CloudWatchConfig{
		Enabled:          true,
		Region:           "us-east-1",
		Namespace:        "TelemetryFlow/Test",
		LogGroupName:     "/telemetryflow/test",
		LogStreamName:    "test-stream",
		EndpointOverride: metricsServer.URL,
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "cpu.usage",
				Value:     75.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host", "environment": "test"},
				Unit:      "percent",
			},
			{
				Name:      "memory.used",
				Value:     2048.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
				Tags:      map[string]string{"host": "test-host"},
				Unit:      "megabytes",
			},
		},
		Logs: []integrations.LogEntry{
			{
				Timestamp:  time.Now(),
				Level:      integrations.LogLevelInfo,
				Message:    "Application started successfully",
				Source:     "main",
				Attributes: map[string]string{"version": "1.0.0"},
			},
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelWarn,
				Message:   "High memory usage detected",
				Source:    "monitor",
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
	assert.Equal(t, 4, result.ItemsExported) // 2 metrics + 2 logs
	assert.Greater(t, result.BytesSent, int64(0))
}

func TestCloudWatchExporterExportDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: false,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	_ = exporter.Init(ctx)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		},
	}

	result, err := exporter.Export(ctx, data)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotEnabled, err)
}

func TestCloudWatchExporterExportOnlyMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	data := &integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{
				Name:      "test.metric",
				Value:     100.0,
				Type:      integrations.MetricTypeCounter,
				Timestamp: time.Now(),
				Tags:      map[string]string{"service": "api"},
				Unit:      "count",
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
	assert.Equal(t, 1, result.ItemsExported)
}

func TestCloudWatchExporterExportOnlyLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled:       true,
		Region:        "us-east-1",
		LogGroupName:  "/test/logs",
		LogStreamName: "test-stream",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	data := &integrations.TelemetryData{
		Logs: []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test",
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
	assert.Equal(t, 1, result.ItemsExported)
}

func TestCloudWatchExporterExportEmptyData(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	data := &integrations.TelemetryData{
		Metrics:   []integrations.Metric{},
		Logs:      []integrations.LogEntry{},
		Timestamp: time.Now(),
		AgentID:   "test-agent",
		Hostname:  "test-host",
	}

	result, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ItemsExported)
}

// ============================================================================
// ExportMetrics Tests with Mock HTTP Server
// ============================================================================

func TestCloudWatchExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock CloudWatch PutMetricData endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-amz-json-1.1", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ResponseMetadata": map[string]string{"RequestId": "test-request-id"},
		})
	}))
	defer server.Close()

	config := integrations.CloudWatchConfig{
		Enabled:          true,
		Region:           "us-east-1",
		Namespace:        "TelemetryFlow/Metrics",
		MetricResolution: 60,
		EndpointOverride: server.URL,
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "system.cpu.usage",
			Value:     78.5,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance_id": "i-1234567890abcdef0", "region": "us-east-1"},
			Unit:      "percent",
		},
		{
			Name:      "system.memory.used",
			Value:     4096.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
			Tags:      map[string]string{"instance_id": "i-1234567890abcdef0"},
			Unit:      "megabytes",
		},
		{
			Name:      "network.bytes.in",
			Value:     1500000.0,
			Type:      integrations.MetricTypeCounter,
			Timestamp: time.Now(),
			Tags:      map[string]string{"interface": "eth0"},
			Unit:      "bytes",
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCloudWatchExporterExportMetricsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: false,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotEnabled, err)
}

func TestCloudWatchExporterExportMetricsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	// Not calling Init() intentionally

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotInitialized, err)
}

func TestCloudWatchExporterExportMetricsWithDimensions(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled:               true,
		Region:                "us-east-1",
		Namespace:             "TelemetryFlow",
		DimensionRollupOption: "NoDimensionRollup",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{
		{
			Name:      "api.request.count",
			Value:     500.0,
			Type:      integrations.MetricTypeCounter,
			Timestamp: time.Now(),
			Tags: map[string]string{
				"service":     "order-api",
				"environment": "production",
				"region":      "us-east-1",
				"method":      "POST",
				"endpoint":    "/api/orders",
			},
			Unit: "count",
		},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 1, result.ItemsExported)
}

func TestCloudWatchExporterExportMetricsUnitMapping(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow/Units",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Test various unit mappings
	metrics := []integrations.Metric{
		{Name: "test.bytes", Value: 1024.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now(), Unit: "bytes"},
		{Name: "test.percent", Value: 75.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now(), Unit: "percent"},
		{Name: "test.count", Value: 100.0, Type: integrations.MetricTypeCounter, Timestamp: time.Now(), Unit: "count"},
		{Name: "test.seconds", Value: 5.5, Type: integrations.MetricTypeGauge, Timestamp: time.Now(), Unit: "seconds"},
		{Name: "test.milliseconds", Value: 250.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now(), Unit: "milliseconds"},
		{Name: "test.bytes_per_second", Value: 10000.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now(), Unit: "bytes/second"},
		{Name: "test.unknown", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now(), Unit: "unknown_unit"},
	}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 7, result.ItemsExported)
}

func TestCloudWatchExporterExportMetricsEmpty(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	metrics := []integrations.Metric{}

	result, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ItemsExported)
}

// ============================================================================
// ExportLogs Tests with Mock HTTP Server
// ============================================================================

func TestCloudWatchExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock CloudWatch Logs PutLogEvents endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nextSequenceToken": "49545678901234567890123456789012345678901234567890123456",
		})
	}))
	defer server.Close()

	config := integrations.CloudWatchConfig{
		Enabled:          true,
		Region:           "us-east-1",
		LogGroupName:     "/telemetryflow/application",
		LogStreamName:    "app-logs",
		EndpointOverride: server.URL,
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelInfo,
			Message:    "Application started successfully",
			Source:     "main",
			Attributes: map[string]string{"version": "1.0.0", "pid": "12345"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelWarn,
			Message:    "High memory usage detected",
			Source:     "monitor",
			TraceID:    "abc123def456",
			SpanID:     "span-001",
			Attributes: map[string]string{"memory_percent": "85"},
		},
		{
			Timestamp:  time.Now(),
			Level:      integrations.LogLevelError,
			Message:    "Database connection failed",
			Source:     "database",
			Attributes: map[string]string{"error_code": "E1001", "retry_count": "3"},
		},
		{
			Timestamp: time.Now(),
			Level:     integrations.LogLevelDebug,
			Message:   "Debug information",
			Source:    "debug",
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
	assert.Equal(t, 5, result.ItemsExported)
	assert.Greater(t, result.BytesSent, int64(0))
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCloudWatchExporterExportLogsDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: false,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test log"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotEnabled, err)
}

func TestCloudWatchExporterExportLogsNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	// Not calling Init() intentionally

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test log"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, integrations.ErrNotInitialized, err)
}

func TestCloudWatchExporterExportLogsEmpty(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	logs := []integrations.LogEntry{}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 0, result.ItemsExported)
}

func TestCloudWatchExporterExportLogsAllLevels(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled:       true,
		Region:        "us-east-1",
		LogGroupName:  "/telemetryflow/test",
		LogStreamName: "level-test",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Test all log levels
	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelDebug, Message: "Debug message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Info message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelWarn, Message: "Warning message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelError, Message: "Error message", Source: "test"},
		{Timestamp: time.Now(), Level: integrations.LogLevelFatal, Message: "Fatal message", Source: "test"},
	}

	result, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 5, result.ItemsExported)
}

// ============================================================================
// ExportTraces Tests
// ============================================================================

func TestCloudWatchExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	traces := []integrations.Trace{
		{
			TraceID:       "abc123def456",
			SpanID:        "span-001",
			OperationName: "http.request",
			ServiceName:   "test-service",
			StartTime:     time.Now().Add(-100 * time.Millisecond),
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	result, err := exporter.ExportTraces(ctx, traces)

	// CloudWatch does not support traces directly - should return error
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "X-Ray")
}

// ============================================================================
// Health Tests
// ============================================================================

func TestCloudWatchExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name           string
		config         integrations.CloudWatchConfig
		init           bool
		expectHealthy  bool
		expectMessage  string
		checkDetails   bool
		expectedRegion string
		expectedNS     string
	}{
		{
			name: "healthy enabled and initialized",
			config: integrations.CloudWatchConfig{
				Enabled:   true,
				Region:    "us-east-1",
				Namespace: "TelemetryFlow",
			},
			init:           true,
			expectHealthy:  true,
			expectMessage:  "CloudWatch configured",
			checkDetails:   true,
			expectedRegion: "us-east-1",
			expectedNS:     "TelemetryFlow",
		},
		{
			name: "unhealthy when disabled",
			config: integrations.CloudWatchConfig{
				Enabled: false,
				Region:  "us-east-1",
			},
			init:          false,
			expectHealthy: false,
			expectMessage: "integration disabled",
			checkDetails:  false,
		},
		{
			name: "healthy with custom region",
			config: integrations.CloudWatchConfig{
				Enabled:   true,
				Region:    "eu-west-1",
				Namespace: "CustomNS",
			},
			init:           true,
			expectHealthy:  true,
			expectMessage:  "CloudWatch configured",
			checkDetails:   true,
			expectedRegion: "eu-west-1",
			expectedNS:     "CustomNS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewCloudWatchExporter(tt.config, logger)
			if tt.init {
				err := exporter.Init(ctx)
				require.NoError(t, err)
			}

			status, err := exporter.Health(ctx)
			require.NoError(t, err)
			assert.NotNil(t, status)
			assert.Equal(t, tt.expectHealthy, status.Healthy)
			assert.Equal(t, tt.expectMessage, status.Message)

			if tt.checkDetails {
				assert.NotNil(t, status.Details)
				assert.Equal(t, tt.expectedRegion, status.Details["region"])
				assert.Equal(t, tt.expectedNS, status.Details["namespace"])
				assert.False(t, status.LastCheck.IsZero())
			}
		})
	}
}

func TestCloudWatchExporterHealthWithContext(t *testing.T) {
	logger := zap.NewNop()

	// Test with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	_ = exporter.Init(context.Background())

	// Health should still return status even with canceled context
	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.NotNil(t, status)
}

// ============================================================================
// Close Tests
// ============================================================================

func TestCloudWatchExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())

	err = exporter.Close(ctx)
	assert.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

func TestCloudWatchExporterCloseWithoutInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	assert.False(t, exporter.IsInitialized())

	err := exporter.Close(ctx)
	assert.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

func TestCloudWatchExporterCloseMultipleTimes(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Close multiple times should not cause issues
	err = exporter.Close(ctx)
	assert.NoError(t, err)

	err = exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestCloudWatchExporterCloseDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: false,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// ============================================================================
// Config Defaults Tests
// ============================================================================

func TestCloudWatchConfigDefaults(t *testing.T) {
	config := integrations.CloudWatchConfig{}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.Region)
	assert.Empty(t, config.AccessKeyID)
	assert.Empty(t, config.SecretAccessKey)
	assert.Empty(t, config.SessionToken)
	assert.Empty(t, config.RoleARN)
	assert.Empty(t, config.Namespace)
	assert.Empty(t, config.LogGroupName)
	assert.Empty(t, config.LogStreamName)
	assert.Equal(t, 0, config.MetricResolution)
	assert.Equal(t, 0, config.BatchSize)
	assert.Equal(t, time.Duration(0), config.FlushInterval)
	assert.Equal(t, time.Duration(0), config.Timeout)
}

func TestCloudWatchConfigWithHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Trace-ID":      "trace-123",
		},
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)
}

// ============================================================================
// Integration Workflow Tests
// ============================================================================

func TestCloudWatchExporterFullWorkflow(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.CloudWatchConfig{
		Enabled:          true,
		Region:           "us-east-1",
		AccessKeyID:      "test-key",
		SecretAccessKey:  "test-secret",
		Namespace:        "TelemetryFlow/Test",
		LogGroupName:     "/telemetryflow/test",
		LogStreamName:    "test-stream",
		MetricResolution: 60,
		BatchSize:        20,
		FlushInterval:    60 * time.Second,
		Timeout:          30 * time.Second,
		EndpointOverride: server.URL,
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)

	// Step 1: Validate
	err := exporter.Validate()
	require.NoError(t, err)

	// Step 2: Initialize
	err = exporter.Init(ctx)
	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())

	// Step 3: Check health
	health, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, health.Healthy)

	// Step 4: Export metrics
	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 100.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}
	metricsResult, err := exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)
	assert.True(t, metricsResult.Success)

	// Step 5: Export logs
	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test log"},
	}
	logsResult, err := exporter.ExportLogs(ctx, logs)
	require.NoError(t, err)
	assert.True(t, logsResult.Success)

	// Step 6: Export full telemetry data
	data := &integrations.TelemetryData{
		Metrics:   metrics,
		Logs:      logs,
		Timestamp: time.Now(),
		AgentID:   "test-agent",
		Hostname:  "test-host",
	}
	exportResult, err := exporter.Export(ctx, data)
	require.NoError(t, err)
	assert.True(t, exportResult.Success)

	// Step 7: Close
	err = exporter.Close(ctx)
	require.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

func TestCloudWatchExporterConcurrentExports(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	config := integrations.CloudWatchConfig{
		Enabled:          true,
		Region:           "us-east-1",
		Namespace:        "TelemetryFlow/Concurrent",
		EndpointOverride: server.URL,
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Run concurrent exports
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
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
			assert.NotNil(t, result)
			done <- true
		}(i)
	}

	// Wait for all exports to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Close
	err = exporter.Close(ctx)
	assert.NoError(t, err)
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkNewCloudWatchExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewCloudWatchExporter(config, logger)
	}
}

func BenchmarkCloudWatchExporterInit(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter := integrations.NewCloudWatchExporter(config, logger)
		_ = exporter.Init(ctx)
	}
}

func BenchmarkCloudWatchExporterExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	_ = exporter.Init(ctx)

	metrics := []integrations.Metric{
		{Name: "test.metric", Value: 100.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkCloudWatchExporterExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	_ = exporter.Init(ctx)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "Test log"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}

func BenchmarkCloudWatchExporterHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}

// ============================================================================
// Table-Driven Tests for Edge Cases
// ============================================================================

func TestCloudWatchExporterMetricTypes(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled:   true,
		Region:    "us-east-1",
		Namespace: "TelemetryFlow",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	tests := []struct {
		name       string
		metricType integrations.MetricType
		value      float64
	}{
		{"gauge metric", integrations.MetricTypeGauge, 50.5},
		{"counter metric", integrations.MetricTypeCounter, 100.0},
		{"histogram metric", integrations.MetricTypeHistogram, 25.0},
		{"summary metric", integrations.MetricTypeSummary, 75.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := []integrations.Metric{
				{
					Name:      "test.metric",
					Value:     tt.value,
					Type:      tt.metricType,
					Timestamp: time.Now(),
				},
			}

			result, err := exporter.ExportMetrics(ctx, metrics)
			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.True(t, result.Success)
		})
	}
}

func TestCloudWatchExporterLogLevels(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.CloudWatchConfig{
		Enabled: true,
		Region:  "us-east-1",
	}

	exporter := integrations.NewCloudWatchExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	tests := []struct {
		name  string
		level integrations.LogLevel
	}{
		{"debug level", integrations.LogLevelDebug},
		{"info level", integrations.LogLevelInfo},
		{"warn level", integrations.LogLevelWarn},
		{"error level", integrations.LogLevelError},
		{"fatal level", integrations.LogLevelFatal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := []integrations.LogEntry{
				{
					Timestamp: time.Now(),
					Level:     tt.level,
					Message:   "Test message",
					Source:    "test",
				},
			}

			result, err := exporter.ExportLogs(ctx, logs)
			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.True(t, result.Success)
		})
	}
}

func TestCloudWatchExporterRegions(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	regions := []string{
		"us-east-1",
		"us-east-2",
		"us-west-1",
		"us-west-2",
		"eu-west-1",
		"eu-west-2",
		"eu-central-1",
		"ap-northeast-1",
		"ap-southeast-1",
		"ap-southeast-2",
		"sa-east-1",
	}

	for _, region := range regions {
		t.Run(region, func(t *testing.T) {
			config := integrations.CloudWatchConfig{
				Enabled: true,
				Region:  region,
			}

			exporter := integrations.NewCloudWatchExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)
			assert.True(t, exporter.IsInitialized())

			health, err := exporter.Health(ctx)
			require.NoError(t, err)
			assert.True(t, health.Healthy)
			assert.Equal(t, region, health.Details["region"])

			err = exporter.Close(ctx)
			require.NoError(t, err)
		})
	}
}
