// package integrations_test provides unit tests for TelemetryFlow Agent Kafka integration.
package integrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// =============================================================================
// NewKafkaExporter Tests
// =============================================================================

func TestNewKafkaExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		MetricsTopic: "telemetryflow-metrics",
		TracesTopic:  "telemetryflow-traces",
		LogsTopic:    "telemetryflow-logs",
	}

	exporter := integrations.NewKafkaExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "kafka", exporter.Name())
	assert.Equal(t, "streaming", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestNewKafkaExporterDisabled(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.KafkaConfig{
		Enabled: false,
		Brokers: []string{"localhost:9092"},
	}

	exporter := integrations.NewKafkaExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "kafka", exporter.Name())
	assert.False(t, exporter.IsEnabled())
}

func TestNewKafkaExporterWithNilLogger(t *testing.T) {
	config := integrations.KafkaConfig{
		Enabled: true,
		Brokers: []string{"localhost:9092"},
	}

	exporter := integrations.NewKafkaExporter(config, nil)

	require.NotNil(t, exporter)
	assert.NotNil(t, exporter.Logger())
}

func TestNewKafkaExporterWithMultipleBrokers(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.KafkaConfig{
		Enabled: true,
		Brokers: []string{
			"broker1.example.com:9092",
			"broker2.example.com:9092",
			"broker3.example.com:9092",
		},
		MetricsTopic: "metrics",
	}

	exporter := integrations.NewKafkaExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

// =============================================================================
// Init Tests
// =============================================================================

func TestKafkaExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.KafkaConfig
		expectError bool
	}{
		{
			name: "valid config with all fields",
			config: integrations.KafkaConfig{
				Enabled:           true,
				Brokers:           []string{"localhost:9092"},
				MetricsTopic:      "test-metrics",
				TracesTopic:       "test-traces",
				LogsTopic:         "test-logs",
				ClientID:          "test-client",
				Compression:       "snappy",
				RequiredAcks:      1,
				MaxRetries:        3,
				BatchSize:         100,
				BatchTimeout:      10 * time.Millisecond,
				FlushFrequency:    500 * time.Millisecond,
				PartitionStrategy: "round_robin",
			},
			expectError: false,
		},
		{
			name: "valid config minimal",
			config: integrations.KafkaConfig{
				Enabled: true,
				Brokers: []string{"localhost:9092"},
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.KafkaConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing brokers when enabled",
			config: integrations.KafkaConfig{
				Enabled:      true,
				MetricsTopic: "test-metrics",
			},
			expectError: true,
		},
		{
			name: "empty brokers array when enabled",
			config: integrations.KafkaConfig{
				Enabled: true,
				Brokers: []string{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewKafkaExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKafkaExporterInitSetsDefaults(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.KafkaConfig{
		Enabled: true,
		Brokers: []string{"localhost:9092"},
		// All other fields left empty to test defaults
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())
}

func TestKafkaExporterInitWithTLS(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.KafkaConfig{
		Enabled:       true,
		Brokers:       []string{"localhost:9093"},
		TLSEnabled:    true,
		TLSSkipVerify: true,
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())
}

func TestKafkaExporterInitWithTLSCertificates(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.KafkaConfig{
		Enabled:       true,
		Brokers:       []string{"localhost:9093"},
		TLSEnabled:    true,
		TLSSkipVerify: false,
		TLSCertFile:   "/path/to/cert.pem",
		TLSKeyFile:    "/path/to/key.pem",
		TLSCAFile:     "/path/to/ca.pem",
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.True(t, exporter.IsInitialized())
}

func TestKafkaExporterInitDisabledSkipsValidation(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.KafkaConfig{
		Enabled: false,
		// No brokers configured, but should not error since disabled
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	err := exporter.Init(ctx)

	require.NoError(t, err)
	assert.False(t, exporter.IsInitialized())
}

// =============================================================================
// Validate Tests
// =============================================================================

func TestKafkaExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.KafkaConfig
		expectError bool
		errorField  string
	}{
		{
			name: "valid config",
			config: integrations.KafkaConfig{
				Enabled: true,
				Brokers: []string{"localhost:9092"},
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.KafkaConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing brokers",
			config: integrations.KafkaConfig{
				Enabled:      true,
				MetricsTopic: "test-metrics",
			},
			expectError: true,
			errorField:  "brokers",
		},
		{
			name: "SASL enabled without username",
			config: integrations.KafkaConfig{
				Enabled:      true,
				Brokers:      []string{"localhost:9092"},
				SASLEnabled:  true,
				SASLPassword: "secret",
			},
			expectError: true,
			errorField:  "sasl_username",
		},
		{
			name: "SASL enabled without password",
			config: integrations.KafkaConfig{
				Enabled:      true,
				Brokers:      []string{"localhost:9092"},
				SASLEnabled:  true,
				SASLUsername: "admin",
			},
			expectError: true,
			errorField:  "sasl_password",
		},
		{
			name: "SASL with invalid mechanism",
			config: integrations.KafkaConfig{
				Enabled:       true,
				Brokers:       []string{"localhost:9092"},
				SASLEnabled:   true,
				SASLUsername:  "admin",
				SASLPassword:  "secret",
				SASLMechanism: "INVALID",
			},
			expectError: true,
			errorField:  "sasl_mechanism",
		},
		{
			name: "SASL with PLAIN mechanism",
			config: integrations.KafkaConfig{
				Enabled:       true,
				Brokers:       []string{"localhost:9092"},
				SASLEnabled:   true,
				SASLUsername:  "admin",
				SASLPassword:  "secret",
				SASLMechanism: "PLAIN",
			},
			expectError: false,
		},
		{
			name: "SASL with SCRAM-SHA-256 mechanism",
			config: integrations.KafkaConfig{
				Enabled:       true,
				Brokers:       []string{"localhost:9092"},
				SASLEnabled:   true,
				SASLUsername:  "admin",
				SASLPassword:  "secret",
				SASLMechanism: "SCRAM-SHA-256",
			},
			expectError: false,
		},
		{
			name: "SASL with SCRAM-SHA-512 mechanism",
			config: integrations.KafkaConfig{
				Enabled:       true,
				Brokers:       []string{"localhost:9092"},
				SASLEnabled:   true,
				SASLUsername:  "admin",
				SASLPassword:  "secret",
				SASLMechanism: "SCRAM-SHA-512",
			},
			expectError: false,
		},
		{
			name: "SASL with empty mechanism uses default",
			config: integrations.KafkaConfig{
				Enabled:      true,
				Brokers:      []string{"localhost:9092"},
				SASLEnabled:  true,
				SASLUsername: "admin",
				SASLPassword: "secret",
				// SASLMechanism empty - should be valid
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewKafkaExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if validationErr, ok := err.(*integrations.ValidationError); ok {
					assert.Equal(t, tt.errorField, validationErr.Field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// Export Tests
// =============================================================================

func TestKafkaExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export with all data types", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
			TracesTopic:  "telemetryflow-traces",
			LogsTopic:    "telemetryflow-logs",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		telemetryData := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{
					Name:      "cpu_usage",
					Value:     75.5,
					Type:      integrations.MetricTypeGauge,
					Timestamp: now,
					Tags:      map[string]string{"host": "server1"},
					Unit:      "percent",
				},
			},
			Traces: []integrations.Trace{
				{
					TraceID:       "trace-123",
					SpanID:        "span-456",
					OperationName: "http_request",
					ServiceName:   "api-gateway",
					StartTime:     now,
					Duration:      100 * time.Millisecond,
					Status:        integrations.TraceStatusOK,
					Tags:          map[string]string{"method": "GET"},
				},
			},
			Logs: []integrations.LogEntry{
				{
					Timestamp:  now,
					Level:      integrations.LogLevelInfo,
					Message:    "Request processed successfully",
					Source:     "api-service",
					Attributes: map[string]string{"request_id": "req-789"},
				},
			},
			Timestamp: now,
			AgentID:   "agent-001",
			Hostname:  "server1.example.com",
		}

		result, err := exporter.Export(ctx, telemetryData)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)
	})

	t.Run("export with only metrics", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		telemetryData := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{
					Name:      "memory_usage",
					Value:     1024.0,
					Type:      integrations.MetricTypeGauge,
					Timestamp: now,
					Unit:      "MB",
				},
				{
					Name:      "disk_usage",
					Value:     80.0,
					Type:      integrations.MetricTypeGauge,
					Timestamp: now,
					Unit:      "percent",
				},
			},
			Timestamp: now,
		}

		result, err := exporter.Export(ctx, telemetryData)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 2, result.ItemsExported)
	})

	t.Run("export with empty data", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		telemetryData := &integrations.TelemetryData{
			Timestamp: time.Now(),
		}

		result, err := exporter.Export(ctx, telemetryData)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ItemsExported)
	})

	t.Run("export fails when disabled", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled: false,
			Brokers: []string{"localhost:9092"},
		}

		exporter := integrations.NewKafkaExporter(config, logger)

		telemetryData := &integrations.TelemetryData{
			Metrics: []integrations.Metric{
				{
					Name:      "test_metric",
					Value:     1.0,
					Type:      integrations.MetricTypeGauge,
					Timestamp: time.Now(),
				},
			},
		}

		result, err := exporter.Export(ctx, telemetryData)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, integrations.ErrNotEnabled, err)
	})
}

// =============================================================================
// ExportMetrics Tests
// =============================================================================

func TestKafkaExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export single metric", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
			BatchSize:    100,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "cpu_usage",
				Value:     65.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
				Tags:      map[string]string{"host": "server1", "region": "us-west-2"},
				Unit:      "percent",
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
		assert.Greater(t, result.BytesSent, int64(0))
	})

	t.Run("export multiple metrics", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
			BatchSize:    100,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "cpu_usage",
				Value:     65.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
				Tags:      map[string]string{"host": "server1"},
				Unit:      "percent",
			},
			{
				Name:      "memory_usage",
				Value:     2048.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
				Tags:      map[string]string{"host": "server1"},
				Unit:      "MB",
			},
			{
				Name:      "disk_io",
				Value:     125.75,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
				Tags:      map[string]string{"host": "server1", "disk": "sda"},
				Unit:      "MB/s",
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)
		assert.Greater(t, result.BytesSent, int64(0))
	})

	t.Run("export metrics with different types", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "gauge_metric",
				Value:     50.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
			{
				Name:      "counter_metric",
				Value:     1000.0,
				Type:      integrations.MetricTypeCounter,
				Timestamp: now,
			},
			{
				Name:      "histogram_metric",
				Value:     75.5,
				Type:      integrations.MetricTypeHistogram,
				Timestamp: now,
			},
			{
				Name:      "summary_metric",
				Value:     99.9,
				Type:      integrations.MetricTypeSummary,
				Timestamp: now,
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 4, result.ItemsExported)
	})

	t.Run("export metrics fails when not initialized", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		// Not calling Init()

		metrics := []integrations.Metric{
			{
				Name:      "test_metric",
				Value:     1.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, integrations.ErrNotInitialized, err)
	})

	t.Run("export metrics fails when disabled", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      false,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)

		metrics := []integrations.Metric{
			{
				Name:      "test_metric",
				Value:     1.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, integrations.ErrNotEnabled, err)
	})

	t.Run("export metrics with empty slice", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		result, err := exporter.ExportMetrics(ctx, []integrations.Metric{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ItemsExported)
	})
}

// =============================================================================
// ExportTraces Tests
// =============================================================================

func TestKafkaExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export single trace", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:     true,
			Brokers:     []string{"localhost:9092"},
			TracesTopic: "telemetryflow-traces",
			BatchSize:   100,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		traces := []integrations.Trace{
			{
				TraceID:       "abc123def456",
				SpanID:        "span-001",
				ParentSpanID:  "",
				OperationName: "http.request",
				ServiceName:   "api-gateway",
				StartTime:     now,
				Duration:      150 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"http.method": "GET", "http.status_code": "200"},
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
		assert.Greater(t, result.BytesSent, int64(0))
	})

	t.Run("export multiple traces with parent-child relationship", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:     true,
			Brokers:     []string{"localhost:9092"},
			TracesTopic: "telemetryflow-traces",
			BatchSize:   100,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		traces := []integrations.Trace{
			{
				TraceID:       "trace-abc123",
				SpanID:        "span-parent",
				ParentSpanID:  "",
				OperationName: "http.request",
				ServiceName:   "frontend",
				StartTime:     now,
				Duration:      500 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"component": "nginx"},
			},
			{
				TraceID:       "trace-abc123",
				SpanID:        "span-child-1",
				ParentSpanID:  "span-parent",
				OperationName: "database.query",
				ServiceName:   "backend",
				StartTime:     now.Add(10 * time.Millisecond),
				Duration:      200 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"db.type": "postgresql"},
			},
			{
				TraceID:       "trace-abc123",
				SpanID:        "span-child-2",
				ParentSpanID:  "span-parent",
				OperationName: "cache.get",
				ServiceName:   "backend",
				StartTime:     now.Add(220 * time.Millisecond),
				Duration:      50 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
				Tags:          map[string]string{"cache.type": "redis"},
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)
	})

	t.Run("export trace with error status", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:     true,
			Brokers:     []string{"localhost:9092"},
			TracesTopic: "telemetryflow-traces",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		traces := []integrations.Trace{
			{
				TraceID:       "error-trace-001",
				SpanID:        "error-span",
				OperationName: "http.request",
				ServiceName:   "payment-service",
				StartTime:     now,
				Duration:      2 * time.Second,
				Status:        integrations.TraceStatusError,
				Tags:          map[string]string{"error": "true", "http.status_code": "500"},
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
	})

	t.Run("export traces fails when not initialized", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:     true,
			Brokers:     []string{"localhost:9092"},
			TracesTopic: "telemetryflow-traces",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		// Not calling Init()

		traces := []integrations.Trace{
			{
				TraceID:       "test-trace",
				SpanID:        "test-span",
				OperationName: "test.operation",
				ServiceName:   "test-service",
				StartTime:     time.Now(),
				Duration:      100 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, integrations.ErrNotInitialized, err)
	})

	t.Run("export traces fails when disabled", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:     false,
			Brokers:     []string{"localhost:9092"},
			TracesTopic: "telemetryflow-traces",
		}

		exporter := integrations.NewKafkaExporter(config, logger)

		traces := []integrations.Trace{
			{
				TraceID:       "test-trace",
				SpanID:        "test-span",
				OperationName: "test.operation",
				ServiceName:   "test-service",
				StartTime:     time.Now(),
				Duration:      100 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, integrations.ErrNotEnabled, err)
	})

	t.Run("export traces with empty slice", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:     true,
			Brokers:     []string{"localhost:9092"},
			TracesTopic: "telemetryflow-traces",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		result, err := exporter.ExportTraces(ctx, []integrations.Trace{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ItemsExported)
	})
}

// =============================================================================
// ExportLogs Tests
// =============================================================================

func TestKafkaExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export single log", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:   true,
			Brokers:   []string{"localhost:9092"},
			LogsTopic: "telemetryflow-logs",
			BatchSize: 100,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := []integrations.LogEntry{
			{
				Timestamp:  now,
				Level:      integrations.LogLevelInfo,
				Message:    "Application started successfully",
				Source:     "main",
				Attributes: map[string]string{"version": "1.0.0", "environment": "production"},
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
		assert.Greater(t, result.BytesSent, int64(0))
	})

	t.Run("export multiple logs with different levels", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:   true,
			Brokers:   []string{"localhost:9092"},
			LogsTopic: "telemetryflow-logs",
			BatchSize: 100,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := []integrations.LogEntry{
			{
				Timestamp:  now,
				Level:      integrations.LogLevelDebug,
				Message:    "Debug message",
				Source:     "debug-source",
				Attributes: map[string]string{"key": "value"},
			},
			{
				Timestamp: now.Add(10 * time.Millisecond),
				Level:     integrations.LogLevelInfo,
				Message:   "Info message",
				Source:    "info-source",
			},
			{
				Timestamp: now.Add(20 * time.Millisecond),
				Level:     integrations.LogLevelWarn,
				Message:   "Warning message",
				Source:    "warn-source",
			},
			{
				Timestamp: now.Add(30 * time.Millisecond),
				Level:     integrations.LogLevelError,
				Message:   "Error message",
				Source:    "error-source",
			},
			{
				Timestamp: now.Add(40 * time.Millisecond),
				Level:     integrations.LogLevelFatal,
				Message:   "Fatal message",
				Source:    "fatal-source",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 5, result.ItemsExported)
	})

	t.Run("export logs with trace correlation", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:   true,
			Brokers:   []string{"localhost:9092"},
			LogsTopic: "telemetryflow-logs",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := []integrations.LogEntry{
			{
				Timestamp:  now,
				Level:      integrations.LogLevelInfo,
				Message:    "Processing order",
				Source:     "order-service",
				TraceID:    "trace-order-123",
				SpanID:     "span-process-456",
				Attributes: map[string]string{"order_id": "ORD-001"},
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
	})

	t.Run("export logs fails when not initialized", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:   true,
			Brokers:   []string{"localhost:9092"},
			LogsTopic: "telemetryflow-logs",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		// Not calling Init()

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
		assert.Equal(t, integrations.ErrNotInitialized, err)
	})

	t.Run("export logs fails when disabled", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:   false,
			Brokers:   []string{"localhost:9092"},
			LogsTopic: "telemetryflow-logs",
		}

		exporter := integrations.NewKafkaExporter(config, logger)

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
		assert.Equal(t, integrations.ErrNotEnabled, err)
	})

	t.Run("export logs with empty slice", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:   true,
			Brokers:   []string{"localhost:9092"},
			LogsTopic: "telemetryflow-logs",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		result, err := exporter.ExportLogs(ctx, []integrations.LogEntry{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ItemsExported)
	})
}

// =============================================================================
// Health Tests
// =============================================================================

func TestKafkaExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("health check when disabled", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled: false,
		}
		exporter := integrations.NewKafkaExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("health check when enabled", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"broker1:9092", "broker2:9092", "broker3:9092"},
			MetricsTopic: "metrics",
			TracesTopic:  "traces",
			LogsTopic:    "logs",
		}
		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.True(t, status.Healthy)
		assert.Contains(t, status.Message, "3 brokers")
		assert.NotZero(t, status.LastCheck)

		// Check details
		details := status.Details
		require.NotNil(t, details)
		assert.Equal(t, []string{"broker1:9092", "broker2:9092", "broker3:9092"}, details["brokers"])
		assert.Equal(t, "metrics", details["metrics_topic"])
		assert.Equal(t, "traces", details["traces_topic"])
		assert.Equal(t, "logs", details["logs_topic"])
	})

	t.Run("health check with single broker", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled: true,
			Brokers: []string{"localhost:9092"},
		}
		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.True(t, status.Healthy)
		assert.Contains(t, status.Message, "1 brokers")
	})
}

// =============================================================================
// Close Tests
// =============================================================================

func TestKafkaExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("close after init", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "test-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)
		assert.True(t, exporter.IsInitialized())

		err = exporter.Close(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("close with pending messages", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "test-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Export some metrics to queue messages
		now := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "test_metric_1",
				Value:     1.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
			{
				Name:      "test_metric_2",
				Value:     2.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
		}
		_, err = exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)

		// Close should flush messages
		err = exporter.Close(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("close without init", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "test-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		// Not calling Init()

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})

	t.Run("close when disabled", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled: false,
		}

		exporter := integrations.NewKafkaExporter(config, logger)

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})

	t.Run("close multiple times", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "test-metrics",
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		err = exporter.Close(ctx)
		assert.NoError(t, err)

		// Close again should not error
		err = exporter.Close(ctx)
		assert.NoError(t, err)
	})
}

// =============================================================================
// SupportedDataTypes Tests
// =============================================================================

func TestKafkaExporterSupportedTypes(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.KafkaConfig{
		Enabled: true,
		Brokers: []string{"localhost:9092"},
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	types := exporter.SupportedDataTypes()

	assert.Len(t, types, 3)
	assert.Contains(t, types, integrations.DataTypeMetrics)
	assert.Contains(t, types, integrations.DataTypeTraces)
	assert.Contains(t, types, integrations.DataTypeLogs)
}

// =============================================================================
// Config Defaults Tests
// =============================================================================

func TestKafkaConfigDefaults(t *testing.T) {
	config := integrations.KafkaConfig{}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.Brokers)
	assert.Empty(t, config.MetricsTopic)
	assert.Empty(t, config.TracesTopic)
	assert.Empty(t, config.LogsTopic)
	assert.Empty(t, config.ClientID)
	assert.Empty(t, config.Compression)
	assert.Equal(t, 0, config.RequiredAcks)
	assert.Equal(t, 0, config.MaxRetries)
	assert.Equal(t, 0, config.BatchSize)
	assert.Equal(t, time.Duration(0), config.BatchTimeout)
	assert.Equal(t, time.Duration(0), config.FlushFrequency)
	assert.False(t, config.TLSEnabled)
	assert.False(t, config.TLSSkipVerify)
	assert.False(t, config.SASLEnabled)
	assert.Empty(t, config.PartitionStrategy)
}

// =============================================================================
// Config Variations Tests
// =============================================================================

func TestKafkaExporterWithHeaders(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.KafkaConfig{
		Enabled: true,
		Brokers: []string{"localhost:9092"},
		Headers: map[string]string{
			"X-Source":      "telemetryflow",
			"X-Environment": "production",
			"X-Version":     "1.0.0",
		},
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestKafkaExporterWithCompression(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	compressionTypes := []string{"none", "gzip", "snappy", "lz4", "zstd"}

	for _, compression := range compressionTypes {
		t.Run("compression_"+compression, func(t *testing.T) {
			config := integrations.KafkaConfig{
				Enabled:     true,
				Brokers:     []string{"localhost:9092"},
				Compression: compression,
			}

			exporter := integrations.NewKafkaExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)
			assert.True(t, exporter.IsInitialized())
		})
	}
}

func TestKafkaExporterWithPartitionStrategies(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	strategies := []string{"round_robin", "hash", "random", "manual"}

	for _, strategy := range strategies {
		t.Run("partition_"+strategy, func(t *testing.T) {
			config := integrations.KafkaConfig{
				Enabled:           true,
				Brokers:           []string{"localhost:9092"},
				PartitionStrategy: strategy,
			}

			exporter := integrations.NewKafkaExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)
			assert.True(t, exporter.IsInitialized())
		})
	}
}

func TestKafkaExporterWithAcks(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// -1 = wait for all replicas, 0 = no wait, 1 = wait for leader
	ackValues := []int{-1, 0, 1}

	for _, acks := range ackValues {
		t.Run("acks_"+string(rune('0'+acks+1)), func(t *testing.T) {
			config := integrations.KafkaConfig{
				Enabled:      true,
				Brokers:      []string{"localhost:9092"},
				RequiredAcks: acks,
			}

			exporter := integrations.NewKafkaExporter(config, logger)
			err := exporter.Init(ctx)
			require.NoError(t, err)
			assert.True(t, exporter.IsInitialized())
		})
	}
}

// =============================================================================
// Batch Export Tests
// =============================================================================

func TestKafkaExporterBatchExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("large batch of metrics", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
			BatchSize:    10,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := make([]integrations.Metric, 100)
		for i := 0; i < 100; i++ {
			metrics[i] = integrations.Metric{
				Name:      "batch_metric",
				Value:     float64(i),
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
				Tags:      map[string]string{"index": string(rune('0' + i%10))},
			}
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 100, result.ItemsExported)
		assert.Greater(t, result.BytesSent, int64(0))
	})

	t.Run("large batch of traces", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:     true,
			Brokers:     []string{"localhost:9092"},
			TracesTopic: "telemetryflow-traces",
			BatchSize:   10,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		traces := make([]integrations.Trace, 50)
		for i := 0; i < 50; i++ {
			traces[i] = integrations.Trace{
				TraceID:       "batch-trace-id",
				SpanID:        "span-" + string(rune('a'+i%26)),
				OperationName: "batch.operation",
				ServiceName:   "batch-service",
				StartTime:     now.Add(time.Duration(i) * time.Millisecond),
				Duration:      time.Duration(i+1) * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			}
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 50, result.ItemsExported)
	})

	t.Run("large batch of logs", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:   true,
			Brokers:   []string{"localhost:9092"},
			LogsTopic: "telemetryflow-logs",
			BatchSize: 10,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := make([]integrations.LogEntry, 75)
		levels := []integrations.LogLevel{
			integrations.LogLevelDebug,
			integrations.LogLevelInfo,
			integrations.LogLevelWarn,
			integrations.LogLevelError,
		}
		for i := 0; i < 75; i++ {
			logs[i] = integrations.LogEntry{
				Timestamp: now.Add(time.Duration(i) * time.Millisecond),
				Level:     levels[i%len(levels)],
				Message:   "Batch log message",
				Source:    "batch-source",
			}
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 75, result.ItemsExported)
	})

	t.Run("combined large batch export", func(t *testing.T) {
		config := integrations.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			MetricsTopic: "telemetryflow-metrics",
			TracesTopic:  "telemetryflow-traces",
			LogsTopic:    "telemetryflow-logs",
			BatchSize:    25,
		}

		exporter := integrations.NewKafkaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()

		// Create 50 metrics
		metrics := make([]integrations.Metric, 50)
		for i := 0; i < 50; i++ {
			metrics[i] = integrations.Metric{
				Name:      "combined_metric",
				Value:     float64(i),
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			}
		}

		// Create 50 traces
		traces := make([]integrations.Trace, 50)
		for i := 0; i < 50; i++ {
			traces[i] = integrations.Trace{
				TraceID:       "combined-trace",
				SpanID:        "span-" + string(rune('a'+i%26)),
				OperationName: "combined.operation",
				ServiceName:   "combined-service",
				StartTime:     now,
				Duration:      time.Duration(i) * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			}
		}

		// Create 50 logs
		logs := make([]integrations.LogEntry, 50)
		for i := 0; i < 50; i++ {
			logs[i] = integrations.LogEntry{
				Timestamp: now,
				Level:     integrations.LogLevelInfo,
				Message:   "Combined log message",
				Source:    "combined-source",
			}
		}

		telemetryData := &integrations.TelemetryData{
			Metrics:   metrics,
			Traces:    traces,
			Logs:      logs,
			Timestamp: now,
		}

		result, err := exporter.Export(ctx, telemetryData)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 150, result.ItemsExported)
	})
}

// =============================================================================
// Stats Tests
// =============================================================================

func TestKafkaExporterStats(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		MetricsTopic: "telemetryflow-metrics",
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Initial stats
	stats := exporter.Stats()
	assert.Equal(t, "kafka", stats.Name)
	assert.Equal(t, "streaming", stats.Type)
	assert.True(t, stats.Enabled)
	assert.True(t, stats.Initialized)
	assert.Equal(t, int64(0), stats.ExportCount)
	assert.Equal(t, int64(0), stats.BytesExported)
	assert.Equal(t, int64(0), stats.ErrorCount)

	// Export some metrics
	now := time.Now()
	metrics := []integrations.Metric{
		{
			Name:      "stats_metric",
			Value:     1.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: now,
		},
	}

	_, err = exporter.ExportMetrics(ctx, metrics)
	require.NoError(t, err)

	// Check stats after export
	stats = exporter.Stats()
	assert.Equal(t, int64(1), stats.ExportCount)
	assert.Greater(t, stats.BytesExported, int64(0))
	assert.NotZero(t, stats.LastSuccess)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkNewKafkaExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		MetricsTopic: "test-metrics",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewKafkaExporter(config, logger)
	}
}

func BenchmarkKafkaExporterInit(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		MetricsTopic: "test-metrics",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter := integrations.NewKafkaExporter(config, logger)
		_ = exporter.Init(ctx)
	}
}

func BenchmarkKafkaExporterExportMetrics(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		MetricsTopic: "test-metrics",
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	_ = exporter.Init(ctx)

	now := time.Now()
	metrics := []integrations.Metric{
		{
			Name:      "benchmark_metric",
			Value:     1.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: now,
			Tags:      map[string]string{"host": "server1"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkKafkaExporterExportTraces(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.KafkaConfig{
		Enabled:     true,
		Brokers:     []string{"localhost:9092"},
		TracesTopic: "test-traces",
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	_ = exporter.Init(ctx)

	now := time.Now()
	traces := []integrations.Trace{
		{
			TraceID:       "benchmark-trace",
			SpanID:        "benchmark-span",
			OperationName: "benchmark.operation",
			ServiceName:   "benchmark-service",
			StartTime:     now,
			Duration:      100 * time.Millisecond,
			Status:        integrations.TraceStatusOK,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportTraces(ctx, traces)
	}
}

func BenchmarkKafkaExporterExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.KafkaConfig{
		Enabled:   true,
		Brokers:   []string{"localhost:9092"},
		LogsTopic: "test-logs",
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	_ = exporter.Init(ctx)

	now := time.Now()
	logs := []integrations.LogEntry{
		{
			Timestamp: now,
			Level:     integrations.LogLevelInfo,
			Message:   "Benchmark log message",
			Source:    "benchmark-source",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}

func BenchmarkKafkaExporterExportBatch(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		MetricsTopic: "test-metrics",
		BatchSize:    100,
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	_ = exporter.Init(ctx)

	now := time.Now()
	metrics := make([]integrations.Metric, 100)
	for i := 0; i < 100; i++ {
		metrics[i] = integrations.Metric{
			Name:      "batch_benchmark_metric",
			Value:     float64(i),
			Type:      integrations.MetricTypeGauge,
			Timestamp: now,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkKafkaExporterHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		MetricsTopic: "test-metrics",
	}

	exporter := integrations.NewKafkaExporter(config, logger)
	_ = exporter.Init(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}
