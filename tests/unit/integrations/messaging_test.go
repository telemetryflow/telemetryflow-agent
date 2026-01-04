// package integrations_test provides unit tests for TelemetryFlow Agent messaging integrations.
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

// TestMQTTExporterExport tests the Export method with TelemetryData
func TestMQTTExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export with all data types", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			TracesTopic:  "telemetryflow/traces",
			LogsTopic:    "telemetryflow/logs",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled: false,
			Broker:  "tcp://localhost:1883",
		}

		exporter := integrations.NewMQTTExporter(config, logger)

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
	})
}

// TestMQTTExporterExportMetrics tests ExportMetrics with a mock server
func TestMQTTExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export single metric", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			BatchSize:    100,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			BatchSize:    100,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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

	t.Run("export metrics with topic prefix", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "metrics",
			TopicPrefix:  "production/telemetryflow",
			BatchSize:    100,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "request_count",
				Value:     1000.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
	})

	t.Run("export metrics fails when not initialized", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
	})

	t.Run("export metrics with labels", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			Labels:       map[string]string{"env": "production", "app": "telemetryflow"},
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "api_latency",
				Value:     50.5,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
				Unit:      "ms",
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.ItemsExported)
	})
}

// TestMQTTExporterExportTraces tests ExportTraces
func TestMQTTExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export single trace", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:     true,
			Broker:      "tcp://localhost:1883",
			TracesTopic: "telemetryflow/traces",
			BatchSize:   100,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:     true,
			Broker:      "tcp://localhost:1883",
			TracesTopic: "telemetryflow/traces",
			BatchSize:   100,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:     true,
			Broker:      "tcp://localhost:1883",
			TracesTopic: "telemetryflow/traces",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:     true,
			Broker:      "tcp://localhost:1883",
			TracesTopic: "telemetryflow/traces",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
	})

	t.Run("export traces with labels", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:     true,
			Broker:      "tcp://localhost:1883",
			TracesTopic: "telemetryflow/traces",
			Labels:      map[string]string{"cluster": "prod-us-east-1", "team": "platform"},
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		traces := []integrations.Trace{
			{
				TraceID:       "labeled-trace",
				SpanID:        "labeled-span",
				OperationName: "grpc.call",
				ServiceName:   "user-service",
				StartTime:     now,
				Duration:      75 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
	})
}

// TestMQTTExporterExportLogs tests ExportLogs
func TestMQTTExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export single log", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:   true,
			Broker:    "tcp://localhost:1883",
			LogsTopic: "telemetryflow/logs",
			BatchSize: 100,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:   true,
			Broker:    "tcp://localhost:1883",
			LogsTopic: "telemetryflow/logs",
			BatchSize: 100,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := []integrations.LogEntry{
			{
				Timestamp:  now,
				Level:      integrations.LogLevelInfo,
				Message:    "Request received",
				Source:     "http-handler",
				Attributes: map[string]string{"method": "POST", "path": "/api/users"},
			},
			{
				Timestamp:  now.Add(10 * time.Millisecond),
				Level:      integrations.LogLevelInfo,
				Message:    "Database query executed",
				Source:     "db-layer",
				Attributes: map[string]string{"query_time": "15ms"},
			},
			{
				Timestamp:  now.Add(50 * time.Millisecond),
				Level:      integrations.LogLevelInfo,
				Message:    "Response sent",
				Source:     "http-handler",
				Attributes: map[string]string{"status": "201"},
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 3, result.ItemsExported)
	})

	t.Run("export logs with trace correlation", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:   true,
			Broker:    "tcp://localhost:1883",
			LogsTopic: "telemetryflow/logs",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
		config := integrations.MQTTConfig{
			Enabled:   true,
			Broker:    "tcp://localhost:1883",
			LogsTopic: "telemetryflow/logs",
		}

		exporter := integrations.NewMQTTExporter(config, logger)
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
	})

	t.Run("export logs with labels", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:   true,
			Broker:    "tcp://localhost:1883",
			LogsTopic: "telemetryflow/logs",
			Labels:    map[string]string{"datacenter": "dc1", "service_tier": "critical"},
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := []integrations.LogEntry{
			{
				Timestamp: now,
				Level:     integrations.LogLevelInfo,
				Message:   "Health check passed",
				Source:    "health-checker",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
	})
}

// TestMQTTExporterExportWithBatching tests batch processing
func TestMQTTExporterExportWithBatching(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("batch metrics with small batch size", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			BatchSize:    2,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := []integrations.Metric{
			{
				Name:      "metric_1",
				Value:     1.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
			{
				Name:      "metric_2",
				Value:     2.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
			{
				Name:      "metric_3",
				Value:     3.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
			{
				Name:      "metric_4",
				Value:     4.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
			{
				Name:      "metric_5",
				Value:     5.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 5, result.ItemsExported)
		// With batch size 2, 5 metrics should result in 3 batches
	})

	t.Run("batch traces with small batch size", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:     true,
			Broker:      "tcp://localhost:1883",
			TracesTopic: "telemetryflow/traces",
			BatchSize:   3,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		traces := make([]integrations.Trace, 10)
		for i := 0; i < 10; i++ {
			traces[i] = integrations.Trace{
				TraceID:       "batch-trace-" + string(rune('0'+i)),
				SpanID:        "batch-span-" + string(rune('0'+i)),
				OperationName: "batch.operation",
				ServiceName:   "batch-service",
				StartTime:     now.Add(time.Duration(i) * time.Millisecond),
				Duration:      10 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			}
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 10, result.ItemsExported)
		// With batch size 3, 10 traces should result in 4 batches
	})

	t.Run("batch logs with small batch size", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:   true,
			Broker:    "tcp://localhost:1883",
			LogsTopic: "telemetryflow/logs",
			BatchSize: 4,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		logs := make([]integrations.LogEntry, 15)
		for i := 0; i < 15; i++ {
			logs[i] = integrations.LogEntry{
				Timestamp: now.Add(time.Duration(i) * time.Millisecond),
				Level:     integrations.LogLevelInfo,
				Message:   "Batch log message " + string(rune('0'+i)),
				Source:    "batch-source",
			}
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 15, result.ItemsExported)
		// With batch size 4, 15 logs should result in 4 batches
	})

	t.Run("batch exactly matches batch size", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			BatchSize:    5,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := make([]integrations.Metric, 10)
		for i := 0; i < 10; i++ {
			metrics[i] = integrations.Metric{
				Name:      "exact_batch_metric",
				Value:     float64(i),
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			}
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 10, result.ItemsExported)
		// With batch size 5, 10 metrics should result in exactly 2 batches
	})

	t.Run("batch with default batch size", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			// BatchSize not set, should default to 100
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()
		metrics := make([]integrations.Metric, 50)
		for i := 0; i < 50; i++ {
			metrics[i] = integrations.Metric{
				Name:      "default_batch_metric",
				Value:     float64(i),
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			}
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 50, result.ItemsExported)
		// With default batch size 100, 50 metrics should be in 1 batch
	})

	t.Run("large batch export with all data types", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "telemetryflow/metrics",
			TracesTopic:  "telemetryflow/traces",
			LogsTopic:    "telemetryflow/logs",
			BatchSize:    10,
		}

		exporter := integrations.NewMQTTExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		now := time.Now()

		// Create 25 metrics
		metrics := make([]integrations.Metric, 25)
		for i := 0; i < 25; i++ {
			metrics[i] = integrations.Metric{
				Name:      "large_batch_metric",
				Value:     float64(i),
				Type:      integrations.MetricTypeGauge,
				Timestamp: now,
			}
		}

		// Create 25 traces
		traces := make([]integrations.Trace, 25)
		for i := 0; i < 25; i++ {
			traces[i] = integrations.Trace{
				TraceID:       "large-batch-trace",
				SpanID:        "span-" + string(rune('a'+i%26)),
				OperationName: "large.batch.operation",
				ServiceName:   "large-batch-service",
				StartTime:     now,
				Duration:      time.Duration(i) * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			}
		}

		// Create 25 logs
		logs := make([]integrations.LogEntry, 25)
		for i := 0; i < 25; i++ {
			logs[i] = integrations.LogEntry{
				Timestamp: now,
				Level:     integrations.LogLevelInfo,
				Message:   "Large batch log",
				Source:    "large-batch-source",
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
		assert.Equal(t, 75, result.ItemsExported)
	})
}
