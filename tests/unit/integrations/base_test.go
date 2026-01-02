// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
package integrations_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

func TestDataTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		dataType integrations.DataType
		expected string
	}{
		{"metrics type", integrations.DataTypeMetrics, "metrics"},
		{"traces type", integrations.DataTypeTraces, "traces"},
		{"logs type", integrations.DataTypeLogs, "logs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.dataType))
		})
	}
}

func TestMetricTypeConstants(t *testing.T) {
	tests := []struct {
		name       string
		metricType integrations.MetricType
		expected   string
	}{
		{"gauge type", integrations.MetricTypeGauge, "gauge"},
		{"counter type", integrations.MetricTypeCounter, "counter"},
		{"histogram type", integrations.MetricTypeHistogram, "histogram"},
		{"summary type", integrations.MetricTypeSummary, "summary"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.metricType))
		})
	}
}

func TestTraceStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		status   integrations.TraceStatus
		expected string
	}{
		{"ok status", integrations.TraceStatusOK, "ok"},
		{"error status", integrations.TraceStatusError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.status))
		})
	}
}

func TestLogLevelConstants(t *testing.T) {
	tests := []struct {
		name     string
		level    integrations.LogLevel
		expected string
	}{
		{"debug level", integrations.LogLevelDebug, "debug"},
		{"info level", integrations.LogLevelInfo, "info"},
		{"warn level", integrations.LogLevelWarn, "warn"},
		{"error level", integrations.LogLevelError, "error"},
		{"fatal level", integrations.LogLevelFatal, "fatal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.level))
		})
	}
}

func TestNewBaseExporter(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name            string
		exporterName    string
		integrationType string
		enabled         bool
		supportedTypes  []integrations.DataType
	}{
		{
			name:            "enabled exporter with all types",
			exporterName:    "test-exporter",
			integrationType: "test",
			enabled:         true,
			supportedTypes:  []integrations.DataType{integrations.DataTypeMetrics, integrations.DataTypeTraces, integrations.DataTypeLogs},
		},
		{
			name:            "disabled exporter",
			exporterName:    "disabled-exporter",
			integrationType: "test",
			enabled:         false,
			supportedTypes:  []integrations.DataType{integrations.DataTypeMetrics},
		},
		{
			name:            "exporter with metrics only",
			exporterName:    "metrics-only",
			integrationType: "metrics",
			enabled:         true,
			supportedTypes:  []integrations.DataType{integrations.DataTypeMetrics},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewBaseExporter(tt.exporterName, tt.integrationType, tt.enabled, logger, tt.supportedTypes)

			require.NotNil(t, exporter)
			assert.Equal(t, tt.exporterName, exporter.Name())
			assert.Equal(t, tt.integrationType, exporter.Type())
			assert.Equal(t, tt.enabled, exporter.IsEnabled())
			assert.Equal(t, tt.supportedTypes, exporter.SupportedDataTypes())
			assert.NotNil(t, exporter.Logger())
		})
	}
}

func TestNewBaseExporterWithNilLogger(t *testing.T) {
	exporter := integrations.NewBaseExporter("test", "test", true, nil, []integrations.DataType{integrations.DataTypeMetrics})

	require.NotNil(t, exporter)
	assert.NotNil(t, exporter.Logger())
}

func TestBaseExporterInitialization(t *testing.T) {
	logger := zap.NewNop()
	exporter := integrations.NewBaseExporter("test", "test", true, logger, []integrations.DataType{integrations.DataTypeMetrics})

	assert.False(t, exporter.IsInitialized())

	exporter.SetInitialized(true)
	assert.True(t, exporter.IsInitialized())

	exporter.SetInitialized(false)
	assert.False(t, exporter.IsInitialized())
}

func TestBaseExporterRecordSuccess(t *testing.T) {
	logger := zap.NewNop()
	exporter := integrations.NewBaseExporter("test", "test", true, logger, []integrations.DataType{integrations.DataTypeMetrics})

	exporter.RecordSuccess(1024)
	stats := exporter.Stats()

	assert.Equal(t, int64(1), stats.ExportCount)
	assert.Equal(t, int64(1024), stats.BytesExported)
	assert.Nil(t, stats.LastError)
	assert.False(t, stats.LastSuccess.IsZero())

	exporter.RecordSuccess(2048)
	stats = exporter.Stats()

	assert.Equal(t, int64(2), stats.ExportCount)
	assert.Equal(t, int64(3072), stats.BytesExported)
}

func TestBaseExporterRecordError(t *testing.T) {
	logger := zap.NewNop()
	exporter := integrations.NewBaseExporter("test", "test", true, logger, []integrations.DataType{integrations.DataTypeMetrics})

	err := integrations.ErrExportFailed
	exporter.RecordError(err)
	stats := exporter.Stats()

	assert.Equal(t, int64(1), stats.ErrorCount)
	assert.Equal(t, err, stats.LastError)

	exporter.RecordError(integrations.ErrTimeout)
	stats = exporter.Stats()

	assert.Equal(t, int64(2), stats.ErrorCount)
	assert.Equal(t, integrations.ErrTimeout, stats.LastError)
}

func TestBaseExporterStats(t *testing.T) {
	logger := zap.NewNop()
	exporter := integrations.NewBaseExporter("test-name", "test-type", true, logger, []integrations.DataType{integrations.DataTypeMetrics})

	exporter.SetInitialized(true)
	exporter.RecordSuccess(100)
	exporter.RecordError(integrations.ErrExportFailed)
	exporter.RecordSuccess(200)

	stats := exporter.Stats()

	assert.Equal(t, "test-name", stats.Name)
	assert.Equal(t, "test-type", stats.Type)
	assert.True(t, stats.Enabled)
	assert.True(t, stats.Initialized)
	assert.Equal(t, int64(2), stats.ExportCount)
	assert.Equal(t, int64(1), stats.ErrorCount)
	assert.Equal(t, int64(300), stats.BytesExported)
}

func TestValidationError(t *testing.T) {
	err := integrations.NewValidationError("mqtt", "broker", "broker URL is required")

	assert.Equal(t, "mqtt", err.Integration)
	assert.Equal(t, "broker", err.Field)
	assert.Equal(t, "broker URL is required", err.Message)
	assert.Equal(t, "mqtt: broker - broker URL is required", err.Error())
}

func TestCommonErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"not enabled", integrations.ErrNotEnabled, "integration is not enabled"},
		{"not initialized", integrations.ErrNotInitialized, "integration is not initialized"},
		{"missing endpoint", integrations.ErrMissingEndpoint, "endpoint is required"},
		{"missing api key", integrations.ErrMissingAPIKey, "api_key is required"},
		{"missing token", integrations.ErrMissingToken, "token is required"},
		{"invalid endpoint", integrations.ErrInvalidEndpoint, "invalid endpoint URL"},
		{"connection failed", integrations.ErrConnectionFailed, "connection failed"},
		{"export failed", integrations.ErrExportFailed, "export failed"},
		{"timeout", integrations.ErrTimeout, "operation timed out"},
		{"rate limited", integrations.ErrRateLimited, "rate limited"},
		{"auth failed", integrations.ErrAuthFailed, "authentication failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestMetricStruct(t *testing.T) {
	metric := integrations.Metric{
		Name:      "cpu.usage",
		Value:     75.5,
		Type:      integrations.MetricTypeGauge,
		Timestamp: time.Now(),
		Tags:      map[string]string{"host": "test-host"},
		Unit:      "percent",
		Interval:  15 * time.Second,
	}

	assert.Equal(t, "cpu.usage", metric.Name)
	assert.Equal(t, 75.5, metric.Value)
	assert.Equal(t, integrations.MetricTypeGauge, metric.Type)
	assert.NotEmpty(t, metric.Tags)
	assert.Equal(t, "percent", metric.Unit)
	assert.Equal(t, 15*time.Second, metric.Interval)
}

func TestTraceStruct(t *testing.T) {
	trace := integrations.Trace{
		TraceID:       "trace-123",
		SpanID:        "span-456",
		ParentSpanID:  "span-000",
		OperationName: "http.request",
		ServiceName:   "api-service",
		StartTime:     time.Now(),
		Duration:      100 * time.Millisecond,
		Status:        integrations.TraceStatusOK,
		Tags:          map[string]string{"http.method": "GET"},
		Logs: []integrations.SpanLog{
			{
				Timestamp: time.Now(),
				Message:   "request started",
				Fields:    map[string]string{"level": "info"},
			},
		},
	}

	assert.Equal(t, "trace-123", trace.TraceID)
	assert.Equal(t, "span-456", trace.SpanID)
	assert.Equal(t, "span-000", trace.ParentSpanID)
	assert.Equal(t, "http.request", trace.OperationName)
	assert.Equal(t, "api-service", trace.ServiceName)
	assert.Equal(t, integrations.TraceStatusOK, trace.Status)
	assert.Len(t, trace.Logs, 1)
}

func TestLogEntryStruct(t *testing.T) {
	entry := integrations.LogEntry{
		Timestamp:  time.Now(),
		Level:      integrations.LogLevelInfo,
		Message:    "test log message",
		Source:     "test-source",
		TraceID:    "trace-123",
		SpanID:     "span-456",
		Attributes: map[string]string{"key": "value"},
	}

	assert.Equal(t, integrations.LogLevelInfo, entry.Level)
	assert.Equal(t, "test log message", entry.Message)
	assert.Equal(t, "test-source", entry.Source)
	assert.Equal(t, "trace-123", entry.TraceID)
	assert.Equal(t, "span-456", entry.SpanID)
	assert.NotEmpty(t, entry.Attributes)
}

func TestTelemetryDataStruct(t *testing.T) {
	data := integrations.TelemetryData{
		Metrics: []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge},
		},
		Traces: []integrations.Trace{
			{TraceID: "trace-1", SpanID: "span-1", OperationName: "test"},
		},
		Logs: []integrations.LogEntry{
			{Level: integrations.LogLevelInfo, Message: "test log"},
		},
		Timestamp: time.Now(),
		AgentID:   "agent-123",
		Hostname:  "test-host",
		Tags:      map[string]string{"env": "test"},
	}

	assert.Len(t, data.Metrics, 1)
	assert.Len(t, data.Traces, 1)
	assert.Len(t, data.Logs, 1)
	assert.Equal(t, "agent-123", data.AgentID)
	assert.Equal(t, "test-host", data.Hostname)
}

func TestHealthStatusStruct(t *testing.T) {
	status := integrations.HealthStatus{
		Healthy:     true,
		Message:     "connected",
		LastCheck:   time.Now(),
		LastSuccess: time.Now(),
		Latency:     50 * time.Millisecond,
		Details: map[string]interface{}{
			"version": "1.0.0",
		},
	}

	assert.True(t, status.Healthy)
	assert.Equal(t, "connected", status.Message)
	assert.NotZero(t, status.LastCheck)
	assert.Equal(t, 50*time.Millisecond, status.Latency)
	assert.NotEmpty(t, status.Details)
}

func TestExportResultStruct(t *testing.T) {
	result := integrations.ExportResult{
		Success:       true,
		ItemsExported: 100,
		BytesSent:     1024,
		Duration:      100 * time.Millisecond,
		RetryCount:    2,
	}

	assert.True(t, result.Success)
	assert.Equal(t, 100, result.ItemsExported)
	assert.Equal(t, int64(1024), result.BytesSent)
	assert.Equal(t, 100*time.Millisecond, result.Duration)
	assert.Equal(t, 2, result.RetryCount)
}

func TestExporterStatsStruct(t *testing.T) {
	stats := integrations.ExporterStats{
		Name:          "test-exporter",
		Type:          "test",
		Enabled:       true,
		Initialized:   true,
		ExportCount:   100,
		ErrorCount:    5,
		BytesExported: 10240,
		LastSuccess:   time.Now(),
	}

	assert.Equal(t, "test-exporter", stats.Name)
	assert.Equal(t, "test", stats.Type)
	assert.True(t, stats.Enabled)
	assert.True(t, stats.Initialized)
	assert.Equal(t, int64(100), stats.ExportCount)
	assert.Equal(t, int64(5), stats.ErrorCount)
	assert.Equal(t, int64(10240), stats.BytesExported)
}

func TestSpanLogStruct(t *testing.T) {
	log := integrations.SpanLog{
		Timestamp: time.Now(),
		Message:   "span log message",
		Fields:    map[string]string{"key": "value"},
	}

	assert.Equal(t, "span log message", log.Message)
	assert.NotEmpty(t, log.Fields)
	assert.NotZero(t, log.Timestamp)
}

// Benchmark tests
func BenchmarkNewBaseExporter(b *testing.B) {
	logger := zap.NewNop()
	types := []integrations.DataType{integrations.DataTypeMetrics, integrations.DataTypeTraces, integrations.DataTypeLogs}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewBaseExporter("test", "test", true, logger, types)
	}
}

func BenchmarkBaseExporterRecordSuccess(b *testing.B) {
	logger := zap.NewNop()
	exporter := integrations.NewBaseExporter("test", "test", true, logger, []integrations.DataType{integrations.DataTypeMetrics})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter.RecordSuccess(1024)
	}
}

func BenchmarkBaseExporterStats(b *testing.B) {
	logger := zap.NewNop()
	exporter := integrations.NewBaseExporter("test", "test", true, logger, []integrations.DataType{integrations.DataTypeMetrics})
	exporter.SetInitialized(true)
	exporter.RecordSuccess(1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter.Stats()
	}
}
