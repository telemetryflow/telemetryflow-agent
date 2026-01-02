// package integrations_test provides unit tests for TelemetryFlow Agent Alibaba Cloud integrations.
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

// Test Alibaba config defaults
func TestAlibabaConfigDefaults(t *testing.T) {
	config := integrations.AlibabaConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.RegionID)
}

// Benchmark tests
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

// ============================================================================
// Alibaba Exporter Health Function Comprehensive Tests
// ============================================================================

func TestAlibabaExporterHealthSuccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint that returns 200
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.Path, "logstores")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"logstores": []string{"test-logstore"},
		})
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		Project:         "test-project",
		SLSEndpoint:     slsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.True(t, status.Healthy)
	assert.Equal(t, "Alibaba Cloud connected", status.Message)
	assert.NotNil(t, status.Details)
	assert.Equal(t, "cn-hangzhou", status.Details["region_id"])
	assert.Equal(t, "test-project", status.Details["project"])
	assert.NotZero(t, status.Latency)
}

func TestAlibabaExporterHealthServerError500(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint that returns 500
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"errorCode":    "InternalError",
			"errorMessage": "Internal server error",
		})
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		SLSEndpoint:     slsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "500")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestAlibabaExporterHealthServerError503(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint that returns 503
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"errorCode":    "ServiceUnavailable",
			"errorMessage": "Service temporarily unavailable",
		})
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-shanghai",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		SLSEndpoint:     slsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "503")
	assert.NotNil(t, status.LastError)
}

func TestAlibabaExporterHealthConnectionTimeout(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint that times out
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		SLSEndpoint:     slsServer.URL,
		Timeout:         100 * time.Millisecond, // Very short timeout
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
}

func TestAlibabaExporterHealthInvalidResponseBody(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint that returns invalid JSON with error status
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid json response {{{"))
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		SLSEndpoint:     slsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.NotNil(t, status.LastError)
}

func TestAlibabaExporterHealthNetworkError(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Use invalid endpoint to simulate network error
	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		SLSEndpoint:     "http://localhost:59999", // Non-existent port
		Timeout:         1 * time.Second,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
	assert.NotNil(t, status.LastError)
	assert.NotZero(t, status.Latency)
}

func TestAlibabaExporterHealthAuthenticationFailure(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint that returns 401 Unauthorized
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"errorCode":    "Unauthorized",
			"errorMessage": "The AccessKeyId or signature is invalid",
		})
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "invalid-access-key",
		AccessKeySecret: "invalid-secret-key",
		SLSEndpoint:     slsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "401")
	assert.NotNil(t, status.LastError)
}

func TestAlibabaExporterHealthForbidden(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Create mock SLS endpoint that returns 403 Forbidden
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"errorCode":    "Forbidden",
			"errorMessage": "Access denied to project",
		})
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		SLSEndpoint:     slsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	err := exporter.Init(ctx)
	require.NoError(t, err)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "403")
}

func TestAlibabaExporterHealthDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.AlibabaConfig{Enabled: false}
	exporter := integrations.NewAlibabaExporter(config, logger)

	status, err := exporter.Health(ctx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Equal(t, "integration disabled", status.Message)
}

func TestAlibabaExporterHealthContextCanceled(t *testing.T) {
	logger := zap.NewNop()

	// Create mock SLS endpoint that delays response
	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slsServer.Close()

	config := integrations.AlibabaConfig{
		Enabled:         true,
		RegionID:        "cn-hangzhou",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-secret-key",
		SLSEndpoint:     slsServer.URL,
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	ctx := context.Background()
	err := exporter.Init(ctx)
	require.NoError(t, err)

	// Create a context that will be canceled
	cancelCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	status, err := exporter.Health(cancelCtx)
	require.NoError(t, err)
	assert.False(t, status.Healthy)
	assert.Contains(t, status.Message, "connection failed")
}

// ============================================================================
// sendSLSRequest Tests - HTTP Status Codes
// ============================================================================

func TestAlibabaSendSLSRequestHTTPStatusCodes(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name          string
		statusCode    int
		expectSuccess bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "200 OK",
			statusCode:    http.StatusOK,
			expectSuccess: true,
			expectError:   false,
		},
		{
			name:          "201 Created",
			statusCode:    http.StatusCreated,
			expectSuccess: true,
			expectError:   false,
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=400",
		},
		{
			name:          "401 Unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=401",
		},
		{
			name:          "403 Forbidden",
			statusCode:    http.StatusForbidden,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=403",
		},
		{
			name:          "404 Not Found",
			statusCode:    http.StatusNotFound,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=404",
		},
		{
			name:          "429 Too Many Requests",
			statusCode:    http.StatusTooManyRequests,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=429",
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=500",
		},
		{
			name:          "502 Bad Gateway",
			statusCode:    http.StatusBadGateway,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=502",
		},
		{
			name:          "503 Service Unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectSuccess: false,
			expectError:   true,
			errorContains: "SLS API error: status=503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode >= 400 {
					_ = json.NewEncoder(w).Encode(map[string]string{
						"errorCode":    "TestError",
						"errorMessage": "Test error message",
					})
				}
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
			}

			exporter := integrations.NewAlibabaExporter(config, logger)
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

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.expectSuccess, result.Success)
		})
	}
}

// ============================================================================
// sendSLSRequest Tests - Network Errors and Timeouts
// ============================================================================

func TestAlibabaSendSLSRequestNetworkErrors(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("connection refused", func(t *testing.T) {
		config := integrations.AlibabaConfig{
			Enabled:         true,
			RegionID:        "cn-hangzhou",
			AccessKeyID:     "test-access-key",
			AccessKeySecret: "test-secret-key",
			Project:         "test-project",
			Logstore:        "test-logstore",
			SLSEndpoint:     "http://127.0.0.1:59999",
			Timeout:         1 * time.Second,
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("request timeout", func(t *testing.T) {
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
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
			Timeout:         100 * time.Millisecond,
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("context cancelled", func(t *testing.T) {
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
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
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(cancelCtx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})

	t.Run("server closes connection", func(t *testing.T) {
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				if conn != nil {
					_ = conn.Close()
				}
			}
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
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
	})
}

// ============================================================================
// sendSLSRequest Tests - Headers
// ============================================================================

func TestAlibabaSendSLSRequestHeaders(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("verifies required headers", func(t *testing.T) {
		var receivedHeaders http.Header
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
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
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		_, err = exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)

		assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
		assert.NotEmpty(t, receivedHeaders.Get("x-log-bodyrawsize"))
		assert.NotEmpty(t, receivedHeaders.Get("x-log-apiversion"))
	})
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

func TestAlibabaEdgeCases(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("empty logs slice", func(t *testing.T) {
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		result, err := exporter.ExportLogs(ctx, []integrations.LogEntry{})
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ItemsExported)
	})

	t.Run("large payload", func(t *testing.T) {
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Create 10000 logs
		logs := make([]integrations.LogEntry, 10000)
		for i := 0; i < 10000; i++ {
			logs[i] = integrations.LogEntry{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-source",
			}
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, 10000, result.ItemsExported)
	})

	t.Run("special characters in log message", func(t *testing.T) {
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Log with special chars: \n\t\r\"'\\<>&{}[]",
				Source:    "test",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
	})

	t.Run("unicode in log message", func(t *testing.T) {
		slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Unicode message: Hello World",
				Source:    "test",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.NoError(t, err)
		assert.True(t, result.Success)
	})
}

// ============================================================================
// Not Initialized/Enabled Tests
// ============================================================================

func TestAlibabaNotInitializedOrEnabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export logs not initialized", func(t *testing.T) {
		config := integrations.AlibabaConfig{
			Enabled:         true,
			RegionID:        "cn-hangzhou",
			AccessKeyID:     "test-access-key",
			AccessKeySecret: "test-secret-key",
		}

		exporter := integrations.NewAlibabaExporter(config, logger)
		// Do NOT call Init()

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export logs not enabled", func(t *testing.T) {
		config := integrations.AlibabaConfig{
			Enabled:         false,
			RegionID:        "cn-hangzhou",
			AccessKeyID:     "test-access-key",
			AccessKeySecret: "test-secret-key",
		}

		exporter := integrations.NewAlibabaExporter(config, logger)

		logs := []integrations.LogEntry{
			{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotEnabled)
	})

	t.Run("export metrics not initialized", func(t *testing.T) {
		config := integrations.AlibabaConfig{
			Enabled:         true,
			RegionID:        "cn-hangzhou",
			AccessKeyID:     "test-access-key",
			AccessKeySecret: "test-secret-key",
		}

		exporter := integrations.NewAlibabaExporter(config, logger)

		metrics := []integrations.Metric{
			{Name: "test.metric", Value: 1.0, Type: integrations.MetricTypeGauge, Timestamp: time.Now()},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})

	t.Run("export traces not initialized", func(t *testing.T) {
		config := integrations.AlibabaConfig{
			Enabled:         true,
			RegionID:        "cn-hangzhou",
			AccessKeyID:     "test-access-key",
			AccessKeySecret: "test-secret-key",
		}

		exporter := integrations.NewAlibabaExporter(config, logger)

		traces := []integrations.Trace{
			{TraceID: "trace-1", SpanID: "span-1", OperationName: "test", StartTime: time.Now(), Duration: 100 * time.Millisecond},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, integrations.ErrNotInitialized)
	})
}

// ============================================================================
// Alibaba percentEncode Helper Function Tests
// ============================================================================

func TestAlibabaPercentEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "hello+world",
		},
		{
			name:     "string with special characters",
			input:    "test=value&key=123",
			expected: "test%3Dvalue%26key%3D123",
		},
		{
			name:     "string with unicode",
			input:    "测试",
			expected: "%E6%B5%8B%E8%AF%95",
		},
		{
			name:     "string with slashes",
			input:    "/api/v1/logs",
			expected: "%2Fapi%2Fv1%2Flogs",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "alphanumeric only",
			input:    "abc123XYZ",
			expected: "abc123XYZ",
		},
		{
			name:     "string with plus sign",
			input:    "a+b",
			expected: "a%2Bb",
		},
		{
			name:     "string with percent",
			input:    "100%",
			expected: "100%25",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := integrations.PercentEncode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Benchmark tests
// ============================================================================

func BenchmarkAlibabaExportLogs(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()

	slsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}

	exporter := integrations.NewAlibabaExporter(config, logger)
	_ = exporter.Init(ctx)

	logs := []integrations.LogEntry{
		{Timestamp: time.Now(), Level: integrations.LogLevelInfo, Message: "test"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportLogs(ctx, logs)
	}
}
