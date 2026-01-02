// package integrations_test provides unit tests for TelemetryFlow Agent SNMP exporter.
package integrations_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// SNMP Exporter Tests
func TestNewSNMPExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.SNMPConfig{
		Enabled: true,
		Targets: []integrations.SNMPTarget{
			{Address: "192.168.1.1"},
		},
		Port:      161,
		Community: "public",
		Version:   "2c",
	}

	exporter := integrations.NewSNMPExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "snmp", exporter.Name())
	assert.Equal(t, "network", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestSNMPExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.SNMPConfig
		expectError bool
	}{
		{
			name: "valid config v2c",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Port:      161,
				Community: "public",
				Version:   "2c",
			},
			expectError: false,
		},
		{
			name: "valid config v3",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Port:         161,
				Version:      "3",
				Username:     "admin",
				AuthProtocol: "SHA",
				AuthPassword: "authpass",
				PrivProtocol: "AES",
				PrivPassword: "privpass",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.SNMPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing targets",
			config: integrations.SNMPConfig{
				Enabled:   true,
				Community: "public",
				Version:   "2c",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSNMPExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.SNMPConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.SNMPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing targets",
			config: integrations.SNMPConfig{
				Enabled:   true,
				Community: "public",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSNMPExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		config := integrations.SNMPConfig{Enabled: false}
		exporter := integrations.NewSNMPExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("successful health check - all targets reachable", func(t *testing.T) {
		// Use localhost which is always reachable via UDP
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "localhost"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Contains(t, status.Message, "/1 targets reachable")
		assert.NotZero(t, status.Latency)
		assert.NotNil(t, status.Details)
		assert.Equal(t, "2c", status.Details["version"])
		assert.Equal(t, 1, status.Details["total_targets"])
		assert.Equal(t, 1, status.Details["reachable_targets"])
	})

	t.Run("health check with multiple targets - partial reachability", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "reachable"},
				{Address: "192.0.2.1", Port: 161, Name: "unreachable"}, // TEST-NET-1, not routable
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		// Should be healthy if at least one target is reachable
		assert.True(t, status.Healthy)
		assert.Equal(t, 2, status.Details["total_targets"])
		// At least one should be reachable
		reachable := status.Details["reachable_targets"].(int)
		assert.GreaterOrEqual(t, reachable, 1)
	})

	t.Run("health check with no reachable targets", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "192.0.2.1", Port: 9999, Name: "unreachable1"}, // TEST-NET-1
				{Address: "192.0.2.2", Port: 9999, Name: "unreachable2"},
			},
			Port:      9999,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		// May report unhealthy if no targets are reachable (depends on UDP behavior)
		assert.Contains(t, status.Message, "targets reachable")
	})

	t.Run("health check with custom port per target", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "custom-port"},
				{Address: "127.0.0.1", Port: 162, Name: "trap-port"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.NotZero(t, status.Latency)
	})

	t.Run("health check with SNMPv3", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "v3-device"},
			},
			Port:          161,
			Version:       "3",
			Username:      "admin",
			SecurityLevel: "authPriv",
			AuthProtocol:  "SHA",
			AuthPassword:  "authpassword",
			PrivProtocol:  "AES",
			PrivPassword:  "privpassword",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.Equal(t, "3", status.Details["version"])
	})

	t.Run("health check measures latency", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "latency-test"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
		assert.NotZero(t, status.Latency)
		assert.NotZero(t, status.LastCheck)
	})

	t.Run("health check with default port fallback", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Name: "no-port"}, // Port = 0, should use config.Port
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.True(t, status.Healthy)
	})
}

func TestSNMPExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.SNMPConfig{
		Enabled: true,
		Targets: []integrations.SNMPTarget{
			{Address: "192.168.1.1"},
		},
		Community: "public",
		Version:   "2c",
	}

	exporter := integrations.NewSNMPExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

// Test SNMP config defaults
func TestSNMPConfigDefaults(t *testing.T) {
	config := integrations.SNMPConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.Targets)
	assert.Equal(t, 0, config.Port)
}

// SNMP Exporter CollectMetrics and Export Tests
func TestSNMPExporterCollectMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("collect metrics with valid target", func(t *testing.T) {
		// SNMP uses UDP, not HTTP. We test with localhost which is always reachable
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{
					Address: "127.0.0.1",
					Port:    161,
					Name:    "localhost",
				},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify target up metric exists
		var foundUpMetric bool
		for _, m := range metrics {
			if m.Name == "snmp_target_up" {
				foundUpMetric = true
				assert.Equal(t, "127.0.0.1", m.Tags["target"])
				assert.Equal(t, "localhost", m.Tags["target_name"])
				assert.Equal(t, "2c", m.Tags["snmp_version"])
			}
		}
		assert.True(t, foundUpMetric, "Expected snmp_target_up metric")
	})

	t.Run("collect metrics with multiple targets", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "target1"},
				{Address: "127.0.0.1", Port: 162, Name: "target2"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify we have metrics for each target
		targetMetrics := make(map[string]bool)
		for _, m := range metrics {
			if m.Name == "snmp_target_up" {
				targetMetrics[m.Tags["target_name"]] = true
			}
		}
		assert.True(t, targetMetrics["target1"], "Expected metrics for target1")
		assert.True(t, targetMetrics["target2"], "Expected metrics for target2")
	})

	t.Run("collect metrics with custom labels", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{
					Address: "127.0.0.1",
					Port:    161,
					Name:    "test-device",
					Labels: map[string]string{
						"location": "rack-a1",
					},
				},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
			Labels: map[string]string{
				"environment": "test",
				"team":        "network",
			},
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify labels are applied
		for _, m := range metrics {
			assert.Equal(t, "test", m.Tags["environment"])
			assert.Equal(t, "network", m.Tags["team"])
			if m.Tags["target_name"] == "test-device" {
				assert.Equal(t, "rack-a1", m.Tags["location"])
			}
		}
	})

	t.Run("collect metrics disabled returns error", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: false,
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		_ = exporter.Init(ctx)

		metrics, err := exporter.CollectMetrics(ctx)
		assert.Error(t, err)
		assert.Nil(t, metrics)
	})

	t.Run("collect metrics uninitialized returns error", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "192.168.1.1"},
			},
			Community: "public",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		// Don't call Init

		metrics, err := exporter.CollectMetrics(ctx)
		assert.Error(t, err)
		assert.Nil(t, metrics)
	})

	t.Run("collect metrics with SNMPv3", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Name: "v3-device"},
			},
			Port:          161,
			Version:       "3",
			Username:      "admin",
			SecurityLevel: "authPriv",
			AuthProtocol:  "SHA",
			AuthPassword:  "authpassword",
			PrivProtocol:  "AES",
			PrivPassword:  "privpassword",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		metrics, err := exporter.CollectMetrics(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Verify v3 version tag
		for _, m := range metrics {
			if m.Name == "snmp_target_up" {
				assert.Equal(t, "3", m.Tags["snmp_version"])
			}
		}
	})
}

func TestSNMPExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export success", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "test-device"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{},
		}

		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Greater(t, result.ItemsExported, 0)
		assert.NotEmpty(t, data.Metrics)
	})

	t.Run("export disabled returns error", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: false,
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		_ = exporter.Init(ctx)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("export appends to existing metrics", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "test-device"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		// Pre-populate with existing metrics
		existingMetric := integrations.Metric{
			Name:  "pre_existing_metric",
			Value: 42,
		}
		data := &integrations.TelemetryData{
			Metrics: []integrations.Metric{existingMetric},
		}

		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.True(t, result.Success)

		// Verify existing metric is preserved
		assert.Equal(t, "pre_existing_metric", data.Metrics[0].Name)
		assert.Equal(t, 42.0, data.Metrics[0].Value)
		// Verify new metrics were added
		assert.Greater(t, len(data.Metrics), 1)
	})

	t.Run("export with multiple targets", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "device1"},
				{Address: "127.0.0.1", Port: 162, Name: "device2"},
				{Address: "127.0.0.1", Port: 163, Name: "device3"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)
		assert.True(t, result.Success)
		assert.Greater(t, result.ItemsExported, 0)

		// Count unique targets in metrics
		targets := make(map[string]bool)
		for _, m := range data.Metrics {
			if name, ok := m.Tags["target_name"]; ok {
				targets[name] = true
			}
		}
		assert.Len(t, targets, 3)
	})

	t.Run("export result contains correct items count", func(t *testing.T) {
		config := integrations.SNMPConfig{
			Enabled: true,
			Targets: []integrations.SNMPTarget{
				{Address: "127.0.0.1", Port: 161, Name: "test-device"},
			},
			Port:      161,
			Community: "public",
			Version:   "2c",
		}

		exporter := integrations.NewSNMPExporter(config, logger)
		err := exporter.Init(ctx)
		require.NoError(t, err)

		data := &integrations.TelemetryData{}
		result, err := exporter.Export(ctx, data)
		require.NoError(t, err)

		// ItemsExported should match the number of metrics added
		assert.Equal(t, len(data.Metrics), result.ItemsExported)
	})
}

// Benchmark tests
func BenchmarkNewSNMPExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.SNMPConfig{
		Enabled: true,
		Targets: []integrations.SNMPTarget{
			{Address: "192.168.1.1"},
		},
		Community: "public",
		Version:   "2c",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewSNMPExporter(config, logger)
	}
}

// TestSNMPExporterExportMetrics tests the ExportMetrics function
// SNMP is a data source, not a metrics destination, so ExportMetrics should return an error
func TestSNMPExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name    string
		config  integrations.SNMPConfig
		metrics []integrations.Metric
	}{
		{
			name: "export metrics returns error - snmp is a data source",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			metrics: []integrations.Metric{
				{
					Name:  "test_metric",
					Value: 42.0,
					Type:  integrations.MetricTypeGauge,
					Tags:  map[string]string{"test": "true"},
				},
			},
		},
		{
			name: "export metrics with empty slice returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			metrics: []integrations.Metric{},
		},
		{
			name: "export metrics with nil slice returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			metrics: nil,
		},
		{
			name: "export metrics with multiple metrics returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			metrics: []integrations.Metric{
				{Name: "metric1", Value: 1.0, Type: integrations.MetricTypeGauge},
				{Name: "metric2", Value: 2.0, Type: integrations.MetricTypeCounter},
				{Name: "metric3", Value: 3.0, Type: integrations.MetricTypeHistogram},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)

			result, err := exporter.ExportMetrics(ctx, tt.metrics)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "snmp is a data source, not a metrics destination")
		})
	}
}

// TestSNMPExporterExportTraces tests the ExportTraces function
// SNMP does not support traces, so ExportTraces should return an error
func TestSNMPExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.SNMPConfig
		traces []integrations.Trace
	}{
		{
			name: "export traces returns error - snmp does not support traces",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			traces: []integrations.Trace{
				{
					TraceID:       "trace-123",
					SpanID:        "span-456",
					OperationName: "test-trace",
				},
			},
		},
		{
			name: "export traces with empty slice returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			traces: []integrations.Trace{},
		},
		{
			name: "export traces with nil slice returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			traces: nil,
		},
		{
			name: "export traces with multiple traces returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			traces: []integrations.Trace{
				{TraceID: "trace-1", SpanID: "span-1", OperationName: "trace1"},
				{TraceID: "trace-2", SpanID: "span-2", OperationName: "trace2"},
				{TraceID: "trace-3", SpanID: "span-3", OperationName: "trace3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)

			result, err := exporter.ExportTraces(ctx, tt.traces)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "snmp does not support traces")
		})
	}
}

// TestSNMPExporterExportLogs tests the ExportLogs function
// SNMP does not support log ingestion, so ExportLogs should return an error
func TestSNMPExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name   string
		config integrations.SNMPConfig
		logs   []integrations.LogEntry
	}{
		{
			name: "export logs returns error - snmp does not support log ingestion",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			logs: []integrations.LogEntry{
				{
					Message:    "test log message",
					Level:      integrations.LogLevelInfo,
					Attributes: map[string]string{"service": "test"},
				},
			},
		},
		{
			name: "export logs with empty slice returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			logs: []integrations.LogEntry{},
		},
		{
			name: "export logs with nil slice returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			logs: nil,
		},
		{
			name: "export logs with multiple logs returns error",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
			},
			logs: []integrations.LogEntry{
				{Message: "log1", Level: "info"},
				{Message: "log2", Level: "warn"},
				{Message: "log3", Level: "error"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)

			result, err := exporter.ExportLogs(ctx, tt.logs)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "snmp does not support log ingestion")
		})
	}
}

// TestSNMPExporterValidateComprehensive provides comprehensive validation tests
func TestSNMPExporterValidateComprehensive(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.SNMPConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid v2c config",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1", Port: 161},
				},
				Community: "public",
				Version:   "2c",
			},
			expectError: false,
		},
		{
			name: "valid v3 config with authPriv",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Version:       "3",
				Username:      "admin",
				SecurityLevel: "authPriv",
				AuthProtocol:  "SHA",
				AuthPassword:  "authpassword",
				PrivProtocol:  "AES",
				PrivPassword:  "privpassword",
			},
			expectError: false,
		},
		{
			name: "valid v3 config with authNoPriv",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Version:       "3",
				Username:      "admin",
				SecurityLevel: "authNoPriv",
				AuthProtocol:  "MD5",
				AuthPassword:  "authpassword",
			},
			expectError: false,
		},
		{
			name: "valid v3 config with noAuthNoPriv",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Version:       "3",
				Username:      "admin",
				SecurityLevel: "noAuthNoPriv",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.SNMPConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing targets when enabled",
			config: integrations.SNMPConfig{
				Enabled:   true,
				Community: "public",
				Version:   "2c",
			},
			expectError: true,
			errorMsg:    "targets",
		},
		{
			name: "empty targets array when enabled",
			config: integrations.SNMPConfig{
				Enabled:   true,
				Targets:   []integrations.SNMPTarget{},
				Community: "public",
				Version:   "2c",
			},
			expectError: true,
			errorMsg:    "targets",
		},
		{
			name: "valid config with multiple targets",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1", Port: 161, Name: "switch1"},
					{Address: "192.168.1.2", Port: 161, Name: "switch2"},
					{Address: "192.168.1.3", Port: 161, Name: "router1"},
				},
				Port:      161,
				Community: "public",
				Version:   "2c",
			},
			expectError: false,
		},
		{
			name: "valid config with OIDs",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
				GetOIDs: []integrations.SNMPOIDConfig{
					{OID: ".1.3.6.1.2.1.1.1.0", Name: "sysDescr"},
					{OID: ".1.3.6.1.2.1.1.3.0", Name: "sysUpTime"},
				},
			},
			expectError: false,
		},
		{
			name: "valid config with custom labels",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "2c",
				Labels: map[string]string{
					"environment": "production",
					"datacenter":  "dc1",
				},
			},
			expectError: false,
		},
		{
			name: "valid v1 config",
			config: integrations.SNMPConfig{
				Enabled: true,
				Targets: []integrations.SNMPTarget{
					{Address: "192.168.1.1"},
				},
				Community: "public",
				Version:   "1",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewSNMPExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
