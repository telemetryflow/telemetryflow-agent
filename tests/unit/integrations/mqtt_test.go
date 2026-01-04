// package integrations_test provides unit tests for TelemetryFlow Agent integrations.
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

func TestNewMQTTExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		MetricsTopic: "telemetryflow/metrics",
		TracesTopic:  "telemetryflow/traces",
		LogsTopic:    "telemetryflow/logs",
	}

	exporter := integrations.NewMQTTExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "mqtt", exporter.Name())
	assert.Equal(t, "messaging", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestMQTTExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name        string
		config      integrations.MQTTConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.MQTTConfig{
				Enabled:      true,
				Broker:       "tcp://localhost:1883",
				MetricsTopic: "test/metrics",
			},
			expectError: false,
		},
		{
			name: "disabled config",
			config: integrations.MQTTConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing broker",
			config: integrations.MQTTConfig{
				Enabled:      true,
				MetricsTopic: "test/metrics",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewMQTTExporter(tt.config, logger)
			err := exporter.Init(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMQTTExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name        string
		config      integrations.MQTTConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: integrations.MQTTConfig{
				Enabled:      true,
				Broker:       "tcp://localhost:1883",
				MetricsTopic: "test/metrics",
			},
			expectError: false,
		},
		{
			name: "disabled always valid",
			config: integrations.MQTTConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "missing broker",
			config: integrations.MQTTConfig{
				Enabled:      true,
				MetricsTopic: "test/metrics",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := integrations.NewMQTTExporter(tt.config, logger)
			err := exporter.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMQTTExporterQoSDefault(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		MetricsTopic: "test/metrics",
	}

	exporter := integrations.NewMQTTExporter(config, logger)
	require.NotNil(t, exporter)
	// QoS defaults to 0 (At most once) which is valid
}

func TestMQTTExporterWithAuth(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		Username:     "testuser",
		Password:     "testpass",
		ClientID:     "test-client",
		MetricsTopic: "test/metrics",
		TracesTopic:  "test/traces",
		LogsTopic:    "test/logs",
		QoS:          1,
	}

	exporter := integrations.NewMQTTExporter(config, logger)
	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestMQTTExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		config := integrations.MQTTConfig{Enabled: false}
		exporter := integrations.NewMQTTExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("not initialized", func(t *testing.T) {
		config := integrations.MQTTConfig{
			Enabled:      true,
			Broker:       "tcp://localhost:1883",
			MetricsTopic: "test/metrics",
		}
		exporter := integrations.NewMQTTExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		assert.False(t, status.Healthy)
	})
}

func TestMQTTExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		MetricsTopic: "test/metrics",
	}

	exporter := integrations.NewMQTTExporter(config, logger)
	_ = exporter.Init(ctx)

	err := exporter.Close(ctx)
	assert.NoError(t, err)
}

func TestMQTTExporterExportMethods(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		MetricsTopic: "test/metrics",
		TracesTopic:  "test/traces",
		LogsTopic:    "test/logs",
	}

	exporter := integrations.NewMQTTExporter(config, logger)

	// Without init, exports should fail
	result, err := exporter.ExportMetrics(ctx, []integrations.Metric{})
	assert.Error(t, err)
	assert.Nil(t, result)

	result, err = exporter.ExportTraces(ctx, []integrations.Trace{})
	assert.Error(t, err)
	assert.Nil(t, result)

	result, err = exporter.ExportLogs(ctx, []integrations.LogEntry{})
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestMQTTConfigDefaults(t *testing.T) {
	config := integrations.MQTTConfig{}
	assert.False(t, config.Enabled)
	assert.Empty(t, config.Broker)
	assert.Equal(t, 0, config.QoS)
	assert.False(t, config.Retained)
}

func TestMQTTExporterWithTLS(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.MQTTConfig{
		Enabled:       true,
		Broker:        "ssl://localhost:8883",
		TLSEnabled:    true,
		TLSSkipVerify: true,
		MetricsTopic:  "test/metrics",
	}

	exporter := integrations.NewMQTTExporter(config, logger)
	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestMQTTExporterSupportedTypes(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		MetricsTopic: "test/metrics",
	}

	exporter := integrations.NewMQTTExporter(config, logger)
	types := exporter.SupportedDataTypes()

	assert.Contains(t, types, integrations.DataTypeMetrics)
	assert.Contains(t, types, integrations.DataTypeTraces)
	assert.Contains(t, types, integrations.DataTypeLogs)
}

func TestMQTTExporterWithKeepAlive(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		KeepAlive:    60 * time.Second,
		MetricsTopic: "test/metrics",
	}

	exporter := integrations.NewMQTTExporter(config, logger)
	require.NotNil(t, exporter)
}

// Benchmark tests
func BenchmarkNewMQTTExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.MQTTConfig{
		Enabled:      true,
		Broker:       "tcp://localhost:1883",
		MetricsTopic: "test/metrics",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewMQTTExporter(config, logger)
	}
}
