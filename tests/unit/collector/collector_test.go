package collector_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

func TestSystemCollector(t *testing.T) {
	t.Run("should create system collector", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		cfg := system.HostCollectorConfig{
			Interval:    15 * time.Second,
			CollectCPU:  true,
			CollectMem:  true,
			CollectDisk: true,
			CollectNet:  true,
			Logger:      logger,
		}

		c := system.NewHostCollector(cfg)
		require.NotNil(t, c)
		assert.Equal(t, "system.host", c.Name())
		assert.False(t, c.IsRunning())
	})

	t.Run("should collect metrics", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		cfg := system.HostCollectorConfig{
			Interval:   time.Second,
			CollectCPU: true,
			CollectMem: true,
			Logger:     logger,
		}

		c := system.NewHostCollector(cfg)
		ctx := context.Background()

		metrics, err := c.Collect(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, metrics)

		// Check for expected metric types
		var cpuFound, memFound bool
		for _, m := range metrics {
			if m.Name == "system.cpu.usage" {
				cpuFound = true
				assert.Equal(t, collector.MetricTypeGauge, m.Type)
				assert.Equal(t, "percent", m.Unit)
			}
			if m.Name == "system.memory.total" {
				memFound = true
				assert.Equal(t, collector.MetricTypeGauge, m.Type)
				assert.Equal(t, "bytes", m.Unit)
			}
		}
		assert.True(t, cpuFound, "CPU metric not found")
		assert.True(t, memFound, "Memory metric not found")
	})
}

func TestMetric(t *testing.T) {
	t.Run("should create metric with defaults", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 42.0, collector.MetricTypeGauge)

		assert.Equal(t, "test.metric", m.Name)
		assert.Equal(t, 42.0, m.Value)
		assert.Equal(t, collector.MetricTypeGauge, m.Type)
		assert.NotZero(t, m.Timestamp)
		assert.NotNil(t, m.Labels)
	})

	t.Run("should add labels", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 42.0, collector.MetricTypeGauge).
			WithLabel("host", "test-host").
			WithLabels(map[string]string{"env": "test"})

		assert.Equal(t, "test-host", m.Labels["host"])
		assert.Equal(t, "test", m.Labels["env"])
	})

	t.Run("should set unit and description", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 42.0, collector.MetricTypeGauge).
			WithUnit("bytes").
			WithDescription("Test metric")

		assert.Equal(t, "bytes", m.Unit)
		assert.Equal(t, "Test metric", m.Description)
	})
}
