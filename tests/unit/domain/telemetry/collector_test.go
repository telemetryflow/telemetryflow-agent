// Package telemetry_test provides unit tests for the telemetry domain.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package telemetry_test

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

func TestMetricType(t *testing.T) {
	t.Run("should have correct metric type values", func(t *testing.T) {
		assert.Equal(t, collector.MetricType("gauge"), collector.MetricTypeGauge)
		assert.Equal(t, collector.MetricType("counter"), collector.MetricTypeCounter)
		assert.Equal(t, collector.MetricType("histogram"), collector.MetricTypeHistogram)
		assert.Equal(t, collector.MetricType("summary"), collector.MetricTypeSummary)
	})
}

func TestNewMetric(t *testing.T) {
	t.Run("should create metric with basic values", func(t *testing.T) {
		before := time.Now()
		m := collector.NewMetric("test.metric", 42.5, collector.MetricTypeGauge)
		after := time.Now()

		assert.Equal(t, "test.metric", m.Name)
		assert.Equal(t, 42.5, m.Value)
		assert.Equal(t, collector.MetricTypeGauge, m.Type)
		assert.NotNil(t, m.Labels)
		assert.Empty(t, m.Labels)
		assert.True(t, m.Timestamp.After(before) || m.Timestamp.Equal(before))
		assert.True(t, m.Timestamp.Before(after) || m.Timestamp.Equal(after))
	})

	t.Run("should create counter metric", func(t *testing.T) {
		m := collector.NewMetric("test.counter", 100, collector.MetricTypeCounter)
		assert.Equal(t, collector.MetricTypeCounter, m.Type)
	})

	t.Run("should create histogram metric", func(t *testing.T) {
		m := collector.NewMetric("test.histogram", 1.5, collector.MetricTypeHistogram)
		assert.Equal(t, collector.MetricTypeHistogram, m.Type)
	})

	t.Run("should create summary metric", func(t *testing.T) {
		m := collector.NewMetric("test.summary", 2.5, collector.MetricTypeSummary)
		assert.Equal(t, collector.MetricTypeSummary, m.Type)
	})
}

func TestMetricWithLabels(t *testing.T) {
	t.Run("should add labels to metric", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge)
		labels := map[string]string{
			"host": "server1",
			"env":  "prod",
		}
		m = m.WithLabels(labels)

		assert.Equal(t, "server1", m.Labels["host"])
		assert.Equal(t, "prod", m.Labels["env"])
	})

	t.Run("should merge labels", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge)
		m = m.WithLabels(map[string]string{"key1": "value1"})
		m = m.WithLabels(map[string]string{"key2": "value2"})

		assert.Equal(t, "value1", m.Labels["key1"])
		assert.Equal(t, "value2", m.Labels["key2"])
	})

	t.Run("should override existing labels", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge)
		m = m.WithLabels(map[string]string{"key": "old"})
		m = m.WithLabels(map[string]string{"key": "new"})

		assert.Equal(t, "new", m.Labels["key"])
	})
}

func TestMetricWithLabel(t *testing.T) {
	t.Run("should add single label", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge)
		m = m.WithLabel("key", "value")

		assert.Equal(t, "value", m.Labels["key"])
	})

	t.Run("should add multiple labels sequentially", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge)
		m = m.WithLabel("key1", "value1").WithLabel("key2", "value2")

		assert.Equal(t, "value1", m.Labels["key1"])
		assert.Equal(t, "value2", m.Labels["key2"])
	})

	t.Run("should handle nil labels map", func(t *testing.T) {
		m := collector.Metric{
			Name:  "test.metric",
			Value: 1.0,
			Type:  collector.MetricTypeGauge,
		}
		m = m.WithLabel("key", "value")

		assert.NotNil(t, m.Labels)
		assert.Equal(t, "value", m.Labels["key"])
	})
}

func TestMetricWithUnit(t *testing.T) {
	t.Run("should set unit", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge)
		m = m.WithUnit("bytes")

		assert.Equal(t, "bytes", m.Unit)
	})

	t.Run("should support various units", func(t *testing.T) {
		units := []string{"bytes", "percent", "seconds", "milliseconds", "bytes/s"}
		for _, unit := range units {
			m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge).WithUnit(unit)
			assert.Equal(t, unit, m.Unit)
		}
	})
}

func TestMetricWithDescription(t *testing.T) {
	t.Run("should set description", func(t *testing.T) {
		m := collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge)
		m = m.WithDescription("This is a test metric")

		assert.Equal(t, "This is a test metric", m.Description)
	})
}

func TestMetricChaining(t *testing.T) {
	t.Run("should support method chaining", func(t *testing.T) {
		m := collector.NewMetric("system.cpu.usage", 75.5, collector.MetricTypeGauge).
			WithUnit("percent").
			WithDescription("CPU usage percentage").
			WithLabel("host", "server1").
			WithLabels(map[string]string{"env": "prod", "region": "us-east"})

		assert.Equal(t, "system.cpu.usage", m.Name)
		assert.Equal(t, 75.5, m.Value)
		assert.Equal(t, collector.MetricTypeGauge, m.Type)
		assert.Equal(t, "percent", m.Unit)
		assert.Equal(t, "CPU usage percentage", m.Description)
		assert.Equal(t, "server1", m.Labels["host"])
		assert.Equal(t, "prod", m.Labels["env"])
		assert.Equal(t, "us-east", m.Labels["region"])
	})
}

func TestMetricBatch(t *testing.T) {
	t.Run("should create metric batch", func(t *testing.T) {
		metrics := []collector.Metric{
			collector.NewMetric("metric1", 1.0, collector.MetricTypeGauge),
			collector.NewMetric("metric2", 2.0, collector.MetricTypeCounter),
		}

		batch := collector.MetricBatch{
			Metrics:     metrics,
			CollectedAt: time.Now(),
			AgentID:     "agent-1",
			Hostname:    "server1",
		}

		assert.Len(t, batch.Metrics, 2)
		assert.Equal(t, "agent-1", batch.AgentID)
		assert.Equal(t, "server1", batch.Hostname)
		assert.False(t, batch.CollectedAt.IsZero())
	})
}

func TestSystemInfo(t *testing.T) {
	t.Run("should hold system information", func(t *testing.T) {
		info := collector.SystemInfo{
			Hostname:         "test-host",
			OS:               "linux",
			OSVersion:        "Ubuntu 22.04",
			KernelVersion:    "5.15.0",
			Architecture:     "x86_64",
			Uptime:           86400,
			CPUCores:         8,
			CPUModel:         "Intel Core i7",
			CPUUsage:         25.5,
			MemoryTotal:      16000000000,
			MemoryUsed:       8000000000,
			MemoryAvailable:  8000000000,
			MemoryUsage:      50.0,
			DiskTotal:        500000000000,
			DiskUsed:         250000000000,
			DiskAvailable:    250000000000,
			DiskUsage:        50.0,
			NetworkBytesSent: 1000000,
			NetworkBytesRecv: 2000000,
		}

		assert.Equal(t, "test-host", info.Hostname)
		assert.Equal(t, "linux", info.OS)
		assert.Equal(t, "Ubuntu 22.04", info.OSVersion)
		assert.Equal(t, "5.15.0", info.KernelVersion)
		assert.Equal(t, "x86_64", info.Architecture)
		assert.Equal(t, uint64(86400), info.Uptime)
		assert.Equal(t, 8, info.CPUCores)
		assert.Equal(t, "Intel Core i7", info.CPUModel)
		assert.Equal(t, 25.5, info.CPUUsage)
		assert.Equal(t, uint64(16000000000), info.MemoryTotal)
		assert.Equal(t, 50.0, info.MemoryUsage)
		assert.Equal(t, uint64(500000000000), info.DiskTotal)
		assert.Equal(t, 50.0, info.DiskUsage)
		assert.Equal(t, uint64(1000000), info.NetworkBytesSent)
		assert.Equal(t, uint64(2000000), info.NetworkBytesRecv)
	})
}

func TestMetricStruct(t *testing.T) {
	t.Run("should have all required fields", func(t *testing.T) {
		m := collector.Metric{
			Name:        "test.metric",
			Description: "A test metric",
			Type:        collector.MetricTypeGauge,
			Value:       42.0,
			Timestamp:   time.Now(),
			Labels:      map[string]string{"key": "value"},
			Unit:        "count",
		}

		assert.Equal(t, "test.metric", m.Name)
		assert.Equal(t, "A test metric", m.Description)
		assert.Equal(t, collector.MetricTypeGauge, m.Type)
		assert.Equal(t, 42.0, m.Value)
		assert.NotEmpty(t, m.Timestamp)
		assert.Equal(t, "value", m.Labels["key"])
		assert.Equal(t, "count", m.Unit)
	})

	t.Run("should support zero values", func(t *testing.T) {
		m := collector.Metric{
			Name:  "test.zero",
			Type:  collector.MetricTypeGauge,
			Value: 0.0,
		}

		assert.Equal(t, "test.zero", m.Name)
		assert.Equal(t, 0.0, m.Value)
		assert.Empty(t, m.Description)
		assert.Empty(t, m.Unit)
		assert.Nil(t, m.Labels)
	})

	t.Run("should support negative values", func(t *testing.T) {
		m := collector.NewMetric("test.negative", -10.5, collector.MetricTypeGauge)
		assert.Equal(t, -10.5, m.Value)
	})

	t.Run("should support large values", func(t *testing.T) {
		m := collector.NewMetric("test.large", 1e15, collector.MetricTypeCounter)
		assert.Equal(t, 1e15, m.Value)
	})
}
