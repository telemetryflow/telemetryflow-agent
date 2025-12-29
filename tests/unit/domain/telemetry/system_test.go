// Package telemetry_test provides unit tests for the system metrics collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package telemetry_test

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
)

func TestNewHostCollector(t *testing.T) {
	t.Run("should create collector with default values", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{})
		assert.NotNil(t, c)
		assert.Equal(t, "system.host", c.Name())
	})

	t.Run("should use provided interval", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			Interval: 30 * time.Second,
		})
		assert.NotNil(t, c)
	})

	t.Run("should use provided logger", func(t *testing.T) {
		logger := zap.NewNop()
		c := system.NewHostCollector(system.HostCollectorConfig{
			Logger: logger,
		})
		assert.NotNil(t, c)
	})

	t.Run("should set collection flags", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectCPU:  true,
			CollectMem:  true,
			CollectDisk: true,
			CollectNet:  true,
		})
		assert.NotNil(t, c)
	})
}

func TestHostCollectorName(t *testing.T) {
	c := system.NewHostCollector(system.HostCollectorConfig{})
	assert.Equal(t, "system.host", c.Name())
}

func TestHostCollectorIsRunning(t *testing.T) {
	t.Run("should return false when not started", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{})
		assert.False(t, c.IsRunning())
	})
}

func TestHostCollectorStartStop(t *testing.T) {
	t.Run("should start and stop correctly", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			Interval:   50 * time.Millisecond,
			CollectCPU: true,
			CollectMem: true,
			Logger:     zap.NewNop(),
		})

		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Start(ctx)
		}()

		time.Sleep(100 * time.Millisecond)
		assert.True(t, c.IsRunning())

		err := c.Stop()
		assert.NoError(t, err)
		cancel()

		wg.Wait()
		assert.False(t, c.IsRunning())
	})

	t.Run("should handle stop when not running", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{})
		err := c.Stop()
		assert.NoError(t, err)
	})
}

func TestHostCollectorCollect(t *testing.T) {
	t.Run("should collect CPU metrics", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectCPU: true,
			Logger:     zap.NewNop(),
		})

		ctx := context.Background()
		metrics, err := c.Collect(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, metrics)

		var hasCPUUsage, hasCPUCores bool
		for _, m := range metrics {
			if m.Name == "system.cpu.usage" {
				hasCPUUsage = true
				assert.Equal(t, collector.MetricTypeGauge, m.Type)
				assert.Equal(t, "percent", m.Unit)
			}
			if m.Name == "system.cpu.cores" {
				hasCPUCores = true
				assert.Equal(t, collector.MetricTypeGauge, m.Type)
			}
		}
		assert.True(t, hasCPUUsage, "should have CPU usage metric")
		assert.True(t, hasCPUCores, "should have CPU cores metric")
	})

	t.Run("should collect memory metrics", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectMem: true,
			Logger:     zap.NewNop(),
		})

		ctx := context.Background()
		metrics, err := c.Collect(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, metrics)

		expectedMetrics := []string{
			"system.memory.total",
			"system.memory.used",
			"system.memory.available",
			"system.memory.usage",
		}

		for _, expected := range expectedMetrics {
			found := false
			for _, m := range metrics {
				if m.Name == expected {
					found = true
					break
				}
			}
			assert.True(t, found, "should have metric: %s", expected)
		}
	})

	t.Run("should collect disk metrics", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectDisk: true,
			Logger:      zap.NewNop(),
		})

		ctx := context.Background()
		metrics, err := c.Collect(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, metrics)

		var hasDiskUsage bool
		for _, m := range metrics {
			if m.Name == "system.disk.usage" {
				hasDiskUsage = true
				assert.Equal(t, collector.MetricTypeGauge, m.Type)
			}
		}
		assert.True(t, hasDiskUsage, "should have disk usage metric")
	})

	t.Run("should collect network metrics", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectNet: true,
			Logger:     zap.NewNop(),
		})

		ctx := context.Background()
		metrics, err := c.Collect(ctx)
		assert.NoError(t, err)

		// Network metrics may be empty on some systems (e.g., containers without network interfaces)
		// Log the count and skip the detailed assertion if none are returned
		if len(metrics) == 0 {
			t.Skip("No network interfaces available on this system")
		}

		expectedMetrics := []string{
			"system.network.bytes_sent",
			"system.network.bytes_recv",
		}

		for _, expected := range expectedMetrics {
			found := false
			for _, m := range metrics {
				if m.Name == expected {
					found = true
					break
				}
			}
			assert.True(t, found, "should have metric: %s", expected)
		}
	})

	t.Run("should collect all metrics when all flags enabled", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectCPU:  true,
			CollectMem:  true,
			CollectDisk: true,
			CollectNet:  true,
			Logger:      zap.NewNop(),
		})

		ctx := context.Background()
		metrics, err := c.Collect(ctx)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(metrics), 10)
	})

	t.Run("should collect no metrics when all flags disabled", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectCPU:  false,
			CollectMem:  false,
			CollectDisk: false,
			CollectNet:  false,
			Logger:      zap.NewNop(),
		})

		ctx := context.Background()
		metrics, err := c.Collect(ctx)
		assert.NoError(t, err)
		assert.Empty(t, metrics)
	})
}

func TestHostCollectorGetSystemInfo(t *testing.T) {
	t.Run("should return system info", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			Logger: zap.NewNop(),
		})

		info, err := c.GetSystemInfo()
		require.NoError(t, err)
		require.NotNil(t, info)

		// These fields are always available
		assert.Greater(t, info.CPUCores, 0)
		assert.Greater(t, info.MemoryTotal, uint64(0))

		// These fields depend on OS capabilities and may be empty on some systems
		// Log them for debugging but don't fail if empty
		t.Logf("Hostname: %s, OS: %s, Architecture: %s", info.Hostname, info.OS, info.Architecture)
	})

	t.Run("should return consistent static values", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			Logger: zap.NewNop(),
		})

		info1, err := c.GetSystemInfo()
		require.NoError(t, err)

		info2, err := c.GetSystemInfo()
		require.NoError(t, err)

		assert.Equal(t, info1.Hostname, info2.Hostname)
		assert.Equal(t, info1.OS, info2.OS)
		assert.Equal(t, info1.Architecture, info2.Architecture)
		assert.Equal(t, info1.CPUCores, info2.CPUCores)
		assert.Equal(t, info1.MemoryTotal, info2.MemoryTotal)
	})
}

func TestGetSystemInfoStatic(t *testing.T) {
	t.Run("should return system info without collector", func(t *testing.T) {
		info, err := system.GetSystemInfoStatic()
		require.NoError(t, err)
		require.NotNil(t, info)

		// These fields are always available
		assert.Greater(t, info.CPUCores, 0)

		// These fields depend on OS capabilities and may be empty on some systems
		// Log them for debugging but don't fail if empty
		t.Logf("Hostname: %s, OS: %s", info.Hostname, info.OS)
	})
}

func TestHostCollectorConfig(t *testing.T) {
	t.Run("should use default disk paths based on OS", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectDisk: true,
			Logger:      zap.NewNop(),
		})

		ctx := context.Background()
		metrics, err := c.Collect(ctx)
		assert.NoError(t, err)

		var foundDiskMetric bool
		for _, m := range metrics {
			if m.Name == "system.disk.total" {
				foundDiskMetric = true
				path := m.Labels["path"]
				if runtime.GOOS == "windows" {
					assert.Equal(t, "C:", path)
				} else {
					assert.Equal(t, "/", path)
				}
				break
			}
		}
		assert.True(t, foundDiskMetric)
	})
}

func TestHostCollectorConcurrency(t *testing.T) {
	t.Run("should handle concurrent collections", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			CollectCPU: true,
			CollectMem: true,
			Logger:     zap.NewNop(),
		})

		ctx := context.Background()
		var wg sync.WaitGroup

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				metrics, err := c.Collect(ctx)
				assert.NoError(t, err)
				assert.NotEmpty(t, metrics)
			}()
		}

		wg.Wait()
	})
}

func TestHostCollectorContextCancellation(t *testing.T) {
	t.Run("should stop on context cancellation", func(t *testing.T) {
		c := system.NewHostCollector(system.HostCollectorConfig{
			Interval:   100 * time.Millisecond,
			CollectCPU: true,
			Logger:     zap.NewNop(),
		})

		ctx, cancel := context.WithCancel(context.Background())

		errChan := make(chan error, 1)
		go func() {
			errChan <- c.Start(ctx)
		}()

		time.Sleep(50 * time.Millisecond)
		assert.True(t, c.IsRunning())

		cancel()

		err := <-errChan
		assert.ErrorIs(t, err, context.Canceled)
	})
}
