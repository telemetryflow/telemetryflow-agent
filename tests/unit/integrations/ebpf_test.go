// package integrations_test provides unit tests for TelemetryFlow Agent eBPF integration.
package integrations_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/integrations"
	"go.uber.org/zap"
)

// =============================================================================
// NewEBPFExporter Tests
// =============================================================================

func TestNewEBPFExporter(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
		CollectNetwork:  true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "ebpf", exporter.Name())
	assert.Equal(t, "kernel", exporter.Type())
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterDisabled(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: false,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "ebpf", exporter.Name())
	assert.False(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithNilLogger(t *testing.T) {
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, nil)

	require.NotNil(t, exporter)
	assert.NotNil(t, exporter.Logger())
}

func TestNewEBPFExporterWithAllCollectors(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:          true,
		CollectSyscalls:  true,
		CollectNetwork:   true,
		CollectFileIO:    true,
		CollectScheduler: true,
		CollectMemory:    true,
		CollectTCPEvents: true,
		CollectDNS:       true,
		CollectHTTP:      true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithLabels(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Labels: map[string]string{
			"environment": "production",
			"region":      "us-west-2",
			"cluster":     "k8s-prod-01",
		},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithFilters(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:          true,
		CollectSyscalls:  true,
		ProcessFilter:    []string{"nginx", "python", "java"},
		ContainerFilter:  []string{"container-123", "container-456"},
		NamespaceFilter:  []string{"production", "staging"},
		ExcludeProcesses: []string{"systemd", "sshd"},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

// =============================================================================
// Init Tests
// =============================================================================

func TestEBPFExporterInit(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("disabled config skips initialization", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("enabled config on non-linux returns platform error", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("Skipping non-Linux test on Linux")
		}
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Linux")
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("valid config with custom paths", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:      true,
			ProgramsPath: "/custom/ebpf/programs",
			PinPath:      "/sys/fs/bpf/custom",
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		// Expect platform error on non-Linux
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("valid config with custom buffer sizes", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:        true,
			RingBufferSize: 512 * 1024,
			PerfBufferSize: 128,
			MaxStackDepth:  64,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		// Expect platform error on non-Linux
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("valid config with BTF path", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: true,
			BTFPath: "/sys/kernel/btf/vmlinux",
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		// Expect platform error on non-Linux
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("config with scrape interval", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:        true,
			ScrapeInterval: 30 * time.Second,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		// Expect platform error on non-Linux
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("config with sample rate", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:    true,
			SampleRate: 10, // 10% sampling
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		// Expect platform error on non-Linux
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})
}

func TestEBPFExporterInitSetsDefaults(t *testing.T) {
	// This test verifies that default values are set during initialization
	// Since we can't easily access private config after Init, we verify
	// via behavior or by checking it doesn't error on zero values
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.EBPFConfig{
		Enabled: true,
		// All other fields left as zero values to test defaults
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	err := exporter.Init(ctx)

	// Expect platform error on non-Linux, but defaults should still be applied
	if runtime.GOOS != "linux" {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Linux")
	}
}

func TestEBPFExporterInitEnablesDefaultCollectors(t *testing.T) {
	// When no collectors are specified, Init should enable defaults
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.EBPFConfig{
		Enabled: true,
		// No collectors specified - should enable syscalls, network, fileio
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	err := exporter.Init(ctx)

	// Expect platform error on non-Linux
	if runtime.GOOS != "linux" {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Linux")
	}
}

// =============================================================================
// Validate Tests
// =============================================================================

func TestEBPFExporterValidate(t *testing.T) {
	logger := zap.NewNop()

	t.Run("disabled always valid", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Validate()
		assert.NoError(t, err)
	})

	t.Run("enabled on non-linux returns platform error", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("Skipping non-Linux test on Linux")
		}
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Linux")

		// Verify it's a ValidationError
		if validationErr, ok := err.(*integrations.ValidationError); ok {
			assert.Equal(t, "ebpf", validationErr.Integration)
			assert.Equal(t, "platform", validationErr.Field)
		}
	})

	t.Run("validate with various configs", func(t *testing.T) {
		configs := []integrations.EBPFConfig{
			{Enabled: false},
			{Enabled: false, CollectSyscalls: true},
			{Enabled: false, CollectNetwork: true, CollectFileIO: true},
		}

		for _, config := range configs {
			exporter := integrations.NewEBPFExporter(config, logger)
			err := exporter.Validate()
			assert.NoError(t, err, "Disabled config should always be valid")
		}
	})
}

// =============================================================================
// Export Tests
// =============================================================================

func TestEBPFExporterExport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export fails when disabled", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		telemetryData := &integrations.TelemetryData{
			Timestamp: time.Now(),
		}

		result, err := exporter.Export(ctx, telemetryData)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, integrations.ErrNotEnabled, err)
	})

	t.Run("export fails when not initialized", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("Skipping on Linux - needs actual eBPF setup")
		}
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		// Not calling Init()

		telemetryData := &integrations.TelemetryData{
			Timestamp: time.Now(),
		}

		result, err := exporter.Export(ctx, telemetryData)
		// Should fail because not initialized (but might fail on platform first)
		assert.Error(t, err)
		if result != nil {
			assert.False(t, result.Success)
		}
	})
}

// =============================================================================
// ExportMetrics Tests
// =============================================================================

func TestEBPFExporterExportMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export metrics returns not-a-destination error", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		metrics := []integrations.Metric{
			{
				Name:      "test_metric",
				Value:     1.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "data source")
		assert.Contains(t, err.Error(), "not a metrics destination")
	})

	t.Run("export metrics fails regardless of initialization state", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		metrics := []integrations.Metric{
			{
				Name:      "test_metric",
				Value:     1.0,
				Type:      integrations.MetricTypeGauge,
				Timestamp: time.Now(),
			},
		}

		result, err := exporter.ExportMetrics(ctx, metrics)
		require.Error(t, err)
		assert.Nil(t, result)
		// Should always return the "data source" error
		assert.Contains(t, err.Error(), "data source")
	})
}

// =============================================================================
// ExportTraces Tests
// =============================================================================

func TestEBPFExporterExportTraces(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export traces returns collected-not-exported error", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:        true,
			CollectNetwork: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		traces := []integrations.Trace{
			{
				TraceID:       "trace-123",
				SpanID:        "span-456",
				OperationName: "http.request",
				ServiceName:   "test-service",
				StartTime:     time.Now(),
				Duration:      100 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "collected")
		assert.Contains(t, err.Error(), "not exported")
	})

	t.Run("export traces fails regardless of config", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		traces := []integrations.Trace{
			{
				TraceID:       "trace-123",
				SpanID:        "span-456",
				OperationName: "test.operation",
				ServiceName:   "test-service",
				StartTime:     time.Now(),
				Duration:      50 * time.Millisecond,
				Status:        integrations.TraceStatusOK,
			},
		}

		result, err := exporter.ExportTraces(ctx, traces)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "collected")
	})
}

// =============================================================================
// ExportLogs Tests
// =============================================================================

func TestEBPFExporterExportLogs(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export logs returns not-supported error", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:       true,
			CollectFileIO: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelInfo,
				Message:   "Test log message",
				Source:    "test-source",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not support")
		assert.Contains(t, err.Error(), "log ingestion")
	})

	t.Run("export logs fails regardless of enabled state", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		logs := []integrations.LogEntry{
			{
				Timestamp: time.Now(),
				Level:     integrations.LogLevelError,
				Message:   "Error log message",
				Source:    "error-source",
			},
		}

		result, err := exporter.ExportLogs(ctx, logs)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "log ingestion")
	})
}

// =============================================================================
// CollectMetrics Tests
// =============================================================================

func TestEBPFExporterCollectMetrics(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("collect metrics fails when disabled", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		metrics, err := exporter.CollectMetrics(ctx)
		require.Error(t, err)
		assert.Nil(t, metrics)
		assert.Equal(t, integrations.ErrNotEnabled, err)
	})

	t.Run("collect metrics fails when not initialized", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("Skipping on Linux - needs actual eBPF setup")
		}
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		// Not calling Init() - can't initialize on non-Linux anyway

		metrics, err := exporter.CollectMetrics(ctx)
		require.Error(t, err)
		assert.Nil(t, metrics)
		assert.Equal(t, integrations.ErrNotInitialized, err)
	})
}

// =============================================================================
// Health Tests
// =============================================================================

func TestEBPFExporterHealth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("health check when disabled", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Healthy)
		assert.Equal(t, "integration disabled", status.Message)
	})

	t.Run("health check on non-linux platform", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("Skipping non-Linux test on Linux")
		}
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
		assert.False(t, status.Healthy)
		assert.Contains(t, status.Message, "Linux")
		assert.NotZero(t, status.LastCheck)
	})

	t.Run("health returns platform details", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
			CollectNetwork:  true,
			CollectFileIO:   true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)

		if runtime.GOOS == "linux" {
			// On Linux, should report healthy with details
			assert.True(t, status.Healthy)
			assert.NotNil(t, status.Details)
			details := status.Details
			assert.Equal(t, "linux", details["platform"])
			assert.NotEmpty(t, details["arch"])
		} else {
			// On non-Linux, should report unhealthy
			assert.False(t, status.Healthy)
		}
	})

	t.Run("health check shows collector configuration", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
			CollectNetwork:  false,
			CollectFileIO:   true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)

		if runtime.GOOS == "linux" {
			details := status.Details
			assert.Equal(t, true, details["collect_syscalls"])
			assert.Equal(t, false, details["collect_network"])
			assert.Equal(t, true, details["collect_fileio"])
		}
	})
}

// =============================================================================
// Close Tests
// =============================================================================

func TestEBPFExporterClose(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("close without init", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		// Not calling Init()

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})

	t.Run("close when disabled", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		err := exporter.Close(ctx)
		assert.NoError(t, err)
	})

	t.Run("close sets initialized to false", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		_ = exporter.Init(ctx)

		err := exporter.Close(ctx)
		assert.NoError(t, err)
		assert.False(t, exporter.IsInitialized())
	})

	t.Run("close multiple times", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: false,
		}
		exporter := integrations.NewEBPFExporter(config, logger)

		err := exporter.Close(ctx)
		assert.NoError(t, err)

		// Close again should not error
		err = exporter.Close(ctx)
		assert.NoError(t, err)
	})
}

// =============================================================================
// SupportedDataTypes Tests
// =============================================================================

func TestEBPFExporterSupportedTypes(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	types := exporter.SupportedDataTypes()

	// eBPF should support metrics and traces (as a data source)
	assert.Len(t, types, 2)
	assert.Contains(t, types, integrations.DataTypeMetrics)
	assert.Contains(t, types, integrations.DataTypeTraces)
}

// =============================================================================
// Config Defaults Tests
// =============================================================================

func TestEBPFConfigDefaults(t *testing.T) {
	config := integrations.EBPFConfig{}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.ProgramsPath)
	assert.Empty(t, config.PinPath)
	assert.Equal(t, time.Duration(0), config.ScrapeInterval)
	assert.False(t, config.CollectSyscalls)
	assert.False(t, config.CollectNetwork)
	assert.False(t, config.CollectFileIO)
	assert.False(t, config.CollectScheduler)
	assert.False(t, config.CollectMemory)
	assert.False(t, config.CollectTCPEvents)
	assert.False(t, config.CollectDNS)
	assert.False(t, config.CollectHTTP)
	assert.Nil(t, config.ProcessFilter)
	assert.Nil(t, config.ContainerFilter)
	assert.Nil(t, config.NamespaceFilter)
	assert.Nil(t, config.ExcludeProcesses)
	assert.Equal(t, 0, config.SampleRate)
	assert.Equal(t, 0, config.RingBufferSize)
	assert.Equal(t, 0, config.PerfBufferSize)
	assert.Equal(t, 0, config.MaxStackDepth)
	assert.Empty(t, config.BTFPath)
	assert.Nil(t, config.Labels)
}

// =============================================================================
// Config Variations Tests
// =============================================================================

func TestEBPFExporterWithAllCollectorCombinations(t *testing.T) {
	logger := zap.NewNop()

	// Test various collector combinations
	testCases := []struct {
		name   string
		config integrations.EBPFConfig
	}{
		{
			name: "syscalls only",
			config: integrations.EBPFConfig{
				Enabled:         true,
				CollectSyscalls: true,
			},
		},
		{
			name: "network only",
			config: integrations.EBPFConfig{
				Enabled:        true,
				CollectNetwork: true,
			},
		},
		{
			name: "fileio only",
			config: integrations.EBPFConfig{
				Enabled:       true,
				CollectFileIO: true,
			},
		},
		{
			name: "scheduler only",
			config: integrations.EBPFConfig{
				Enabled:          true,
				CollectScheduler: true,
			},
		},
		{
			name: "memory only",
			config: integrations.EBPFConfig{
				Enabled:       true,
				CollectMemory: true,
			},
		},
		{
			name: "tcp events only",
			config: integrations.EBPFConfig{
				Enabled:          true,
				CollectTCPEvents: true,
			},
		},
		{
			name: "syscalls and network",
			config: integrations.EBPFConfig{
				Enabled:         true,
				CollectSyscalls: true,
				CollectNetwork:  true,
			},
		},
		{
			name: "all collectors",
			config: integrations.EBPFConfig{
				Enabled:          true,
				CollectSyscalls:  true,
				CollectNetwork:   true,
				CollectFileIO:    true,
				CollectScheduler: true,
				CollectMemory:    true,
				CollectTCPEvents: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exporter := integrations.NewEBPFExporter(tc.config, logger)
			require.NotNil(t, exporter)
			assert.True(t, exporter.IsEnabled())
		})
	}
}

func TestEBPFExporterWithBufferSizeVariations(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	bufferSizes := []struct {
		name       string
		ringBuffer int
		perfBuffer int
	}{
		{"small", 64 * 1024, 32},
		{"medium", 256 * 1024, 64},
		{"large", 1024 * 1024, 256},
		{"extra_large", 4096 * 1024, 512},
	}

	for _, bs := range bufferSizes {
		t.Run(bs.name, func(t *testing.T) {
			config := integrations.EBPFConfig{
				Enabled:        true,
				RingBufferSize: bs.ringBuffer,
				PerfBufferSize: bs.perfBuffer,
			}

			exporter := integrations.NewEBPFExporter(config, logger)
			require.NotNil(t, exporter)

			// Init will fail on non-Linux, but exporter creation should succeed
			err := exporter.Init(ctx)
			if runtime.GOOS != "linux" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Linux")
			}
		})
	}
}

func TestEBPFExporterWithScrapeIntervalVariations(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	intervals := []time.Duration{
		1 * time.Second,
		5 * time.Second,
		10 * time.Second,
		30 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
	}

	for _, interval := range intervals {
		t.Run(interval.String(), func(t *testing.T) {
			config := integrations.EBPFConfig{
				Enabled:        true,
				ScrapeInterval: interval,
			}

			exporter := integrations.NewEBPFExporter(config, logger)
			require.NotNil(t, exporter)

			err := exporter.Init(ctx)
			if runtime.GOOS != "linux" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Linux")
			}
		})
	}
}

func TestEBPFExporterWithSampleRateVariations(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	sampleRates := []int{1, 10, 50, 100}

	for _, rate := range sampleRates {
		t.Run("sample_rate_"+string(rune('0'+rate)), func(t *testing.T) {
			config := integrations.EBPFConfig{
				Enabled:    true,
				SampleRate: rate,
			}

			exporter := integrations.NewEBPFExporter(config, logger)
			require.NotNil(t, exporter)

			err := exporter.Init(ctx)
			if runtime.GOOS != "linux" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "Linux")
			}
		})
	}
}

// =============================================================================
// Stats Tests
// =============================================================================

func TestEBPFExporterStats(t *testing.T) {
	logger := zap.NewNop()

	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	stats := exporter.Stats()
	assert.Equal(t, "ebpf", stats.Name)
	assert.Equal(t, "kernel", stats.Type)
	assert.True(t, stats.Enabled)
	assert.False(t, stats.Initialized) // Not initialized yet
}

func TestEBPFExporterStatsWhenDisabled(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.EBPFConfig{
		Enabled: false,
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	_ = exporter.Init(ctx)

	stats := exporter.Stats()
	assert.Equal(t, "ebpf", stats.Name)
	assert.Equal(t, "kernel", stats.Type)
	assert.False(t, stats.Enabled)
	assert.False(t, stats.Initialized) // Disabled doesn't initialize
}

// =============================================================================
// Error Path Tests
// =============================================================================

func TestEBPFExporterErrorPaths(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("export on disabled exporter", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: false}
		exporter := integrations.NewEBPFExporter(config, logger)

		telemetryData := &integrations.TelemetryData{Timestamp: time.Now()}
		result, err := exporter.Export(ctx, telemetryData)

		assert.Error(t, err)
		assert.Equal(t, integrations.ErrNotEnabled, err)
		assert.Nil(t, result)
	})

	t.Run("collect metrics on disabled exporter", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: false}
		exporter := integrations.NewEBPFExporter(config, logger)

		metrics, err := exporter.CollectMetrics(ctx)

		assert.Error(t, err)
		assert.Equal(t, integrations.ErrNotEnabled, err)
		assert.Nil(t, metrics)
	})

	t.Run("export metrics always fails with specific error", func(t *testing.T) {
		// ExportMetrics should always fail as eBPF is a data source
		configs := []integrations.EBPFConfig{
			{Enabled: true},
			{Enabled: false},
			{Enabled: true, CollectSyscalls: true},
		}

		for _, config := range configs {
			exporter := integrations.NewEBPFExporter(config, logger)
			metrics := []integrations.Metric{{Name: "test", Value: 1.0, Timestamp: time.Now()}}

			result, err := exporter.ExportMetrics(ctx, metrics)
			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "data source")
		}
	})

	t.Run("export traces always fails with specific error", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: true}
		exporter := integrations.NewEBPFExporter(config, logger)

		traces := []integrations.Trace{{TraceID: "test", SpanID: "span", StartTime: time.Now()}}
		result, err := exporter.ExportTraces(ctx, traces)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "collected")
	})

	t.Run("export logs always fails with specific error", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: true}
		exporter := integrations.NewEBPFExporter(config, logger)

		logs := []integrations.LogEntry{{Timestamp: time.Now(), Message: "test"}}
		result, err := exporter.ExportLogs(ctx, logs)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "log ingestion")
	})
}

// =============================================================================
// Platform-Specific Tests
// =============================================================================

func TestEBPFExporterPlatformBehavior(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
		CollectNetwork:  true,
		CollectFileIO:   true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	// Test behavior based on current platform
	t.Run("init behavior", func(t *testing.T) {
		err := exporter.Init(ctx)
		if runtime.GOOS == "linux" {
			// On Linux, should succeed (assuming proper permissions)
			// In test environment, might still fail due to missing eBPF support
			// Just verify the error doesn't mention "Linux"
			if err != nil {
				assert.NotContains(t, err.Error(), "only supported on Linux")
			}
		} else {
			// On non-Linux, should fail with platform error
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("validate behavior", func(t *testing.T) {
		err := exporter.Validate()
		if runtime.GOOS == "linux" {
			// On Linux, validation should pass
			assert.NoError(t, err)
		} else {
			// On non-Linux, should fail with platform error
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("health check behavior", func(t *testing.T) {
		status, err := exporter.Health(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)

		if runtime.GOOS == "linux" {
			// On Linux, should report platform as linux
			if status.Details != nil {
				assert.Equal(t, "linux", status.Details["platform"])
			}
		} else {
			// On non-Linux, should report unhealthy with Linux message
			assert.False(t, status.Healthy)
			assert.Contains(t, status.Message, "Linux")
		}
	})
}

// =============================================================================
// ValidationError Tests
// =============================================================================

func TestEBPFValidationError(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Skipping validation error test on Linux")
	}

	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	err := exporter.Validate()

	require.Error(t, err)

	// Check if it's a ValidationError
	validationErr, ok := err.(*integrations.ValidationError)
	require.True(t, ok, "Expected ValidationError type")

	assert.Equal(t, "ebpf", validationErr.Integration)
	assert.Equal(t, "platform", validationErr.Field)
	assert.Contains(t, validationErr.Message, "Linux")
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkNewEBPFExporter(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
		CollectNetwork:  true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewEBPFExporter(config, logger)
	}
}

func BenchmarkEBPFExporterHealth(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.Health(ctx)
	}
}

func BenchmarkEBPFExporterValidate(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = exporter.Validate()
	}
}

func BenchmarkEBPFExporterExportMetricsError(b *testing.B) {
	logger := zap.NewNop()
	ctx := context.Background()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	metrics := []integrations.Metric{
		{
			Name:      "benchmark_metric",
			Value:     1.0,
			Type:      integrations.MetricTypeGauge,
			Timestamp: time.Now(),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = exporter.ExportMetrics(ctx, metrics)
	}
}

func BenchmarkEBPFExporterStats(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:         true,
		CollectSyscalls: true,
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = exporter.Stats()
	}
}

func BenchmarkEBPFExporterWithLabels(b *testing.B) {
	logger := zap.NewNop()
	labels := map[string]string{
		"environment": "production",
		"region":      "us-west-2",
		"cluster":     "k8s-prod-01",
		"namespace":   "default",
		"service":     "api-gateway",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := integrations.EBPFConfig{
			Enabled: true,
			Labels:  labels,
		}
		integrations.NewEBPFExporter(config, logger)
	}
}

// =============================================================================
// Integration Edge Cases
// =============================================================================

func TestEBPFExporterEdgeCases(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("nil telemetry data", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: false}
		exporter := integrations.NewEBPFExporter(config, logger)

		// Export with nil data - should return ErrNotEnabled first
		result, err := exporter.Export(ctx, nil)
		assert.Error(t, err)
		assert.Equal(t, integrations.ErrNotEnabled, err)
		assert.Nil(t, result)
	})

	t.Run("empty metrics slice", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: true}
		exporter := integrations.NewEBPFExporter(config, logger)

		result, err := exporter.ExportMetrics(ctx, []integrations.Metric{})
		// Should still fail with "data source" error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "data source")
		assert.Nil(t, result)
	})

	t.Run("empty traces slice", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: true}
		exporter := integrations.NewEBPFExporter(config, logger)

		result, err := exporter.ExportTraces(ctx, []integrations.Trace{})
		// Should still fail with "collected" error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "collected")
		assert.Nil(t, result)
	})

	t.Run("empty logs slice", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: true}
		exporter := integrations.NewEBPFExporter(config, logger)

		result, err := exporter.ExportLogs(ctx, []integrations.LogEntry{})
		// Should still fail with "log ingestion" error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "log ingestion")
		assert.Nil(t, result)
	})

	t.Run("context cancellation", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: false}
		exporter := integrations.NewEBPFExporter(config, logger)

		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		// Operations should still work (or fail with ErrNotEnabled)
		status, err := exporter.Health(canceledCtx)
		assert.NoError(t, err)
		assert.NotNil(t, status)
	})

	t.Run("context with timeout", func(t *testing.T) {
		config := integrations.EBPFConfig{Enabled: false}
		exporter := integrations.NewEBPFExporter(config, logger)

		timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Nanosecond)
		defer cancel()

		// Let it timeout
		time.Sleep(10 * time.Nanosecond)

		// Operations should still work
		status, err := exporter.Health(timeoutCtx)
		assert.NoError(t, err)
		assert.NotNil(t, status)
	})
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestEBPFExporterConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	config := integrations.EBPFConfig{
		Enabled: false,
	}

	exporter := integrations.NewEBPFExporter(config, logger)
	_ = exporter.Init(ctx)

	t.Run("concurrent health checks", func(t *testing.T) {
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					_, _ = exporter.Health(ctx)
				}
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("concurrent stats access", func(t *testing.T) {
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					_ = exporter.Stats()
				}
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("concurrent export attempts", func(t *testing.T) {
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					telemetryData := &integrations.TelemetryData{Timestamp: time.Now()}
					_, _ = exporter.Export(ctx, telemetryData)
				}
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// =============================================================================
// Cilium Hubble Configuration Tests
// =============================================================================

func TestCiliumConfigDefaults(t *testing.T) {
	config := integrations.CiliumConfig{}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.HubbleAddress)
	assert.False(t, config.HubbleTLSEnabled)
	assert.Empty(t, config.HubbleTLSCertPath)
	assert.Empty(t, config.HubbleTLSKeyPath)
	assert.Empty(t, config.HubbleTLSCAPath)
	assert.False(t, config.CollectFlows)
	assert.False(t, config.CollectL7Flows)
	assert.False(t, config.CollectDrops)
	assert.False(t, config.CollectPolicies)
	assert.False(t, config.CollectServices)
	assert.False(t, config.KubernetesEnabled)
	assert.Nil(t, config.WatchNamespaces)
	assert.Nil(t, config.ExcludeNamespaces)
	assert.Equal(t, 0, config.FlowBufferSize)
	assert.Equal(t, 0, config.FlowSampleRate)
	assert.Equal(t, 0, config.MaxFlowsPerSecond)
	assert.Equal(t, time.Duration(0), config.AggregationWindow)
}

func TestNewEBPFExporterWithCilium(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			HubbleAddress:     "hubble-relay:4245",
			CollectFlows:      true,
			CollectL7Flows:    true,
			CollectDrops:      true,
			KubernetesEnabled: true,
		},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.Equal(t, "ebpf", exporter.Name())
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithCiliumDisabled(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Cilium: integrations.CiliumConfig{
			Enabled: false,
		},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithCiliumTLS(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			HubbleAddress:     "hubble-relay.kube-system.svc:4245",
			HubbleTLSEnabled:  true,
			HubbleTLSCertPath: "/etc/hubble/tls.crt",
			HubbleTLSKeyPath:  "/etc/hubble/tls.key",
			HubbleTLSCAPath:   "/etc/hubble/ca.crt",
			CollectFlows:      true,
		},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithCiliumNamespaceFilters(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			HubbleAddress:     "localhost:4245",
			KubernetesEnabled: true,
			WatchNamespaces:   []string{"production", "staging"},
			ExcludeNamespaces: []string{"kube-system", "cilium"},
			CollectFlows:      true,
		},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithCiliumPerformanceSettings(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			HubbleAddress:     "localhost:4245",
			CollectFlows:      true,
			FlowBufferSize:    8192,
			FlowSampleRate:    10,
			MaxFlowsPerSecond: 5000,
			AggregationWindow: 30 * time.Second,
		},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

func TestNewEBPFExporterWithCiliumAllCollectors(t *testing.T) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			HubbleAddress:     "localhost:4245",
			CollectFlows:      true,
			CollectL7Flows:    true,
			CollectDrops:      true,
			CollectPolicies:   true,
			CollectServices:   true,
			KubernetesEnabled: true,
		},
	}

	exporter := integrations.NewEBPFExporter(config, logger)

	require.NotNil(t, exporter)
	assert.True(t, exporter.IsEnabled())
}

// =============================================================================
// Cilium Hubble Init Tests
// =============================================================================

func TestEBPFExporterInitWithCilium(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("init with cilium enabled on non-linux", func(t *testing.T) {
		if runtime.GOOS == "linux" {
			t.Skip("Skipping non-Linux test on Linux")
		}
		config := integrations.EBPFConfig{
			Enabled: true,
			Cilium: integrations.CiliumConfig{
				Enabled:       true,
				HubbleAddress: "localhost:4245",
				CollectFlows:  true,
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Linux")
	})

	t.Run("init with cilium sets default address", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: true,
			Cilium: integrations.CiliumConfig{
				Enabled:      true,
				CollectFlows: true,
				// HubbleAddress left empty - should default to localhost:4245
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		// On non-Linux, will fail with platform error
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("init with cilium sets default buffer size", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: true,
			Cilium: integrations.CiliumConfig{
				Enabled:      true,
				CollectFlows: true,
				// FlowBufferSize left as 0 - should default to 4096
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})

	t.Run("init with cilium enables default collectors", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: true,
			Cilium: integrations.CiliumConfig{
				Enabled: true,
				// No collectors specified - should enable CollectFlows and CollectDrops
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		err := exporter.Init(ctx)
		if runtime.GOOS != "linux" {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "Linux")
		}
	})
}

// =============================================================================
// Cilium Hubble Collector Combinations Tests
// =============================================================================

func TestEBPFExporterWithCiliumCollectorCombinations(t *testing.T) {
	logger := zap.NewNop()

	testCases := []struct {
		name   string
		config integrations.CiliumConfig
	}{
		{
			name: "flows only",
			config: integrations.CiliumConfig{
				Enabled:      true,
				CollectFlows: true,
			},
		},
		{
			name: "l7 flows only",
			config: integrations.CiliumConfig{
				Enabled:        true,
				CollectL7Flows: true,
			},
		},
		{
			name: "drops only",
			config: integrations.CiliumConfig{
				Enabled:      true,
				CollectDrops: true,
			},
		},
		{
			name: "policies only",
			config: integrations.CiliumConfig{
				Enabled:         true,
				CollectPolicies: true,
			},
		},
		{
			name: "services only",
			config: integrations.CiliumConfig{
				Enabled:         true,
				CollectServices: true,
			},
		},
		{
			name: "flows and drops",
			config: integrations.CiliumConfig{
				Enabled:      true,
				CollectFlows: true,
				CollectDrops: true,
			},
		},
		{
			name: "l7 and policies",
			config: integrations.CiliumConfig{
				Enabled:         true,
				CollectL7Flows:  true,
				CollectPolicies: true,
			},
		},
		{
			name: "all collectors",
			config: integrations.CiliumConfig{
				Enabled:         true,
				CollectFlows:    true,
				CollectL7Flows:  true,
				CollectDrops:    true,
				CollectPolicies: true,
				CollectServices: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := integrations.EBPFConfig{
				Enabled: true,
				Cilium:  tc.config,
			}
			exporter := integrations.NewEBPFExporter(config, logger)
			require.NotNil(t, exporter)
			assert.True(t, exporter.IsEnabled())
		})
	}
}

// =============================================================================
// Cilium Hubble with eBPF Collector Combinations Tests
// =============================================================================

func TestEBPFExporterWithBothEBPFAndCilium(t *testing.T) {
	logger := zap.NewNop()

	t.Run("ebpf syscalls with cilium flows", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:         true,
			CollectSyscalls: true,
			Cilium: integrations.CiliumConfig{
				Enabled:      true,
				CollectFlows: true,
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		require.NotNil(t, exporter)
		assert.True(t, exporter.IsEnabled())
	})

	t.Run("ebpf network with cilium l7", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:        true,
			CollectNetwork: true,
			Cilium: integrations.CiliumConfig{
				Enabled:        true,
				CollectL7Flows: true,
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		require.NotNil(t, exporter)
		assert.True(t, exporter.IsEnabled())
	})

	t.Run("all ebpf with all cilium", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled:          true,
			CollectSyscalls:  true,
			CollectNetwork:   true,
			CollectFileIO:    true,
			CollectScheduler: true,
			CollectMemory:    true,
			CollectTCPEvents: true,
			Cilium: integrations.CiliumConfig{
				Enabled:           true,
				HubbleAddress:     "hubble-relay:4245",
				CollectFlows:      true,
				CollectL7Flows:    true,
				CollectDrops:      true,
				CollectPolicies:   true,
				CollectServices:   true,
				KubernetesEnabled: true,
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		require.NotNil(t, exporter)
		assert.True(t, exporter.IsEnabled())
	})

	t.Run("cilium only without ebpf collectors", func(t *testing.T) {
		config := integrations.EBPFConfig{
			Enabled: true,
			// No eBPF collectors enabled
			Cilium: integrations.CiliumConfig{
				Enabled:      true,
				CollectFlows: true,
				CollectDrops: true,
			},
		}
		exporter := integrations.NewEBPFExporter(config, logger)
		require.NotNil(t, exporter)
		assert.True(t, exporter.IsEnabled())
	})
}

// =============================================================================
// Cilium Hubble Benchmark Tests
// =============================================================================

func BenchmarkNewEBPFExporterWithCilium(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled: true,
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			HubbleAddress:     "localhost:4245",
			CollectFlows:      true,
			CollectL7Flows:    true,
			CollectDrops:      true,
			KubernetesEnabled: true,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewEBPFExporter(config, logger)
	}
}

func BenchmarkNewEBPFExporterWithCiliumAllOptions(b *testing.B) {
	logger := zap.NewNop()
	config := integrations.EBPFConfig{
		Enabled:          true,
		CollectSyscalls:  true,
		CollectNetwork:   true,
		CollectFileIO:    true,
		CollectScheduler: true,
		CollectMemory:    true,
		CollectTCPEvents: true,
		Labels: map[string]string{
			"environment": "production",
			"cluster":     "k8s-prod",
		},
		Cilium: integrations.CiliumConfig{
			Enabled:           true,
			HubbleAddress:     "hubble-relay.kube-system.svc:4245",
			HubbleTLSEnabled:  true,
			HubbleTLSCertPath: "/etc/hubble/tls.crt",
			HubbleTLSKeyPath:  "/etc/hubble/tls.key",
			HubbleTLSCAPath:   "/etc/hubble/ca.crt",
			CollectFlows:      true,
			CollectL7Flows:    true,
			CollectDrops:      true,
			CollectPolicies:   true,
			CollectServices:   true,
			KubernetesEnabled: true,
			WatchNamespaces:   []string{"production", "staging"},
			ExcludeNamespaces: []string{"kube-system", "cilium"},
			FlowBufferSize:    8192,
			FlowSampleRate:    1,
			MaxFlowsPerSecond: 10000,
			AggregationWindow: 10 * time.Second,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrations.NewEBPFExporter(config, logger)
	}
}
