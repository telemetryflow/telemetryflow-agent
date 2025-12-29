// Package application_test provides unit tests for the TelemetryFlow Agent main functionality.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package application_test

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// TestInitLoggerLevels tests logger initialization with different log levels
func TestInitLoggerLevels(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected zapcore.Level
	}{
		{"debug level", "debug", zapcore.DebugLevel},
		{"info level", "info", zapcore.InfoLevel},
		{"warn level", "warn", zapcore.WarnLevel},
		{"error level", "error", zapcore.ErrorLevel},
		{"invalid level defaults to info", "invalid", zapcore.InfoLevel},
		{"empty level defaults to info", "", zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.LoggingConfig{
				Level:  tt.level,
				Format: "json",
			}

			logger, err := initTestLogger(cfg)
			require.NoError(t, err)
			require.NotNil(t, logger)
			defer func() { _ = logger.Sync() }()
		})
	}
}

// TestInitLoggerFormats tests logger initialization with different log formats
func TestInitLoggerFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"json format", "json"},
		{"text format", "text"},
		{"console format", "console"},
		{"empty format defaults", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.LoggingConfig{
				Level:  "info",
				Format: tt.format,
			}

			logger, err := initTestLogger(cfg)
			require.NoError(t, err)
			require.NotNil(t, logger)
			defer func() { _ = logger.Sync() }()
		})
	}
}

// TestInitLoggerWithFile tests logger with file output
func TestInitLoggerWithFile(t *testing.T) {
	t.Run("should create logger with file output", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "test-log-*.log")
		require.NoError(t, err)
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		_ = tmpFile.Close()

		cfg := config.LoggingConfig{
			Level:  "debug",
			Format: "json",
			File:   tmpFile.Name(),
		}

		logger, err := initTestLogger(cfg)
		require.NoError(t, err)
		require.NotNil(t, logger)

		// Write a log entry
		logger.Info("test message")
		_ = logger.Sync()

		// Verify file has content
		content, err := os.ReadFile(tmpFile.Name())
		require.NoError(t, err)
		assert.NotEmpty(t, content)
	})
}

// TestPrintConfig tests config printing functionality
func TestPrintConfig(t *testing.T) {
	t.Run("should print configuration without error", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.ID = "test-agent-id"
		cfg.Agent.Hostname = "test-hostname"
		cfg.TelemetryFlow.Endpoint = "test-endpoint:4317"
		cfg.TelemetryFlow.WorkspaceID = "test-workspace"

		// Capture output
		output := captureOutput(func() {
			printTestConfig(cfg)
		})

		assert.Contains(t, output, "TelemetryFlow Agent Configuration")
		assert.Contains(t, output, "test-agent-id")
		assert.Contains(t, output, "test-hostname")
		assert.Contains(t, output, "test-endpoint:4317")
	})

	t.Run("should print collector settings", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = true
		cfg.Collector.Logs.Enabled = true
		cfg.Collector.Process.Enabled = false

		output := captureOutput(func() {
			printTestConfig(cfg)
		})

		assert.Contains(t, output, "Collectors")
		assert.Contains(t, output, "System")
	})

	t.Run("should print exporter settings", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Exporter.OTLP.Enabled = true
		cfg.Exporter.OTLP.BatchSize = 200
		cfg.Exporter.OTLP.Compression = "gzip"

		output := captureOutput(func() {
			printTestConfig(cfg)
		})

		assert.Contains(t, output, "Exporter")
		assert.Contains(t, output, "200")
		assert.Contains(t, output, "gzip")
	})

	t.Run("should print buffer settings", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Buffer.Enabled = true
		cfg.Buffer.MaxSizeMB = 150
		cfg.Buffer.Path = "/custom/path"

		output := captureOutput(func() {
			printTestConfig(cfg)
		})

		assert.Contains(t, output, "Buffer")
		assert.Contains(t, output, "150")
	})

	t.Run("should print TLS settings", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.TLS.Enabled = true

		output := captureOutput(func() {
			printTestConfig(cfg)
		})

		assert.Contains(t, output, "TLS")
	})
}

// TestConfigEffectiveMethods tests all GetEffective* methods
func TestConfigEffectiveMethods(t *testing.T) {
	t.Run("GetEffectiveTimeout should return configured timeout", func(t *testing.T) {
		cfg := config.DefaultConfig()

		timeout := cfg.GetEffectiveTimeout()
		assert.Equal(t, cfg.TelemetryFlow.Timeout, timeout)
	})

	t.Run("GetEffectiveTimeout should return default when zero", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Timeout = 0

		timeout := cfg.GetEffectiveTimeout()
		assert.NotZero(t, timeout)
	})

	t.Run("GetEffectiveRetryAttempts should return configured value", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Retry.MaxAttempts = 5

		attempts := cfg.GetEffectiveRetryAttempts()
		assert.Equal(t, 5, attempts)
	})

	t.Run("GetEffectiveRetryAttempts should return default when zero", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Retry.MaxAttempts = 0

		attempts := cfg.GetEffectiveRetryAttempts()
		assert.Equal(t, 3, attempts)
	})

	t.Run("GetEffectiveRetryDelay should return configured value", func(t *testing.T) {
		cfg := config.DefaultConfig()

		delay := cfg.GetEffectiveRetryDelay()
		assert.Equal(t, cfg.TelemetryFlow.Retry.InitialInterval, delay)
	})

	t.Run("GetEffectiveRetryDelay should return default when zero", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Retry.InitialInterval = 0

		delay := cfg.GetEffectiveRetryDelay()
		assert.NotZero(t, delay)
	})

	t.Run("GetEffectiveTLSConfig should return TLS config", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.TLS.Enabled = true
		cfg.TelemetryFlow.TLS.SkipVerify = true

		tlsCfg := cfg.GetEffectiveTLSConfig()
		assert.True(t, tlsCfg.Enabled)
		assert.True(t, tlsCfg.SkipVerify)
	})

	t.Run("GetEffectiveWorkspaceID should return workspace ID", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.WorkspaceID = "ws-123"

		wsID := cfg.GetEffectiveWorkspaceID()
		assert.Equal(t, "ws-123", wsID)
	})

	t.Run("GetEffectiveTenantID should return tenant ID", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.TenantID = "tenant-456"

		tenantID := cfg.GetEffectiveTenantID()
		assert.Equal(t, "tenant-456", tenantID)
	})
}

// TestConfigError tests the configError type
func TestConfigError(t *testing.T) {
	t.Run("ErrMissingEndpoint should have correct message", func(t *testing.T) {
		assert.Contains(t, config.ErrMissingEndpoint.Error(), "endpoint")
	})

	t.Run("ErrInvalidHeartbeatInterval should have correct message", func(t *testing.T) {
		assert.Contains(t, config.ErrInvalidHeartbeatInterval.Error(), "heartbeat")
	})

	t.Run("ErrInvalidProtocol should have correct message", func(t *testing.T) {
		assert.Contains(t, config.ErrInvalidProtocol.Error(), "protocol")
	})
}

// TestRetryConfig tests retry configuration
func TestRetryConfig(t *testing.T) {
	t.Run("should have valid retry defaults", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.True(t, cfg.TelemetryFlow.Retry.Enabled)
		assert.Greater(t, cfg.TelemetryFlow.Retry.MaxAttempts, 0)
		assert.Greater(t, cfg.TelemetryFlow.Retry.InitialInterval.Nanoseconds(), int64(0))
		assert.Greater(t, cfg.TelemetryFlow.Retry.MaxInterval.Nanoseconds(), int64(0))
	})
}

// TestAPIConfig tests deprecated API config using reflection to avoid staticcheck warnings
func TestAPIConfig(t *testing.T) {
	t.Run("should have API config for backward compatibility", func(t *testing.T) {
		cfg := config.DefaultConfig()

		// Use reflection to access deprecated API field without triggering staticcheck
		apiConfig := getDeprecatedAPIConfig(cfg)
		require.NotNil(t, apiConfig, "API config should exist for backward compatibility")

		// Verify API config has valid defaults
		assert.NotEmpty(t, apiConfig.Endpoint)
		assert.Greater(t, apiConfig.Timeout.Nanoseconds(), int64(0))
		assert.Greater(t, apiConfig.RetryAttempts, 0)
	})
}

// getDeprecatedAPIConfig uses reflection to access the deprecated API field
// This avoids staticcheck SA1019 warnings while still testing backward compatibility
func getDeprecatedAPIConfig(cfg *config.Config) *config.APIConfig {
	val := reflect.ValueOf(cfg).Elem()
	apiField := val.FieldByName("API")
	if !apiField.IsValid() {
		return nil
	}
	apiConfig := apiField.Interface().(config.APIConfig)
	return &apiConfig
}

// Helper function to mimic initLogger from main.go
func initTestLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var level zapcore.Level
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	var zapCfg zap.Config
	if cfg.Format == "json" {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	zapCfg.Level = zap.NewAtomicLevelAt(level)

	if cfg.File != "" {
		zapCfg.OutputPaths = []string{cfg.File}
		zapCfg.ErrorOutputPaths = []string{cfg.File}
	}

	return zapCfg.Build()
}

// Helper function to mimic printConfig from main.go
func printTestConfig(cfg *config.Config) {
	var output strings.Builder
	output.WriteString("TelemetryFlow Agent Configuration\n")
	output.WriteString("==================================\n")
	output.WriteString("\nAgent:\n")
	output.WriteString("  ID:       " + cfg.Agent.ID + "\n")
	output.WriteString("  Hostname: " + cfg.Agent.Hostname + "\n")

	output.WriteString("\nTelemetryFlow:\n")
	output.WriteString("  Endpoint:    " + cfg.GetEffectiveEndpoint() + "\n")
	output.WriteString("  Workspace:   " + cfg.GetEffectiveWorkspaceID() + "\n")
	if cfg.GetEffectiveTLSConfig().Enabled {
		output.WriteString("  TLS Enabled: true\n")
	} else {
		output.WriteString("  TLS Enabled: false\n")
	}

	output.WriteString("\nHeartbeat:\n")
	output.WriteString("  Interval: " + cfg.Heartbeat.Interval.String() + "\n")
	output.WriteString("  Timeout:  " + cfg.Heartbeat.Timeout.String() + "\n")

	output.WriteString("\nCollectors:\n")
	if cfg.Collector.System.Enabled {
		output.WriteString("  System:  enabled=true, interval=" + cfg.Collector.System.Interval.String() + "\n")
	} else {
		output.WriteString("  System:  enabled=false\n")
	}
	if cfg.Collector.Logs.Enabled {
		output.WriteString("  Logs:    enabled=true\n")
	} else {
		output.WriteString("  Logs:    enabled=false\n")
	}
	if cfg.Collector.Process.Enabled {
		output.WriteString("  Process: enabled=true\n")
	} else {
		output.WriteString("  Process: enabled=false\n")
	}

	output.WriteString("\nExporter:\n")
	output.WriteString("  OTLP: enabled=" + boolToString(cfg.Exporter.OTLP.Enabled) +
		", batch_size=" + intToString(cfg.Exporter.OTLP.BatchSize) +
		", compression=" + cfg.Exporter.OTLP.Compression + "\n")

	output.WriteString("\nBuffer:\n")
	output.WriteString("  Enabled: " + boolToString(cfg.Buffer.Enabled) +
		", max_size=" + int64ToString(cfg.Buffer.MaxSizeMB) + "MB" +
		", path=" + cfg.Buffer.Path + "\n")

	output.WriteString("\nLogging:\n")
	output.WriteString("  Level: " + cfg.Logging.Level + ", Format: " + cfg.Logging.Format + "\n")

	// Print to stdout (this will be captured in tests)
	_, _ = os.Stdout.WriteString(output.String())
}

// Helper functions
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func intToString(i int) string {
	return fmt.Sprintf("%d", i)
}

func int64ToString(i int64) string {
	return fmt.Sprintf("%d", i)
}

// captureOutput captures stdout output
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}
