// Package config_test provides unit tests for the configuration package.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("should return valid default configuration", func(t *testing.T) {
		cfg := config.DefaultConfig()

		require.NotNil(t, cfg)
		assert.Equal(t, "http://localhost:3100", cfg.API.Endpoint)
		assert.Equal(t, 60*time.Second, cfg.Heartbeat.Interval)
		assert.True(t, cfg.Collector.System.Enabled)
		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "json", cfg.Logging.Format)
	})

	t.Run("should have valid heartbeat defaults", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.Equal(t, 60*time.Second, cfg.Heartbeat.Interval)
		assert.Equal(t, 10*time.Second, cfg.Heartbeat.Timeout)
		assert.True(t, cfg.Heartbeat.IncludeSystemInfo)
	})

	t.Run("should have valid collector defaults", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.True(t, cfg.Collector.System.Enabled)
		assert.Equal(t, 15*time.Second, cfg.Collector.System.Interval)
		assert.True(t, cfg.Collector.System.CPU)
		assert.True(t, cfg.Collector.System.Memory)
		assert.True(t, cfg.Collector.System.Disk)
		assert.True(t, cfg.Collector.System.Network)
	})

	t.Run("should have valid exporter defaults", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.True(t, cfg.Exporter.OTLP.Enabled)
		assert.Equal(t, 100, cfg.Exporter.OTLP.BatchSize)
		assert.Equal(t, "gzip", cfg.Exporter.OTLP.Compression)
	})

	t.Run("should have valid buffer defaults", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.True(t, cfg.Buffer.Enabled)
		assert.Equal(t, 100, cfg.Buffer.MaxSizeMB)
		assert.Equal(t, "/var/lib/tfo-agent/buffer", cfg.Buffer.Path)
	})
}

func TestConfigValidation(t *testing.T) {
	t.Run("should pass validation with valid config", func(t *testing.T) {
		cfg := config.DefaultConfig()

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("should fail validation with missing endpoint", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.API.Endpoint = ""

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Equal(t, config.ErrMissingEndpoint, err)
	})

	t.Run("should fail validation with invalid heartbeat interval", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Heartbeat.Interval = 500 * time.Millisecond // Less than 1 second

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Equal(t, config.ErrInvalidHeartbeatInterval, err)
	})

	t.Run("should pass validation with minimum heartbeat interval", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Heartbeat.Interval = 1 * time.Second

		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestAgentConfig(t *testing.T) {
	t.Run("should allow empty agent ID", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.ID = ""

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("should allow empty hostname", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.Hostname = ""

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("should preserve custom tags", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.Tags = map[string]string{
			"environment": "production",
			"datacenter":  "us-east-1",
		}

		assert.Equal(t, "production", cfg.Agent.Tags["environment"])
		assert.Equal(t, "us-east-1", cfg.Agent.Tags["datacenter"])
	})
}

func TestAPIConfig(t *testing.T) {
	t.Run("should have correct default timeout", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.Equal(t, 30*time.Second, cfg.API.Timeout)
	})

	t.Run("should have correct default retry settings", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.Equal(t, 3, cfg.API.RetryAttempts)
		assert.Equal(t, time.Second, cfg.API.RetryDelay)
	})

	t.Run("should have TLS disabled by default", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.False(t, cfg.API.TLS.Enabled)
		assert.False(t, cfg.API.TLS.SkipVerify)
	})
}

func TestLoggingConfig(t *testing.T) {
	validLevels := []string{"debug", "info", "warn", "error"}

	for _, level := range validLevels {
		t.Run("should accept log level "+level, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Logging.Level = level

			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}

	validFormats := []string{"json", "text"}

	for _, format := range validFormats {
		t.Run("should accept log format "+format, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Logging.Format = format

			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestCollectorConfig(t *testing.T) {
	t.Run("should allow disabling all collectors", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = false
		cfg.Collector.Logs.Enabled = false
		cfg.Collector.Process.Enabled = false

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("should allow custom disk paths", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.DiskPaths = []string{"/", "/home", "/var"}

		assert.Len(t, cfg.Collector.System.DiskPaths, 3)
	})

	t.Run("should allow custom log paths", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.Logs.Enabled = true
		cfg.Collector.Logs.Paths = []string{"/var/log/syslog", "/var/log/auth.log"}

		assert.Len(t, cfg.Collector.Logs.Paths, 2)
	})
}

func TestBufferConfig(t *testing.T) {
	t.Run("should allow disabling buffer", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Buffer.Enabled = false

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("should allow custom buffer path", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Buffer.Path = "/tmp/tfo-agent-buffer"

		assert.Equal(t, "/tmp/tfo-agent-buffer", cfg.Buffer.Path)
	})
}
