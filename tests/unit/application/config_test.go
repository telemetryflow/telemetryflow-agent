// Package application_test provides unit tests for the configuration package.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package application_test

import (
	"os"
	"path/filepath"
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
		// Check TelemetryFlow config
		assert.Equal(t, "localhost:4317", cfg.TelemetryFlow.Endpoint)
		assert.Equal(t, "grpc", cfg.TelemetryFlow.Protocol)
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
		assert.Equal(t, int64(100), cfg.Buffer.MaxSizeMB)
		assert.Equal(t, "/var/lib/tfo-agent/buffer", cfg.Buffer.Path)
		assert.Equal(t, 24*time.Hour, cfg.Buffer.MaxAge)
		assert.Equal(t, 5*time.Second, cfg.Buffer.FlushInterval)
	})

	t.Run("should have valid TelemetryFlow defaults", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.Equal(t, "localhost:4317", cfg.TelemetryFlow.Endpoint)
		assert.Equal(t, "grpc", cfg.TelemetryFlow.Protocol)
		assert.Equal(t, 30*time.Second, cfg.TelemetryFlow.Timeout)
		assert.True(t, cfg.TelemetryFlow.TLS.Enabled)
		assert.False(t, cfg.TelemetryFlow.TLS.SkipVerify)
		assert.True(t, cfg.TelemetryFlow.Retry.Enabled)
		assert.Equal(t, 3, cfg.TelemetryFlow.Retry.MaxAttempts)
	})

	t.Run("should have valid agent defaults", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.Equal(t, "TelemetryFlow Agent", cfg.Agent.Name)
		assert.Contains(t, cfg.Agent.Description, "TelemetryFlow Agent")
		assert.Equal(t, "production", cfg.Agent.Tags["environment"])
	})
}

func TestConfigStructValidation(t *testing.T) {
	t.Run("should pass validation with valid config", func(t *testing.T) {
		cfg := config.DefaultConfig()

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("should fail validation with missing endpoint", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Endpoint = ""

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

	t.Run("should fail validation with invalid protocol", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Protocol = "invalid"

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Equal(t, config.ErrInvalidProtocol, err)
	})

	t.Run("should pass validation with grpc protocol", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Protocol = "grpc"

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("should pass validation with http protocol", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Protocol = "http"

		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestConfigHelpers(t *testing.T) {
	t.Run("should return TelemetryFlow endpoint", func(t *testing.T) {
		cfg := config.DefaultConfig()

		assert.Equal(t, "localhost:4317", cfg.GetEffectiveEndpoint())
	})

	t.Run("should return TelemetryFlow API key ID", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.APIKeyID = "tfk_test_key"
		assert.Equal(t, "tfk_test_key", cfg.GetEffectiveAPIKeyID())
	})

	t.Run("should return TelemetryFlow API key secret", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.APIKeySecret = "tfs_test_secret"
		assert.Equal(t, "tfs_test_secret", cfg.GetEffectiveAPIKeySecret())
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

func TestNewLoader(t *testing.T) {
	t.Run("should create loader with default config paths", func(t *testing.T) {
		loader := config.NewLoader()

		require.NotNil(t, loader)
	})
}

func TestLoaderWithConfigPaths(t *testing.T) {
	t.Run("should add additional config paths", func(t *testing.T) {
		loader := config.NewLoader().WithConfigPaths("/custom/path", "/another/path")

		require.NotNil(t, loader)
	})
}

func TestLoaderWithEnvPrefix(t *testing.T) {
	t.Run("should set custom env prefix", func(t *testing.T) {
		loader := config.NewLoader().WithEnvPrefix("CUSTOM")

		require.NotNil(t, loader)
	})
}

func TestLoaderLoad(t *testing.T) {
	t.Run("should load config with defaults when no file found", func(t *testing.T) {
		loader := config.NewLoader().WithConfigPaths("/nonexistent/path")

		cfg, err := loader.Load("")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Should have default TelemetryFlow endpoint
		assert.Equal(t, "localhost:4317", cfg.TelemetryFlow.Endpoint)
		assert.Equal(t, "grpc", cfg.TelemetryFlow.Protocol)
	})

	t.Run("should load config from explicit file path", func(t *testing.T) {
		// Create temporary config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
telemetryflow:
  endpoint: "custom-host:4317"
  protocol: "http"
heartbeat:
  interval: 30s
logging:
  level: debug
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		cfg, err := loader.Load(configPath)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "custom-host:4317", cfg.TelemetryFlow.Endpoint)
		assert.Equal(t, "http", cfg.TelemetryFlow.Protocol)
		assert.Equal(t, "debug", cfg.Logging.Level)
	})

	t.Run("should fail with invalid config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yaml")

		// Write invalid YAML
		err := os.WriteFile(configPath, []byte("invalid: yaml: content:::"), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		_, err = loader.Load(configPath)
		assert.Error(t, err)
	})

	t.Run("should fail validation with missing endpoint", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		// Config with empty endpoint
		configContent := `
telemetryflow:
  endpoint: ""
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		_, err = loader.Load(configPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "telemetryflow.endpoint is required")
	})

	t.Run("should auto-detect hostname when not set", func(t *testing.T) {
		loader := config.NewLoader().WithConfigPaths("/nonexistent/path")

		cfg, err := loader.Load("")
		require.NoError(t, err)

		// Hostname should be auto-detected
		expectedHostname, _ := os.Hostname()
		assert.Equal(t, expectedHostname, cfg.Agent.Hostname)
	})
}

func TestLoaderLoadFromFile(t *testing.T) {
	t.Run("should load config from absolute file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
telemetryflow:
  endpoint: "test-endpoint:4317"
  api_key_id: "tfk_test"
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		cfg, err := loader.LoadFromFile(configPath)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "test-endpoint:4317", cfg.TelemetryFlow.Endpoint)
		assert.Equal(t, "tfk_test", cfg.TelemetryFlow.APIKeyID)
	})

	t.Run("should handle relative file path", func(t *testing.T) {
		// Create temp file in current directory
		tmpFile, err := os.CreateTemp(".", "tfo-agent-*.yaml")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(tmpFile.Name()) })

		configContent := `
telemetryflow:
  endpoint: "relative-test:4317"
`
		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		loader := config.NewLoader()
		cfg, err := loader.LoadFromFile(tmpFile.Name())
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "relative-test:4317", cfg.TelemetryFlow.Endpoint)
	})
}

func TestLoaderEnvironmentVariables(t *testing.T) {
	t.Run("should override config with environment variables", func(t *testing.T) {
		// Set environment variables
		t.Setenv("TELEMETRYFLOW_LOG_LEVEL", "error")

		loader := config.NewLoader().WithConfigPaths("/nonexistent/path")
		cfg, err := loader.Load("")
		require.NoError(t, err)

		assert.Equal(t, "error", cfg.Logging.Level)
	})

	t.Run("should use TELEMETRYFLOW_HOSTNAME env var", func(t *testing.T) {
		t.Setenv("TELEMETRYFLOW_HOSTNAME", "env-hostname")

		loader := config.NewLoader().WithConfigPaths("/nonexistent/path")
		cfg, err := loader.Load("")
		require.NoError(t, err)

		assert.Equal(t, "env-hostname", cfg.Agent.Hostname)
	})
}

func TestLoaderCollectorConfig(t *testing.T) {
	t.Run("should load collector configuration", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
telemetryflow:
  endpoint: "localhost:4317"
collectors:
  system:
    enabled: true
    interval: 30s
    cpu: true
    memory: true
    disk: false
    network: false
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		cfg, err := loader.Load(configPath)
		require.NoError(t, err)

		assert.True(t, cfg.Collector.System.Enabled)
		assert.True(t, cfg.Collector.System.CPU)
		assert.True(t, cfg.Collector.System.Memory)
		assert.False(t, cfg.Collector.System.Disk)
		assert.False(t, cfg.Collector.System.Network)
	})
}

func TestLoaderExporterConfig(t *testing.T) {
	t.Run("should load exporter configuration", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
telemetryflow:
  endpoint: "localhost:4317"
exporter:
  otlp:
    enabled: true
    batch_size: 200
    compression: "gzip"
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		cfg, err := loader.Load(configPath)
		require.NoError(t, err)

		assert.True(t, cfg.Exporter.OTLP.Enabled)
		assert.Equal(t, 200, cfg.Exporter.OTLP.BatchSize)
		assert.Equal(t, "gzip", cfg.Exporter.OTLP.Compression)
	})
}

func TestLoaderBufferConfig(t *testing.T) {
	t.Run("should load buffer configuration", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
telemetryflow:
  endpoint: "localhost:4317"
buffer:
  enabled: true
  max_size_mb: 200
  path: "/custom/buffer/path"
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		cfg, err := loader.Load(configPath)
		require.NoError(t, err)

		assert.True(t, cfg.Buffer.Enabled)
		assert.Equal(t, int64(200), cfg.Buffer.MaxSizeMB)
		assert.Equal(t, "/custom/buffer/path", cfg.Buffer.Path)
	})
}

func TestLoaderTLSConfig(t *testing.T) {
	t.Run("should load TLS configuration", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "tfo-agent.yaml")

		configContent := `
telemetryflow:
  endpoint: "localhost:4317"
  tls:
    enabled: true
    skip_verify: false
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
    ca_file: "/path/to/ca.pem"
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		loader := config.NewLoader()
		cfg, err := loader.Load(configPath)
		require.NoError(t, err)

		assert.True(t, cfg.TelemetryFlow.TLS.Enabled)
		assert.False(t, cfg.TelemetryFlow.TLS.SkipVerify)
		assert.Equal(t, "/path/to/cert.pem", cfg.TelemetryFlow.TLS.CertFile)
		assert.Equal(t, "/path/to/key.pem", cfg.TelemetryFlow.TLS.KeyFile)
		assert.Equal(t, "/path/to/ca.pem", cfg.TelemetryFlow.TLS.CAFile)
	})
}
