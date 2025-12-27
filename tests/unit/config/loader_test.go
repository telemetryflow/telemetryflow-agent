// Package config_test provides unit tests for the configuration loader.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

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
