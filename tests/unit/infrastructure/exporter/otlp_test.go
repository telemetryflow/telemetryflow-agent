// Package exporter_test provides unit tests for the TelemetryFlow OTLP exporter infrastructure.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package exporter_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func TestOTLPExporter(t *testing.T) {
	t.Run("should create OTLP exporter with config", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "test-agent-001",
			AgentName:     "Test Agent",
			Hostname:      "test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			APIKeyID:      "tfk_test_key",
			APIKeySecret:  "tfs_test_secret",
			TLSEnabled:    false,
			TLSSkipVerify: false,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       30 * time.Second,
			Compression:   true,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
		assert.False(t, exp.IsRunning())
	})

	t.Run("should create OTLP exporter with nil logger", func(t *testing.T) {
		cfg := exporter.OTLPExporterConfig{
			AgentID:  "test-agent-002",
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Logger:   nil, // Will use production logger
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
	})

	t.Run("should return not running initially", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:  "test-agent-003",
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Logger:   logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		assert.False(t, exp.IsRunning())
	})

	t.Run("should return initial stats", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:  "test-agent-004",
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Logger:   logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		stats := exp.Stats()

		assert.False(t, stats.Running)
		assert.Zero(t, stats.ExportCount)
		assert.Zero(t, stats.ErrorCount)
		assert.Nil(t, stats.LastError)
		assert.Zero(t, stats.MetricsSent)
		assert.Zero(t, stats.BytesSent)
	})

	t.Run("should return nil meter before start", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:  "test-agent-005",
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Logger:   logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		meter := exp.Meter()
		assert.Nil(t, meter)
	})

	t.Run("should fail start with unsupported protocol", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:  "test-agent-006",
			Endpoint: "localhost:4317",
			Protocol: "invalid-protocol",
			Logger:   logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		err := exp.Start(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported protocol")
	})

	t.Run("should not allow double start", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "test-agent-007",
			AgentName:     "Test Agent",
			Hostname:      "test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// First start - may fail due to connection, but sets running state
		_ = exp.Start(ctx)

		// If it's running, second start should fail
		if exp.IsRunning() {
			err := exp.Start(ctx)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "already running")
		}
	})

	t.Run("should stop gracefully when not running", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:  "test-agent-008",
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Logger:   logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		err := exp.Stop(ctx)
		assert.NoError(t, err)
	})
}

func TestOTLPExporterConfig(t *testing.T) {
	t.Run("should have all config fields", func(t *testing.T) {
		cfg := exporter.OTLPExporterConfig{
			AgentID:       "agent-id",
			AgentName:     "Agent Name",
			Hostname:      "hostname",
			Environment:   "production",
			Version:       "1.0.0",
			Endpoint:      "otlp.example.com:4317",
			Protocol:      "grpc",
			APIKeyID:      "tfk_xxx",
			APIKeySecret:  "tfs_xxx",
			TLSEnabled:    true,
			TLSSkipVerify: false,
			BatchSize:     200,
			FlushInterval: 15 * time.Second,
			Timeout:       60 * time.Second,
			Compression:   true,
		}

		assert.Equal(t, "agent-id", cfg.AgentID)
		assert.Equal(t, "Agent Name", cfg.AgentName)
		assert.Equal(t, "hostname", cfg.Hostname)
		assert.Equal(t, "production", cfg.Environment)
		assert.Equal(t, "1.0.0", cfg.Version)
		assert.Equal(t, "otlp.example.com:4317", cfg.Endpoint)
		assert.Equal(t, "grpc", cfg.Protocol)
		assert.Equal(t, "tfk_xxx", cfg.APIKeyID)
		assert.Equal(t, "tfs_xxx", cfg.APIKeySecret)
		assert.True(t, cfg.TLSEnabled)
		assert.False(t, cfg.TLSSkipVerify)
		assert.Equal(t, 200, cfg.BatchSize)
		assert.Equal(t, 15*time.Second, cfg.FlushInterval)
		assert.Equal(t, 60*time.Second, cfg.Timeout)
		assert.True(t, cfg.Compression)
	})
}

func TestOTLPExporterStats(t *testing.T) {
	t.Run("should have all stats fields", func(t *testing.T) {
		now := time.Now()
		stats := exporter.OTLPExporterStats{
			Running:      true,
			ExportCount:  100,
			ErrorCount:   5,
			LastExportAt: now,
			LastError:    nil,
			LastErrorAt:  time.Time{},
			MetricsSent:  1000,
			BytesSent:    50000,
		}

		assert.True(t, stats.Running)
		assert.Equal(t, int64(100), stats.ExportCount)
		assert.Equal(t, int64(5), stats.ErrorCount)
		assert.Equal(t, now, stats.LastExportAt)
		assert.Nil(t, stats.LastError)
		assert.Equal(t, int64(1000), stats.MetricsSent)
		assert.Equal(t, int64(50000), stats.BytesSent)
	})
}

func TestNewOTLPExporterFromConfig(t *testing.T) {
	t.Run("should create exporter from agent config", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := config.DefaultConfig()
		cfg.Agent.ID = "config-agent-001"
		cfg.Agent.Name = "Config Test Agent"
		cfg.Agent.Hostname = "config-test-host"
		cfg.Agent.Version = "2.0.0"
		cfg.Agent.Tags = map[string]string{"environment": "staging"}
		cfg.TelemetryFlow.Endpoint = "otlp.test.com:4317"
		cfg.TelemetryFlow.Protocol = "grpc"
		cfg.TelemetryFlow.APIKeyID = "tfk_config_key"
		cfg.TelemetryFlow.APIKeySecret = "tfs_config_secret"
		cfg.TelemetryFlow.TLS.Enabled = true
		cfg.TelemetryFlow.TLS.SkipVerify = false
		cfg.Exporter.OTLP.BatchSize = 150
		cfg.Exporter.OTLP.FlushInterval = 20 * time.Second
		cfg.Exporter.OTLP.Compression = "gzip"

		exp := exporter.NewOTLPExporterFromConfig(cfg, logger)
		require.NotNil(t, exp)
		assert.False(t, exp.IsRunning())
	})

	t.Run("should create exporter with http protocol", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Protocol = "http"
		cfg.TelemetryFlow.Endpoint = "otlp.test.com:4318"

		exp := exporter.NewOTLPExporterFromConfig(cfg, logger)
		require.NotNil(t, exp)
	})

	t.Run("should default to grpc when protocol empty", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Protocol = ""

		exp := exporter.NewOTLPExporterFromConfig(cfg, logger)
		require.NotNil(t, exp)
	})

	t.Run("should handle compression setting", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := config.DefaultConfig()
		cfg.Exporter.OTLP.Compression = "gzip"

		exp := exporter.NewOTLPExporterFromConfig(cfg, logger)
		require.NotNil(t, exp)
	})

	t.Run("should handle no compression", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := config.DefaultConfig()
		cfg.Exporter.OTLP.Compression = "none"

		exp := exporter.NewOTLPExporterFromConfig(cfg, logger)
		require.NotNil(t, exp)
	})

	t.Run("should handle TLS skip verify", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.TLS.Enabled = true
		cfg.TelemetryFlow.TLS.SkipVerify = true

		exp := exporter.NewOTLPExporterFromConfig(cfg, logger)
		require.NotNil(t, exp)
	})

	t.Run("should handle nil logger", func(t *testing.T) {
		cfg := config.DefaultConfig()

		exp := exporter.NewOTLPExporterFromConfig(cfg, nil)
		require.NotNil(t, exp)
	})
}

func TestOTLPExporterGRPCProtocol(t *testing.T) {
	t.Run("should create gRPC exporter with TLS disabled", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "grpc-test-001",
			AgentName:     "gRPC Test Agent",
			Hostname:      "grpc-test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       5 * time.Second,
			Compression:   false,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
	})

	t.Run("should create gRPC exporter with TLS enabled", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "grpc-test-002",
			AgentName:     "gRPC TLS Test Agent",
			Hostname:      "grpc-tls-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    true,
			TLSSkipVerify: true,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       5 * time.Second,
			Compression:   true,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
	})

	t.Run("should create gRPC exporter with auth headers", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "grpc-test-003",
			AgentName:     "gRPC Auth Test Agent",
			Hostname:      "grpc-auth-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			APIKeyID:      "tfk_grpc_key",
			APIKeySecret:  "tfs_grpc_secret",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
	})
}

func TestOTLPExporterHTTPProtocol(t *testing.T) {
	t.Run("should create HTTP exporter with TLS disabled", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "http-test-001",
			AgentName:     "HTTP Test Agent",
			Hostname:      "http-test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4318",
			Protocol:      "http",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       5 * time.Second,
			Compression:   false,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
	})

	t.Run("should create HTTP exporter with TLS enabled", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "http-test-002",
			AgentName:     "HTTP TLS Test Agent",
			Hostname:      "http-tls-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4318",
			Protocol:      "http",
			TLSEnabled:    true,
			TLSSkipVerify: true,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       5 * time.Second,
			Compression:   true,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
	})

	t.Run("should create HTTP exporter with auth headers", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "http-test-003",
			AgentName:     "HTTP Auth Test Agent",
			Hostname:      "http-auth-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4318",
			Protocol:      "http",
			APIKeyID:      "tfk_http_key",
			APIKeySecret:  "tfs_http_secret",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 10 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		require.NotNil(t, exp)
	})
}

func TestOTLPExporterLifecycle(t *testing.T) {
	t.Run("should handle stop without start", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:  "lifecycle-001",
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Logger:   logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Stop without start should not error
		err := exp.Stop(ctx)
		assert.NoError(t, err)
		assert.False(t, exp.IsRunning())
	})

	t.Run("should handle multiple stops", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:  "lifecycle-002",
			Endpoint: "localhost:4317",
			Protocol: "grpc",
			Logger:   logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Multiple stops should not error
		err := exp.Stop(ctx)
		assert.NoError(t, err)

		err = exp.Stop(ctx)
		assert.NoError(t, err)
	})

	t.Run("should start and stop with gRPC protocol", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "lifecycle-003",
			AgentName:     "Lifecycle Test Agent",
			Hostname:      "lifecycle-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Start exporter
		err := exp.Start(ctx)
		require.NoError(t, err)
		assert.True(t, exp.IsRunning())

		// Verify meter is available after start
		meter := exp.Meter()
		assert.NotNil(t, meter)

		// Stop exporter - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)
		assert.False(t, exp.IsRunning())
	})

	t.Run("should start and stop with HTTP protocol", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "lifecycle-004",
			AgentName:     "HTTP Lifecycle Agent",
			Hostname:      "http-lifecycle-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4318",
			Protocol:      "http",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Start exporter
		err := exp.Start(ctx)
		require.NoError(t, err)
		assert.True(t, exp.IsRunning())

		// Stop exporter - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)
		assert.False(t, exp.IsRunning())
	})

	t.Run("should start with TLS and compression", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "lifecycle-005",
			AgentName:     "TLS Compression Agent",
			Hostname:      "tls-compress-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    true,
			TLSSkipVerify: true,
			BatchSize:     100,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Compression:   true,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Start exporter
		err := exp.Start(ctx)
		require.NoError(t, err)
		assert.True(t, exp.IsRunning())

		// Stop exporter - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)
	})

	t.Run("should start HTTP with TLS and auth", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "lifecycle-006",
			AgentName:     "HTTP TLS Auth Agent",
			Hostname:      "http-tls-auth-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4318",
			Protocol:      "http",
			APIKeyID:      "tfk_test_key",
			APIKeySecret:  "tfs_test_secret",
			TLSEnabled:    true,
			TLSSkipVerify: true,
			BatchSize:     100,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Compression:   true,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Start exporter
		err := exp.Start(ctx)
		require.NoError(t, err)
		assert.True(t, exp.IsRunning())

		// Stop exporter - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)
	})

	t.Run("should start gRPC with auth headers", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "lifecycle-007",
			AgentName:     "gRPC Auth Agent",
			Hostname:      "grpc-auth-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			APIKeyID:      "tfk_grpc_key",
			APIKeySecret:  "tfs_grpc_secret",
			TLSEnabled:    false,
			BatchSize:     100,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Start exporter
		err := exp.Start(ctx)
		require.NoError(t, err)
		assert.True(t, exp.IsRunning())

		// Stop exporter - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)
	})
}

func TestOTLPExporterIsRunning(t *testing.T) {
	t.Run("should be thread-safe", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "running-001",
			AgentName:     "Running Test Agent",
			Hostname:      "running-test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Start
		err := exp.Start(ctx)
		require.NoError(t, err)

		// Check running from multiple goroutines
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				_ = exp.IsRunning()
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		// Stop - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)
	})
}

func TestOTLPExporterStatsAfterStart(t *testing.T) {
	t.Run("should show running status after start", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "stats-001",
			AgentName:     "Stats Test Agent",
			Hostname:      "stats-test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Stats before start
		statsBefore := exp.Stats()
		assert.False(t, statsBefore.Running)

		// Start
		err := exp.Start(ctx)
		require.NoError(t, err)

		// Stats after start
		statsAfter := exp.Stats()
		assert.True(t, statsAfter.Running)

		// Stop - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)

		// Stats after stop
		statsStop := exp.Stats()
		assert.False(t, statsStop.Running)
	})
}

func TestOTLPExporterMeter(t *testing.T) {
	t.Run("should return meter after start", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "meter-001",
			AgentName:     "Meter Test Agent",
			Hostname:      "meter-test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			FlushInterval: 1 * time.Second,
			Timeout:       5 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)
		ctx := context.Background()

		// Meter before start should be nil
		meterBefore := exp.Meter()
		assert.Nil(t, meterBefore)

		// Start
		err := exp.Start(ctx)
		require.NoError(t, err)

		// Meter after start should not be nil
		meterAfter := exp.Meter()
		assert.NotNil(t, meterAfter)

		// Stop - may error if no server is running (connection refused on flush)
		_ = exp.Stop(ctx)
	})
}

func TestOTLPExporterContextCancellation(t *testing.T) {
	t.Run("should handle context cancellation during start", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "ctx-001",
			AgentName:     "Context Test Agent",
			Hostname:      "ctx-test-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			FlushInterval: 1 * time.Second,
			Timeout:       1 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)

		// Create canceled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Start with canceled context - may error
		_ = exp.Start(ctx)

		// Cleanup - always stop regardless of start result
		_ = exp.Stop(context.Background())
	})

	t.Run("should handle stop with timeout context", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()

		cfg := exporter.OTLPExporterConfig{
			AgentID:       "ctx-002",
			AgentName:     "Context Timeout Agent",
			Hostname:      "ctx-timeout-host",
			Environment:   "test",
			Version:       "1.0.0",
			Endpoint:      "localhost:4317",
			Protocol:      "grpc",
			TLSEnabled:    false,
			FlushInterval: 100 * time.Millisecond,
			Timeout:       1 * time.Second,
			Logger:        logger,
		}

		exp := exporter.NewOTLPExporter(cfg)

		// Use timeout context for start
		startCtx, startCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer startCancel()

		// Start - may fail due to no server, but that's expected
		err := exp.Start(startCtx)
		require.NoError(t, err)

		// Stop with very short timeout - expect it may error due to flush timeout
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer stopCancel()

		// Stop may error due to timeout during flush - this is expected behavior
		err = exp.Stop(stopCtx)
		// Don't assert on error - timeout during shutdown is acceptable
		if err != nil {
			assert.Contains(t, err.Error(), "deadline exceeded")
		}

		// Verify exporter is no longer running regardless of shutdown error
		assert.False(t, exp.IsRunning())
	})
}
