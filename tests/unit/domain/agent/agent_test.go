// Package agent_test provides unit tests for the agent domain.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package agent_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/agent"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestNew(t *testing.T) {
	t.Run("should create agent with default config", func(t *testing.T) {
		cfg := config.DefaultConfig()
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)
		assert.NotNil(t, ag)
		assert.NotEmpty(t, ag.ID())
	})

	t.Run("should use provided agent ID", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.ID = "test-agent-123"
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)
		assert.Equal(t, "test-agent-123", ag.ID())
	})
}

func TestAgentLifecycle(t *testing.T) {
	t.Run("should start and stop gracefully", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = false // Disable for test
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Start agent in goroutine
		errChan := make(chan error, 1)
		go func() {
			errChan <- ag.Run(ctx)
		}()

		// Wait briefly then cancel
		time.Sleep(100 * time.Millisecond)
		assert.True(t, ag.IsRunning())

		cancel()

		// Should shutdown gracefully
		err = <-errChan
		assert.NoError(t, err)
		assert.False(t, ag.IsRunning())
	})

	t.Run("should not start twice", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = false
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		ctx1, cancel1 := context.WithCancel(context.Background())
		defer cancel1()

		// Start first instance
		go func() {
			_ = ag.Run(ctx1)
		}()

		time.Sleep(50 * time.Millisecond)

		// Try to start second instance
		ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel2()

		err = ag.Run(ctx2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already running")
	})
}

func TestAgentStats(t *testing.T) {
	t.Run("should return correct stats", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.Hostname = "test-host"
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		stats := ag.Stats()
		assert.Equal(t, ag.ID(), stats.ID)
		assert.Equal(t, "test-host", stats.Hostname)
		assert.False(t, stats.Running)
		assert.Zero(t, stats.Uptime)
	})

	t.Run("should track uptime when running", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = false
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = ag.Run(ctx)
		}()

		time.Sleep(100 * time.Millisecond)

		stats := ag.Stats()
		assert.True(t, stats.Running)
		assert.Greater(t, stats.Uptime, time.Duration(0))

		uptime1 := ag.Uptime()
		assert.Greater(t, uptime1, time.Duration(0))

		cancel()
		time.Sleep(50 * time.Millisecond)

		assert.Zero(t, ag.Uptime())
	})

	t.Run("should return collector count in stats", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = true
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		stats := ag.Stats()
		assert.Equal(t, 1, stats.CollectorCount)
	})

	t.Run("should return zero collectors when disabled", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = false
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		stats := ag.Stats()
		assert.Equal(t, 0, stats.CollectorCount)
	})
}

func TestAgentWithCollectors(t *testing.T) {
	t.Run("should create agent with system collector enabled", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = true
		cfg.Collector.System.CPU = true
		cfg.Collector.System.Memory = true
		cfg.Collector.System.Disk = true
		cfg.Collector.System.Network = true
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)
		assert.NotNil(t, ag)

		stats := ag.Stats()
		assert.Equal(t, 1, stats.CollectorCount)
	})

	t.Run("should run agent with system collector", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = true
		cfg.Collector.System.Interval = 100 * time.Millisecond
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		errChan := make(chan error, 1)
		go func() {
			errChan <- ag.Run(ctx)
		}()

		// Let it run briefly
		time.Sleep(200 * time.Millisecond)
		assert.True(t, ag.IsRunning())

		cancel()

		err = <-errChan
		assert.NoError(t, err)
	})
}

func TestAgentShutdown(t *testing.T) {
	t.Run("should shutdown gracefully with no collectors", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = false
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())

		errChan := make(chan error, 1)
		go func() {
			errChan <- ag.Run(ctx)
		}()

		time.Sleep(50 * time.Millisecond)
		cancel()

		err = <-errChan
		assert.NoError(t, err)
		assert.False(t, ag.IsRunning())
	})

	t.Run("should shutdown gracefully with collectors", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = true
		cfg.Collector.System.Interval = 100 * time.Millisecond
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())

		errChan := make(chan error, 1)
		go func() {
			errChan <- ag.Run(ctx)
		}()

		time.Sleep(150 * time.Millisecond)
		assert.True(t, ag.IsRunning())

		cancel()

		err = <-errChan
		assert.NoError(t, err)
		assert.False(t, ag.IsRunning())
	})
}

func TestAgentConfiguration(t *testing.T) {
	t.Run("should use custom hostname", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.Hostname = "custom-hostname"
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		stats := ag.Stats()
		assert.Equal(t, "custom-hostname", stats.Hostname)
	})

	t.Run("should use TelemetryFlow endpoint config", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.Endpoint = "custom-endpoint:4317"
		cfg.TelemetryFlow.APIKeyID = "tfk_test"
		cfg.TelemetryFlow.APIKeySecret = "tfs_test"
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)
		assert.NotNil(t, ag)
	})

	t.Run("should configure TLS settings", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.TelemetryFlow.TLS.Enabled = true
		cfg.TelemetryFlow.TLS.SkipVerify = true
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)
		assert.NotNil(t, ag)
	})

	t.Run("should configure heartbeat settings", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Heartbeat.Interval = 30 * time.Second
		cfg.Heartbeat.Timeout = 5 * time.Second
		cfg.Heartbeat.IncludeSystemInfo = true
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)
		assert.NotNil(t, ag)
	})

	t.Run("should configure collector disk paths", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = true
		cfg.Collector.System.DiskPaths = []string{"/", "/home"}
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		stats := ag.Stats()
		assert.Equal(t, 1, stats.CollectorCount)
	})
}

func TestAgentStatsStruct(t *testing.T) {
	t.Run("should have all fields", func(t *testing.T) {
		stats := agent.AgentStats{
			ID:             "test-id",
			Hostname:       "test-host",
			Running:        true,
			Started:        time.Now(),
			Uptime:         5 * time.Minute,
			CollectorCount: 2,
		}

		assert.Equal(t, "test-id", stats.ID)
		assert.Equal(t, "test-host", stats.Hostname)
		assert.True(t, stats.Running)
		assert.False(t, stats.Started.IsZero())
		assert.Equal(t, 5*time.Minute, stats.Uptime)
		assert.Equal(t, 2, stats.CollectorCount)
	})
}
