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

func TestAgentIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("should run agent with system collector", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Agent.ID = "integration-test-agent"
		cfg.Collector.System.Enabled = true
		cfg.Collector.System.Interval = 2 * time.Second
		cfg.Heartbeat.Interval = 5 * time.Second

		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Start agent
		errChan := make(chan error, 1)
		go func() {
			errChan <- ag.Run(ctx)
		}()

		// Let it run for a few seconds
		time.Sleep(3 * time.Second)

		// Verify agent is running
		assert.True(t, ag.IsRunning())

		stats := ag.Stats()
		assert.True(t, stats.Running)
		assert.Greater(t, stats.Uptime, time.Duration(0))

		// Stop agent
		cancel()

		// Wait for shutdown
		err = <-errChan
		assert.NoError(t, err) // Graceful shutdown returns nil
		assert.False(t, ag.IsRunning())
	})

	t.Run("should handle multiple start/stop cycles", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Collector.System.Enabled = false // Disable for faster test
		logger, _ := zap.NewDevelopment()

		ag, err := agent.New(cfg, logger)
		require.NoError(t, err)

		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)

			// Start agent and wait for it to be running
			errChan := make(chan error, 1)
			go func() {
				errChan <- ag.Run(ctx)
			}()

			// Wait for agent to start
			for j := 0; j < 10; j++ {
				if ag.IsRunning() {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			assert.True(t, ag.IsRunning())

			// Stop agent and wait for shutdown
			cancel()
			err := <-errChan
			assert.NoError(t, err)
			assert.False(t, ag.IsRunning())
		}
	})
}
