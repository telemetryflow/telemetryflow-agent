package exporter_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
	"github.com/telemetryflow/telemetryflow-agent/tests/mocks"
)

func TestHeartbeat(t *testing.T) {
	t.Run("should create heartbeat exporter", func(t *testing.T) {
		mockClient := mocks.NewMockAPIClient()
		logger, _ := zap.NewDevelopment()

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Hostname: "test-host",
			Interval: time.Second,
			Timeout:  500 * time.Millisecond,
			Client:   mockClient,
			Logger:   logger,
		}

		h := exporter.NewHeartbeat(cfg)
		require.NotNil(t, h)
		assert.False(t, h.IsRunning())
	})

	t.Run("should start and stop heartbeat", func(t *testing.T) {
		mockClient := mocks.NewMockAPIClient()
		logger, _ := zap.NewDevelopment()

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Hostname: "test-host",
			Interval: 100 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
			Client:   mockClient,
			Logger:   logger,
		}

		// Mock successful heartbeat
		mockClient.On("Heartbeat", mock.Anything, "test-agent", (*api.SystemInfoPayload)(nil)).Return(nil)

		h := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		// Start heartbeat
		errChan := make(chan error, 1)
		go func() {
			errChan <- h.Start(ctx)
		}()

		time.Sleep(50 * time.Millisecond)
		assert.True(t, h.IsRunning())

		// Stop heartbeat
		err := h.Stop()
		assert.NoError(t, err)
		assert.False(t, h.IsRunning())

		// Wait for context cancellation
		cancel()
		err = <-errChan
		assert.Error(t, err) // Should be context.Canceled
	})

	t.Run("should send immediate heartbeat", func(t *testing.T) {
		mockClient := mocks.NewMockAPIClient()
		logger, _ := zap.NewDevelopment()

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Hostname: "test-host",
			Client:   mockClient,
			Logger:   logger,
		}

		// Mock heartbeat call
		mockClient.On("Heartbeat", context.Background(), "test-agent", (*api.SystemInfoPayload)(nil)).Return(nil)

		h := exporter.NewHeartbeat(cfg)

		ctx := context.Background()
		err := h.SendNow(ctx)
		assert.NoError(t, err)

		mockClient.AssertExpectations(t)
	})

	t.Run("should return stats", func(t *testing.T) {
		mockClient := mocks.NewMockAPIClient()
		logger, _ := zap.NewDevelopment()

		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Client:  mockClient,
			Logger:  logger,
		}

		h := exporter.NewHeartbeat(cfg)
		stats := h.Stats()

		assert.False(t, stats.Running)
		assert.Zero(t, stats.SuccessCount)
		assert.Zero(t, stats.ErrorCount)
		assert.Nil(t, stats.LastError)
	})
}
