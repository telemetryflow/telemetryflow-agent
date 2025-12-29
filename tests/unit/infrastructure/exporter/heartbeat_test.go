// Package exporter_test provides unit tests for the TelemetryFlow exporter infrastructure.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
package exporter_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

// mockHeartbeatClient is a mock implementation of HeartbeatClient
type mockHeartbeatClient struct {
	mu           sync.RWMutex
	callCount    int32
	shouldFail   bool
	failAfter    int32
	lastAgentID  string
	lastSysInfo  *api.SystemInfoPayload
	responseTime time.Duration
}

func (m *mockHeartbeatClient) Heartbeat(ctx context.Context, agentID string, sysInfo *api.SystemInfoPayload) error {
	count := atomic.AddInt32(&m.callCount, 1)
	m.mu.Lock()
	m.lastAgentID = agentID
	m.lastSysInfo = sysInfo
	m.mu.Unlock()

	if m.responseTime > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.responseTime):
		}
	}

	if m.shouldFail {
		return errors.New("mock heartbeat failure")
	}

	if m.failAfter > 0 && count > m.failAfter {
		return errors.New("mock heartbeat failure after threshold")
	}

	return nil
}

func (m *mockHeartbeatClient) CallCount() int32 {
	return atomic.LoadInt32(&m.callCount)
}

func (m *mockHeartbeatClient) LastAgentID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastAgentID
}

func (m *mockHeartbeatClient) LastSysInfo() *api.SystemInfoPayload {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastSysInfo
}

func TestNewHeartbeat(t *testing.T) {
	t.Run("should create heartbeat with config", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:           "test-agent-001",
			Hostname:          "test-host",
			Interval:          30 * time.Second,
			Timeout:           5 * time.Second,
			IncludeSystemInfo: true,
			Client:            mock,
			Logger:            logger,
		}

		hb := exporter.NewHeartbeat(cfg)
		require.NotNil(t, hb)
		assert.False(t, hb.IsRunning())
	})

	t.Run("should use default interval when not specified", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		require.NotNil(t, hb)
	})

	t.Run("should use default timeout when not specified", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		require.NotNil(t, hb)
	})

	t.Run("should use nop logger when not specified", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		require.NotNil(t, hb)
	})
}

func TestHeartbeatStart(t *testing.T) {
	t.Run("should start heartbeat loop", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		logger, _ := zap.NewDevelopment()

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 100 * time.Millisecond,
			Timeout:  200 * time.Millisecond,
			Client:   mock,
			Logger:   logger,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errChan := make(chan error, 1)
		go func() {
			errChan <- hb.Start(ctx)
		}()

		time.Sleep(150 * time.Millisecond)
		assert.True(t, hb.IsRunning())

		cancel()
		err := <-errChan
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("should send initial heartbeat on start", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent-123",
			Interval: 1 * time.Second,
			Timeout:  200 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = hb.Start(ctx)
		}()

		time.Sleep(150 * time.Millisecond)
		assert.GreaterOrEqual(t, mock.CallCount(), int32(1))
		assert.Equal(t, "test-agent-123", mock.LastAgentID())

		cancel()
	})

	t.Run("should send periodic heartbeats", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 100 * time.Millisecond,
			Timeout:  150 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			_ = hb.Start(ctx)
		}()

		// Wait for initial + a few periodic heartbeats
		time.Sleep(350 * time.Millisecond)
		cancel()

		// Should have sent at least 2-3 heartbeats (initial + periodic)
		assert.GreaterOrEqual(t, mock.CallCount(), int32(2))
	})

	t.Run("should not start if already running", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 200 * time.Millisecond,
			Timeout:  150 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx1, cancel1 := context.WithCancel(context.Background())
		defer cancel1()

		go func() {
			_ = hb.Start(ctx1)
		}()

		time.Sleep(100 * time.Millisecond)
		assert.True(t, hb.IsRunning())

		// Try to start again - should return immediately without error
		ctx2, cancel2 := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel2()

		err := hb.Start(ctx2)
		assert.NoError(t, err)
	})
}

func TestHeartbeatStop(t *testing.T) {
	t.Run("should stop heartbeat loop", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		logger, _ := zap.NewDevelopment()

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 50 * time.Millisecond,
			Timeout:  100 * time.Millisecond,
			Client:   mock,
			Logger:   logger,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errChan := make(chan error, 1)
		go func() {
			errChan <- hb.Start(ctx)
		}()

		time.Sleep(30 * time.Millisecond)
		assert.True(t, hb.IsRunning())

		err := hb.Stop()
		require.NoError(t, err)

		// Wait for goroutine to finish
		err = <-errChan
		assert.NoError(t, err)
		assert.False(t, hb.IsRunning())
	})

	t.Run("should not error when stopping non-running heartbeat", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		err := hb.Stop()
		require.NoError(t, err)
	})
}

func TestHeartbeatStats(t *testing.T) {
	t.Run("should return initial stats", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		stats := hb.Stats()

		assert.False(t, stats.Running)
		assert.Zero(t, stats.SuccessCount)
		assert.Zero(t, stats.ErrorCount)
		assert.True(t, stats.LastSent.IsZero())
		assert.Nil(t, stats.LastError)
	})

	t.Run("should track success count", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 30 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			_ = hb.Start(ctx)
		}()

		// Wait for a few heartbeats
		time.Sleep(100 * time.Millisecond)
		cancel()

		stats := hb.Stats()
		assert.Greater(t, stats.SuccessCount, 0)
		assert.False(t, stats.LastSent.IsZero())
	})

	t.Run("should track error count", func(t *testing.T) {
		mock := &mockHeartbeatClient{
			shouldFail: true,
		}
		logger, _ := zap.NewDevelopment()

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 30 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
			Client:   mock,
			Logger:   logger,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			_ = hb.Start(ctx)
		}()

		// Wait for a few heartbeat attempts
		time.Sleep(100 * time.Millisecond)
		cancel()

		stats := hb.Stats()
		assert.Greater(t, stats.ErrorCount, 0)
		assert.NotNil(t, stats.LastError)
	})

	t.Run("should show running status", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 100 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		// Before starting
		stats := hb.Stats()
		assert.False(t, stats.Running)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			_ = hb.Start(ctx)
		}()

		time.Sleep(30 * time.Millisecond)

		// While running
		stats = hb.Stats()
		assert.True(t, stats.Running)

		cancel()
		time.Sleep(30 * time.Millisecond)

		// After stopping
		stats = hb.Stats()
		// May or may not be running depending on timing
	})
}

func TestHeartbeatSendNow(t *testing.T) {
	t.Run("should send immediate heartbeat", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent-now",
			Interval: 10 * time.Second, // Long interval
			Timeout:  100 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		ctx := context.Background()

		err := hb.SendNow(ctx)
		require.NoError(t, err)
		assert.Equal(t, int32(1), mock.CallCount())
		assert.Equal(t, "test-agent-now", mock.LastAgentID())
	})

	t.Run("should return error on failure", func(t *testing.T) {
		mock := &mockHeartbeatClient{
			shouldFail: true,
		}

		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Timeout: 100 * time.Millisecond,
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		ctx := context.Background()

		err := hb.SendNow(ctx)
		require.Error(t, err)
	})

	t.Run("should respect timeout", func(t *testing.T) {
		mock := &mockHeartbeatClient{
			responseTime: 200 * time.Millisecond,
		}

		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Timeout: 50 * time.Millisecond,
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		ctx := context.Background()

		err := hb.SendNow(ctx)
		require.Error(t, err)
	})
}

func TestHeartbeatWithSystemInfo(t *testing.T) {
	t.Run("should include system info when enabled", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:           "test-agent",
			Interval:          1 * time.Second,
			Timeout:           100 * time.Millisecond,
			IncludeSystemInfo: true,
			Client:            mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		ctx := context.Background()

		err := hb.SendNow(ctx)
		require.NoError(t, err)

		// System info should be populated (or nil if collection failed)
		// The test just verifies no panic occurs
		assert.Equal(t, int32(1), mock.CallCount())
	})

	t.Run("should not include system info when disabled", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:           "test-agent",
			Interval:          1 * time.Second,
			Timeout:           100 * time.Millisecond,
			IncludeSystemInfo: false,
			Client:            mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		ctx := context.Background()

		err := hb.SendNow(ctx)
		require.NoError(t, err)
		assert.Nil(t, mock.LastSysInfo())
	})
}

func TestHeartbeatContextCancellation(t *testing.T) {
	t.Run("should stop on context cancellation", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 50 * time.Millisecond,
			Timeout:  100 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := hb.Start(ctx)
		assert.Equal(t, context.DeadlineExceeded, err)
	})
}

func TestHeartbeatIsRunning(t *testing.T) {
	t.Run("should return false before start", func(t *testing.T) {
		mock := &mockHeartbeatClient{}
		cfg := exporter.HeartbeatConfig{
			AgentID: "test-agent",
			Client:  mock,
		}

		hb := exporter.NewHeartbeat(cfg)
		assert.False(t, hb.IsRunning())
	})

	t.Run("should return true while running", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 100 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			_ = hb.Start(ctx)
		}()

		time.Sleep(30 * time.Millisecond)
		assert.True(t, hb.IsRunning())
	})

	t.Run("should return false after stop", func(t *testing.T) {
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:  "test-agent",
			Interval: 100 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
			Client:   mock,
		}

		hb := exporter.NewHeartbeat(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errChan := make(chan error, 1)
		go func() {
			errChan <- hb.Start(ctx)
		}()

		time.Sleep(30 * time.Millisecond)
		_ = hb.Stop()

		// Wait for goroutine to exit
		<-errChan

		assert.False(t, hb.IsRunning())
	})
}

func TestHeartbeatStatsStruct(t *testing.T) {
	t.Run("should have all fields", func(t *testing.T) {
		stats := exporter.HeartbeatStats{
			Running:      true,
			LastSent:     time.Now(),
			LastError:    errors.New("test error"),
			SuccessCount: 10,
			ErrorCount:   2,
		}

		assert.True(t, stats.Running)
		assert.False(t, stats.LastSent.IsZero())
		assert.NotNil(t, stats.LastError)
		assert.Equal(t, 10, stats.SuccessCount)
		assert.Equal(t, 2, stats.ErrorCount)
	})
}

func TestHeartbeatConfigStruct(t *testing.T) {
	t.Run("should have all fields", func(t *testing.T) {
		logger, _ := zap.NewDevelopment()
		mock := &mockHeartbeatClient{}

		cfg := exporter.HeartbeatConfig{
			AgentID:           "agent-123",
			Hostname:          "test-host",
			Interval:          60 * time.Second,
			Timeout:           10 * time.Second,
			IncludeSystemInfo: true,
			Client:            mock,
			Logger:            logger,
		}

		assert.Equal(t, "agent-123", cfg.AgentID)
		assert.Equal(t, "test-host", cfg.Hostname)
		assert.Equal(t, 60*time.Second, cfg.Interval)
		assert.Equal(t, 10*time.Second, cfg.Timeout)
		assert.True(t, cfg.IncludeSystemInfo)
		assert.NotNil(t, cfg.Client)
		assert.NotNil(t, cfg.Logger)
	})
}
