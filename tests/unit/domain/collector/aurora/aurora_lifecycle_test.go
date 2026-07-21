// Package aurora_test contains unit tests for the Aurora collector module.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aurora_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/aurora"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestStart_RunsAndStopsOnContextCancel(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)

	cfg := baseCollectorConfig()
	cfg.TopologyInterval = 10 * time.Millisecond
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	// Give it time to init clients, run the initial discovery and tick at least once.
	assert.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)
	time.Sleep(40 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
	assert.False(t, c.IsRunning())
}

func TestStart_AlreadyRunning(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)

	cfg := baseCollectorConfig()
	cfg.TopologyInterval = time.Hour
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	assert.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	err := c.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestStart_StopViaStopMethod(t *testing.T) {
	srv := newMockAWSServer(t, mockSuccess)
	setAWSTestEnv(t, srv.URL)
	cfg := baseCollectorConfig()
	cfg.TopologyInterval = time.Hour
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	assert.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	// Stop() (not ctx cancel) closes stopChan and Start returns nil.
	require.NoError(t, c.Stop())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop()")
	}
}

func TestStart_DiscoveryErrorsInitialAndTick(t *testing.T) {
	srv := newMockAWSServer(t, mockError)
	setAWSTestEnv(t, srv.URL)
	cfg := baseCollectorConfig()
	cfg.TopologyInterval = 8 * time.Millisecond
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	assert.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)
	// Initial discovery and at least one tick both fail (logged, not fatal).
	time.Sleep(40 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return")
	}
}

func TestStart_ClientInitFailure(t *testing.T) {
	setBadAWSConfig(t)
	cfg := baseCollectorConfig()
	cfg.TopologyInterval = 8 * time.Millisecond
	c := aurora.NewAuroraCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	// initAWSClients fails; rdsClient stays nil so both the initial discovery
	// and the ticks skip the cluster.
	assert.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)
	time.Sleep(40 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return")
	}
}

func TestStop_WhenNotRunning(t *testing.T) {
	c := aurora.NewAuroraCollector(baseCollectorConfig(), zap.NewNop())
	require.NoError(t, c.Stop())
	require.NoError(t, c.Stop()) // idempotent
}

func TestStart_NoClusters(t *testing.T) {
	c := aurora.NewAuroraCollector(config.AuroraCollectorConfig{}, zap.NewNop())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	require.NoError(t, c.Start(ctx))
	assert.False(t, c.IsRunning())
}
