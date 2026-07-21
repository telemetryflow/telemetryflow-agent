// Package cockroachdb_test contains unit tests for the CockroachDB collector.
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
package cockroachdb_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestCollector_NameAndInitialState(t *testing.T) {
	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{}, zap.NewNop())
	assert.Equal(t, "cockroachdb", c.Name())
	assert.False(t, c.IsRunning())
}

func TestCollector_StartStop(t *testing.T) {
	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{{Name: "n1"}},
	}, zap.NewNop())

	// Start blocks until ctx cancels; run it in a goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()

	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	// Second Start while running => error.
	err := c.Start(context.Background())
	assert.Error(t, err)

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
	assert.False(t, c.IsRunning())
}

func TestCollector_StartStopViaStop(t *testing.T) {
	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{}, zap.NewNop())

	// Stop when not running => no-op nil.
	require.NoError(t, c.Stop())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	require.NoError(t, c.Stop())
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
	assert.False(t, c.IsRunning())

	// Idempotent second Stop.
	require.NoError(t, c.Stop())
}

func TestCollector_CollectNoInstances(t *testing.T) {
	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{}, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, metrics)
}

func TestCollector_CollectUnreachableInstance(t *testing.T) {
	// Points at a closed port => connection fails, backoff engages, no panic.
	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{{
			Name:    "dead",
			Host:    "127.0.0.1",
			SQLPort: 1, // nothing listens here
			SSLMode: "disable",
		}},
	}, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err) // Collect swallows per-instance errors
	assert.Empty(t, metrics)

	// Second immediate collect exercises the back-off short-circuit branch.
	metrics2, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics2)

	// Stop closes any (nil) pools cleanly.
	require.NoError(t, c.Stop())
}

func TestCollector_CollectBadConnString(t *testing.T) {
	// An invalid host value that fails pgxpool.ParseConfig.
	c := cockroachdb.NewCockroachDBCollector(config.CockroachDBCollectorConfig{
		Instances: []config.CockroachDBInstanceConfig{{
			Name:    "bad",
			Host:    "bad host with spaces",
			SQLPort: 26257,
			SSLMode: "disable",
		}},
	}, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}
