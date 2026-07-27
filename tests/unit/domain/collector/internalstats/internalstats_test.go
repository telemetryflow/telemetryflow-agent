// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package internalstats_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/internalstats"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/selfstat"
)

// resetSelfstat ensures each test starts from an empty registry. selfstat is
// process-global, so cross-test pollution would otherwise corrupt assertions.
func resetSelfstat(t *testing.T) {
	t.Helper()
	selfstat.Reset()
}

func TestInternalStats_Name(t *testing.T) {
	c := internalstats.NewInternalStatsCollector(config.InternalStatsCollectorConfig{}, zap.NewNop())
	assert.Equal(t, "internal", c.Name(), "collector name must be Telegraf-compatible 'internal'")
}

func TestInternalStats_DefaultConfig(t *testing.T) {
	cfg := config.InternalStatsCollectorConfig{}
	require.False(t, cfg.Enabled, "default Enabled should be false")
	require.Zero(t, cfg.Interval, "default Interval should be zero (collector-side default applies at wiring time)")
}

func TestInternalStats_Lifecycle(t *testing.T) {
	resetSelfstat(t)
	c := internalstats.NewInternalStatsCollector(config.InternalStatsCollectorConfig{Enabled: true}, zap.NewNop())

	require.False(t, c.IsRunning(), "should not be running before Start")
	require.NoError(t, c.Start(context.Background()))
	require.True(t, c.IsRunning(), "should be running after Start")

	require.Error(t, c.Start(context.Background()), "double Start should error")

	require.NoError(t, c.Stop())
	require.False(t, c.IsRunning(), "should not be running after Stop")

	// Stop is idempotent.
	require.NoError(t, c.Stop())
}

func TestInternalStats_Collect_ReturnsPopulatedMetrics(t *testing.T) {
	resetSelfstat(t)
	defer resetSelfstat(t)

	// Populate the registry with known stats.
	s := selfstat.RegisterStat("internal.collector.metrics_collected", map[string]string{"collector": "system"})
	s.Incr(7)
	s.Incr(3)

	tm := selfstat.RegisterTimingStat("internal.collector.collect_duration_ns", map[string]string{"collector": "system"})
	tm.Add(1_000_000)

	c := internalstats.NewInternalStatsCollector(config.InternalStatsCollectorConfig{Enabled: true}, zap.NewNop())
	require.NoError(t, c.Start(context.Background()))
	defer func() { _ = c.Stop() }()

	out, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, out, 2, "expected both registered stats emitted")

	names := map[string]collector.Metric{}
	for _, m := range out {
		names[m.Name] = m
	}

	gotStat, ok := names["internal.collector.metrics_collected"]
	require.True(t, ok, "counter stat should be emitted")
	assert.Equal(t, float64(10), gotStat.Value)
	assert.Equal(t, "system", gotStat.Labels["collector"])
	assert.Equal(t, collector.MetricTypeCounter, gotStat.Type)

	gotTiming, ok := names["internal.collector.collect_duration_ns"]
	require.True(t, ok, "timing stat should be emitted")
	assert.Equal(t, float64(1_000_000), gotTiming.Value, "timing stat reports the average sample on Get")
}

func TestInternalStats_Collect_AfterReset_IsEmpty(t *testing.T) {
	resetSelfstat(t)

	// Register a stat, then reset before Collect — should produce no metrics.
	selfstat.RegisterStat("internal.agent.will_be_reset", nil)
	selfstat.Reset()

	c := internalstats.NewInternalStatsCollector(config.InternalStatsCollectorConfig{Enabled: true}, zap.NewNop())
	require.NoError(t, c.Start(context.Background()))
	defer func() { _ = c.Stop() }()

	out, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, out, "expected empty Collect after Reset")
}

func TestInternalStats_Collect_EmptyWhenNothingRegistered(t *testing.T) {
	resetSelfstat(t)
	defer resetSelfstat(t)

	c := internalstats.NewInternalStatsCollector(config.InternalStatsCollectorConfig{Enabled: true}, zap.NewNop())
	require.NoError(t, c.Start(context.Background()))
	defer func() { _ = c.Stop() }()

	out, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, out)
}
