// Package plugincore_test unit-tests the internal/plugin framework: the
// channel/discard accumulators, the legacy-collector and sync-processor
// adapters, and the metric conversion + copy helpers. These are pure,
// dependency-free units, so the tests are table/scenario driven and exercise
// every branch (full-channel drop, nil error, deep copy, flush paths).
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package plugincore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	legacycol "github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// ───────────────────────── stubs ─────────────────────────

type fakeLegacyCollector struct {
	name              string
	started, stopped  bool
	running           bool
	metrics           []legacycol.Metric
	startErr, collErr error
}

func (f *fakeLegacyCollector) Name() string                { return f.name }
func (f *fakeLegacyCollector) Start(context.Context) error { f.started = true; return f.startErr }
func (f *fakeLegacyCollector) Stop() error                 { f.stopped = true; return nil }
func (f *fakeLegacyCollector) IsRunning() bool             { return f.running }
func (f *fakeLegacyCollector) Collect(context.Context) ([]legacycol.Metric, error) {
	if f.collErr != nil {
		return nil, f.collErr
	}
	return f.metrics, nil
}

type fakeSyncProcessor struct {
	name  string
	apply func([]plugin.Metric) []plugin.Metric
}

func (f *fakeSyncProcessor) Name() string { return f.name }
func (f *fakeSyncProcessor) Apply(m []plugin.Metric) []plugin.Metric {
	if f.apply != nil {
		return f.apply(m)
	}
	return m
}

// a plugin.Collector that is NOT a *CollectorAdapter.
type nonAdapterCollector struct{}

func (nonAdapterCollector) Name() string                                     { return "n" }
func (nonAdapterCollector) Start(context.Context) error                      { return nil }
func (nonAdapterCollector) Stop() error                                      { return nil }
func (nonAdapterCollector) Collect(context.Context) ([]plugin.Metric, error) { return nil, nil }
func (nonAdapterCollector) IsRunning() bool                                  { return false }

// ───────────────────────── ChannelAccumulator ─────────────────────────

func TestChannelAccumulator_AddAndTypedHelpers(t *testing.T) {
	ch := make(chan plugin.Metric, 8)
	acc := plugin.NewChannelAccumulator(ch, make(chan error, 8))
	now := time.Unix(1_700_000_000, 0)

	acc.Add(plugin.Metric{Name: "raw", Type: plugin.MetricTypeGauge, Value: 1}) // nil Labels → initialised
	acc.AddFields("f", 2, nil, now)                                             // → counter
	acc.AddGauge("g", 3, map[string]string{"k": "v"}, now)
	acc.AddCounter("c", 4, nil, now)

	require.Len(t, ch, 4)
	m := <-ch
	assert.Equal(t, "raw", m.Name)
	assert.NotNil(t, m.Labels, "Add must initialise nil Labels")
	assert.Equal(t, plugin.MetricTypeCounter, (<-ch).Type) // AddFields
	g := <-ch
	assert.Equal(t, plugin.MetricTypeGauge, g.Type)
	assert.Equal(t, "v", g.Labels["k"])
	c := <-ch
	assert.Equal(t, plugin.MetricTypeCounter, c.Type)
	assert.Equal(t, 4.0, c.Value)
}

func TestChannelAccumulator_FullChannelDropsAndRecords(t *testing.T) {
	ch := make(chan plugin.Metric) // unbuffered, no reader → always full
	errCh := make(chan error, 1)
	acc := plugin.NewChannelAccumulator(ch, errCh)

	acc.Add(plugin.Metric{Name: "x"})

	errs := acc.Errors()
	require.Len(t, errs, 1)
	assert.ErrorIs(t, errs[0], plugin.ErrAccumulatorFull)
	assert.ErrorIs(t, <-errCh, plugin.ErrAccumulatorFull)
}

func TestChannelAccumulator_AddError(t *testing.T) {
	// nil errCh must not panic; nil error is a no-op; Errors() is a copy.
	acc := plugin.NewChannelAccumulator(make(chan plugin.Metric, 1), nil)
	acc.AddError(nil)
	assert.Empty(t, acc.Errors())

	e := errors.New("boom")
	acc.AddError(e)
	snap := acc.Errors()
	require.Len(t, snap, 1)
	assert.ErrorIs(t, snap[0], e)

	acc.AddError(errors.New("second"))
	assert.Len(t, snap, 1, "earlier snapshot must be independent")
	assert.Len(t, acc.Errors(), 2)
}

// ───────────────────────── DiscardAccumulator ─────────────────────────

func TestDiscardAccumulator(t *testing.T) {
	acc := plugin.NewDiscardAccumulator()
	now := time.Now()
	// all Add* variants are silent no-ops.
	acc.Add(plugin.Metric{Name: "x"})
	acc.AddFields("f", 1, nil, now)
	acc.AddGauge("g", 2, map[string]string{"a": "b"}, now)
	acc.AddCounter("c", 3, nil, now)
	assert.Empty(t, acc.Errors())

	acc.AddError(nil)
	assert.Empty(t, acc.Errors())
	acc.AddError(errors.New("e"))
	require.Len(t, acc.Errors(), 1)
}

// ───────────────────────── metric conversion helpers ─────────────────────────

func TestLegacyMetricRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	legacy := legacycol.Metric{
		Name: "sys.cpu", Description: "cpu", Type: legacycol.MetricType("gauge"),
		Value: 42, Timestamp: now, Labels: map[string]string{"host": "h1"}, Unit: "percent",
	}

	pm := plugin.FromLegacyMetric(legacy)
	assert.Equal(t, "sys.cpu", pm.Name)
	assert.Equal(t, plugin.MetricType("gauge"), pm.Type)
	assert.Equal(t, plugin.SignalMetric, pm.Signal)
	assert.Equal(t, "percent", pm.Unit)

	back := plugin.ToLegacyMetric(pm)
	assert.Equal(t, legacy.Name, back.Name)
	assert.Equal(t, legacy.Type, back.Type)
	assert.Equal(t, legacy.Value, back.Value)
	assert.Equal(t, legacy.Unit, back.Unit)
}

func TestLegacyMetricSlices(t *testing.T) {
	in := []legacycol.Metric{{Name: "a"}, {Name: "b"}}
	pm := plugin.FromLegacyMetrics(in)
	require.Len(t, pm, 2)
	assert.Equal(t, "b", pm[1].Name)

	back := plugin.ToLegacyMetrics(pm)
	require.Len(t, back, 2)
	assert.Equal(t, "a", back[0].Name)

	assert.Empty(t, plugin.FromLegacyMetrics(nil))
	assert.Empty(t, plugin.ToLegacyMetrics(nil))
}

// ───────────────────────── CollectorAdapter ─────────────────────────

func TestCollectorAdapter_Lifecycle(t *testing.T) {
	impl := &fakeLegacyCollector{
		name: "legacy", running: true,
		metrics: []legacycol.Metric{{Name: "m1", Value: 1}},
	}
	ad := plugin.NewCollectorAdapter("", impl) // empty name → impl.Name()
	assert.Equal(t, "legacy", ad.Name())
	assert.True(t, ad.IsRunning())

	require.NoError(t, ad.Start(context.Background()))
	assert.True(t, impl.started)

	out, err := ad.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "m1", out[0].Name)
	assert.Equal(t, plugin.SignalMetric, out[0].Signal)

	require.NoError(t, ad.Stop())
	assert.True(t, impl.stopped)

	assert.Equal(t, "legacy", ad.Impl().Name())
	lc, ok := plugin.AsLegacyCollector(ad)
	require.True(t, ok)
	assert.Equal(t, "legacy", lc.Name())
}

func TestCollectorAdapter_ExplicitNameAndCollectError(t *testing.T) {
	impl := &fakeLegacyCollector{name: "legacy", collErr: errors.New("collect failed")}
	ad := plugin.NewCollectorAdapter("override", impl)
	assert.Equal(t, "override", ad.Name())

	_, err := ad.Collect(context.Background())
	assert.Error(t, err)
}

func TestAsLegacyCollector_NotAnAdapter(t *testing.T) {
	lc, ok := plugin.AsLegacyCollector(nonAdapterCollector{})
	assert.False(t, ok)
	assert.Nil(t, lc)
}

// ───────────────────────── SyncProcessorAdapter ─────────────────────────

func TestSyncProcessorAdapter_FlushOnStop(t *testing.T) {
	sp := &fakeSyncProcessor{name: "dbl", apply: func(ms []plugin.Metric) []plugin.Metric {
		for i := range ms {
			ms[i].Value *= 2
		}
		return ms
	}}
	ad := plugin.NewSyncProcessorAdapter("dbl", sp)
	assert.Equal(t, "dbl", ad.Name())

	ch := make(chan plugin.Metric, 16)
	acc := plugin.NewChannelAccumulator(ch, nil)
	require.NoError(t, ad.Start(acc))

	require.NoError(t, ad.Add(plugin.Metric{Name: "a", Value: 1}, acc))
	assert.Empty(t, ch, "not flushed below the 1000-metric batch size")

	require.NoError(t, ad.Stop()) // flush
	require.Len(t, ch, 1)
	assert.Equal(t, 2.0, (<-ch).Value)

	require.NoError(t, ad.Stop()) // empty buffer → no-op
}

func TestSyncProcessorAdapter_FlushWithoutAccumulator(t *testing.T) {
	ad := plugin.NewSyncProcessorAdapter("p", &fakeSyncProcessor{name: "p"})
	// no Start → acc is nil; Add + Stop must not panic and must flush nothing.
	require.NoError(t, ad.Add(plugin.Metric{Name: "x"}, nil))
	require.NoError(t, ad.Stop())
}

// ───────────────────────── Metric helpers ─────────────────────────

func TestMetric_CopyIsDeep(t *testing.T) {
	m := plugin.Metric{
		Name: "m", Labels: map[string]string{"k": "v"},
		HistogramBuckets: []float64{1, 2}, HistogramCounts: []uint64{3, 4},
		SummaryQuantiles: []float64{0.5}, SummaryValues: []float64{9},
	}
	c := m.Copy()
	c.Labels["k"] = "changed"
	c.HistogramBuckets[0] = 99
	c.SummaryValues[0] = 99

	assert.Equal(t, "v", m.Labels["k"], "original labels must be untouched")
	assert.Equal(t, 1.0, m.HistogramBuckets[0])
	assert.Equal(t, 9.0, m.SummaryValues[0])

	// nil slices/maps copy cleanly.
	bare := plugin.Metric{Name: "bare"}.Copy()
	assert.Nil(t, bare.Labels)
	assert.Nil(t, bare.HistogramBuckets)
}

func TestMetric_AddLabelAndAddField(t *testing.T) {
	var m plugin.Metric
	m.AddLabel("a", "1")
	m.AddLabel("b", "2")
	assert.Equal(t, map[string]string{"a": "1", "b": "2"}, m.Labels)

	var m2 plugin.Metric
	m2.AddField("ignored", 123) // no-op placeholder, just ensures Labels non-nil
	assert.NotNil(t, m2.Labels)
}
