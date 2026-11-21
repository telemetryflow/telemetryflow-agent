// Package plugincore_test unit-tests the internal/plugin typed registries
// (Add/MustAdd/Get/Names for every plugin category plus AllNames) and the
// startup/partial-write error types. The registries are process globals that
// self-register via init(); tests use unique names to stay isolated and cover
// the empty-name, duplicate, MustAdd-panic, and unknown-name branches.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// ───────────────────────── minimal fakes per interface ─────────────────────────

type fakeCollector struct{ name string }

func (f *fakeCollector) Name() string                                     { return f.name }
func (f *fakeCollector) Start(context.Context) error                      { return nil }
func (f *fakeCollector) Stop() error                                      { return nil }
func (f *fakeCollector) Collect(context.Context) ([]plugin.Metric, error) { return nil, nil }
func (f *fakeCollector) IsRunning() bool                                  { return false }

type fakeServiceCollector struct{ name string }

func (f *fakeServiceCollector) Name() string                                     { return f.name }
func (f *fakeServiceCollector) Start(context.Context, plugin.Accumulator) error  { return nil }
func (f *fakeServiceCollector) Stop() error                                      { return nil }
func (f *fakeServiceCollector) Collect(context.Context) ([]plugin.Metric, error) { return nil, nil }
func (f *fakeServiceCollector) IsRunning() bool                                  { return false }

type fakeOutput struct{ name string }

func (f *fakeOutput) Name() string                { return f.name }
func (f *fakeOutput) Connect() error              { return nil }
func (f *fakeOutput) Close() error                { return nil }
func (f *fakeOutput) Write([]plugin.Metric) error { return nil }

type fakeStreamProcessor struct{ name string }

func (f *fakeStreamProcessor) Name() string                                { return f.name }
func (f *fakeStreamProcessor) Start(plugin.Accumulator) error              { return nil }
func (f *fakeStreamProcessor) Add(plugin.Metric, plugin.Accumulator) error { return nil }
func (f *fakeStreamProcessor) Stop() error                                 { return nil }

type fakeAggregator struct{ name string }

func (f *fakeAggregator) Name() string            { return f.name }
func (f *fakeAggregator) Add(plugin.Metric)       {}
func (f *fakeAggregator) Push(plugin.Accumulator) {}
func (f *fakeAggregator) Reset()                  {}
func (f *fakeAggregator) DropOriginal() bool      { return true }

type fakeParser struct{}

func (fakeParser) Parse([]byte) ([]plugin.Metric, error)   { return nil, nil }
func (fakeParser) ParseLine(string) (plugin.Metric, error) { return plugin.Metric{}, nil }
func (fakeParser) SetDefaultTags(map[string]string)        {}

type fakeSerializer struct{}

func (fakeSerializer) Serialize(plugin.Metric) ([]byte, error)        { return nil, nil }
func (fakeSerializer) SerializeBatch([]plugin.Metric) ([]byte, error) { return nil, nil }

type fakeSecretStore struct{ name string }

func (f *fakeSecretStore) Name() string               { return f.name }
func (f *fakeSecretStore) Init(map[string]any) error  { return nil }
func (f *fakeSecretStore) Get(string) (string, error) { return "", nil }
func (f *fakeSecretStore) List() ([]string, error)    { return nil, nil }
func (f *fakeSecretStore) GetResolver(string) (plugin.ResolveFunc, error) {
	return func() (string, bool, error) { return "", false, nil }, nil
}

// ───────────────────────── registry Add/Get/Names + AllNames ─────────────────────────

// TestRegistries_HappyPath registers one of every plugin type, then checks
// Get returns a fresh instance, Names includes it, and AllNames aggregates it.
func TestRegistries_HappyPath(t *testing.T) {
	require.NoError(t, plugin.AddCollector("tfo_test_col", func() plugin.Collector { return &fakeCollector{name: "c"} }))
	require.NoError(t, plugin.AddServiceCollector("tfo_test_svc", func() plugin.ServiceCollector { return &fakeServiceCollector{name: "s"} }))
	require.NoError(t, plugin.AddOutput("tfo_test_out", func() plugin.Output { return &fakeOutput{name: "o"} }))
	require.NoError(t, plugin.AddProcessor("tfo_test_proc", func() plugin.StreamingProcessor { return &fakeStreamProcessor{name: "p"} }))
	require.NoError(t, plugin.AddSyncProcessor("tfo_test_sync", func() plugin.SyncProcessor { return &fakeSyncProcessor{name: "sp"} }))
	require.NoError(t, plugin.AddAggregator("tfo_test_agg", func() plugin.Aggregator { return &fakeAggregator{name: "a"} }))
	require.NoError(t, plugin.AddParser("tfo_test_parser", func() plugin.Parser { return fakeParser{} }))
	require.NoError(t, plugin.AddSerializer("tfo_test_ser", func() plugin.Serializer { return fakeSerializer{} }))
	require.NoError(t, plugin.AddSecretStore("tfo_test_secret", func() plugin.SecretStore { return &fakeSecretStore{name: "ss"} }))

	// Get returns a non-nil instance + ok.
	col, dep, ok := plugin.GetCollector("tfo_test_col")
	require.True(t, ok)
	assert.Empty(t, dep)
	assert.Equal(t, "c", col.Name())

	svc, _, ok := plugin.GetServiceCollector("tfo_test_svc")
	require.True(t, ok)
	assert.Equal(t, "s", svc.Name())

	out, _, ok := plugin.GetOutput("tfo_test_out")
	require.True(t, ok)
	assert.Equal(t, "o", out.Name())

	proc, _, ok := plugin.GetProcessor("tfo_test_proc")
	require.True(t, ok)
	assert.Equal(t, "p", proc.Name())

	sp, _, ok := plugin.GetSyncProcessor("tfo_test_sync")
	require.True(t, ok)
	assert.Equal(t, "sp", sp.Name())

	agg, _, ok := plugin.GetAggregator("tfo_test_agg")
	require.True(t, ok)
	assert.Equal(t, "a", agg.Name())

	par, _, ok := plugin.GetParser("tfo_test_parser")
	require.True(t, ok)
	assert.NotNil(t, par)

	ser, _, ok := plugin.GetSerializer("tfo_test_ser")
	require.True(t, ok)
	assert.NotNil(t, ser)

	ss, _, ok := plugin.GetSecretStore("tfo_test_secret")
	require.True(t, ok)
	assert.Equal(t, "ss", ss.Name())

	// Names include the registered entry.
	assert.Contains(t, plugin.CollectorNames(), "tfo_test_col")
	assert.Contains(t, plugin.ServiceCollectorNames(), "tfo_test_svc")
	assert.Contains(t, plugin.OutputNames(), "tfo_test_out")
	assert.Contains(t, plugin.ProcessorNames(), "tfo_test_proc")
	assert.Contains(t, plugin.AggregatorNames(), "tfo_test_agg")
	assert.Contains(t, plugin.ParserNames(), "tfo_test_parser")
	assert.Contains(t, plugin.SerializerNames(), "tfo_test_ser")
	assert.Contains(t, plugin.SecretStoreNames(), "tfo_test_secret")

	// AllNames aggregates across registries and is sorted.
	all := plugin.AllNames()
	assert.Contains(t, all, "tfo_test_col")
	assert.Contains(t, all, "tfo_test_secret")
	assert.IsIncreasing(t, all)
}

// TestRegistries_UnknownName covers the ok=false branch of every Get*.
func TestRegistries_UnknownName(t *testing.T) {
	_, _, ok := plugin.GetCollector("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetServiceCollector("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetOutput("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetProcessor("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetSyncProcessor("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetAggregator("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetParser("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetSerializer("nope")
	assert.False(t, ok)
	_, _, ok = plugin.GetSecretStore("nope")
	assert.False(t, ok)
}

// TestRegistry_EmptyNameAndDuplicate covers the add() guard branches.
func TestRegistry_EmptyNameAndDuplicate(t *testing.T) {
	assert.Error(t, plugin.AddCollector("", func() plugin.Collector { return &fakeCollector{} }),
		"empty name must be rejected")

	require.NoError(t, plugin.AddOutput("tfo_dup_out", func() plugin.Output { return &fakeOutput{} }))
	assert.Error(t, plugin.AddOutput("tfo_dup_out", func() plugin.Output { return &fakeOutput{} }),
		"duplicate name must be rejected")
}

// TestMustAdd covers both the success and panic-on-duplicate branches for the
// Must* helpers across every registry.
func TestMustAdd(t *testing.T) {
	// Success paths (no panic).
	require.NotPanics(t, func() {
		plugin.MustAddCollector("tfo_must_col", func() plugin.Collector { return &fakeCollector{} })
		plugin.MustAddServiceCollector("tfo_must_svc", func() plugin.ServiceCollector { return &fakeServiceCollector{} })
		plugin.MustAddOutput("tfo_must_out", func() plugin.Output { return &fakeOutput{} })
		plugin.MustAddProcessor("tfo_must_proc", func() plugin.StreamingProcessor { return &fakeStreamProcessor{} })
		plugin.MustAddSyncProcessor("tfo_must_sync", func() plugin.SyncProcessor { return &fakeSyncProcessor{} })
		plugin.MustAddAggregator("tfo_must_agg", func() plugin.Aggregator { return &fakeAggregator{} })
		plugin.MustAddParser("tfo_must_parser", func() plugin.Parser { return fakeParser{} })
		plugin.MustAddSerializer("tfo_must_ser", func() plugin.Serializer { return fakeSerializer{} })
		plugin.MustAddSecretStore("tfo_must_secret", func() plugin.SecretStore { return &fakeSecretStore{} })
	})

	// Panic-on-duplicate paths.
	assert.Panics(t, func() {
		plugin.MustAddCollector("tfo_must_col", func() plugin.Collector { return &fakeCollector{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddServiceCollector("tfo_must_svc", func() plugin.ServiceCollector { return &fakeServiceCollector{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddOutput("tfo_must_out", func() plugin.Output { return &fakeOutput{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddProcessor("tfo_must_proc", func() plugin.StreamingProcessor { return &fakeStreamProcessor{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddSyncProcessor("tfo_must_sync", func() plugin.SyncProcessor { return &fakeSyncProcessor{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddAggregator("tfo_must_agg", func() plugin.Aggregator { return &fakeAggregator{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddParser("tfo_must_parser", func() plugin.Parser { return fakeParser{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddSerializer("tfo_must_ser", func() plugin.Serializer { return fakeSerializer{} })
	})
	assert.Panics(t, func() {
		plugin.MustAddSecretStore("tfo_must_secret", func() plugin.SecretStore { return &fakeSecretStore{} })
	})
}

// ───────────────────────── startup / write error types ─────────────────────────

func TestFatalError(t *testing.T) {
	inner := errors.New("boom")
	e := &plugin.FatalError{Err: inner}
	assert.Equal(t, "fatal: boom", e.Error())
	assert.ErrorIs(t, e, inner)
}

func TestStartupError_MessageVariants(t *testing.T) {
	inner := errors.New("db down")

	assert.Equal(t, "startup error: db down", (&plugin.StartupError{Err: inner}).Error())
	assert.Equal(t, "startup error (partial): db down", (&plugin.StartupError{Err: inner, Partial: true}).Error())
	// Retry takes precedence over Partial in the message.
	assert.Equal(t, "startup error (retry): db down", (&plugin.StartupError{Err: inner, Retry: true, Partial: true}).Error())

	assert.ErrorIs(t, &plugin.StartupError{Err: inner}, inner)
}

func TestPartialWriteError(t *testing.T) {
	inner := errors.New("rejected 2")
	e := &plugin.PartialWriteError{
		Err:             inner,
		MetricsAccepted: []plugin.Metric{{Name: "ok"}},
		MetricsRejected: []plugin.Metric{{Name: "bad1"}, {Name: "bad2"}},
	}
	assert.Equal(t, "partial write: rejected 2", e.Error())
	assert.ErrorIs(t, e, inner)
	assert.Len(t, e.MetricsRejected, 2)
}
