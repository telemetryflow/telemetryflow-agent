// Package exporter_test contains unit tests for the metric forwarder.
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
package exporter_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// fakeCollector is a minimal collector.Collector implementation for tests.
type fakeCollector struct {
	name    string
	running bool
	metrics []collector.Metric
	err     error
	mu      sync.Mutex
	calls   int
}

func (f *fakeCollector) Name() string                    { return f.name }
func (f *fakeCollector) Start(ctx context.Context) error { f.running = true; return nil }
func (f *fakeCollector) Stop() error                     { f.running = false; return nil }
func (f *fakeCollector) IsRunning() bool                 { return f.running }
func (f *fakeCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.metrics, nil
}

// fakeMetricSink records metrics passed to Export.
type fakeMetricSink struct {
	mu       sync.Mutex
	batches  int
	metrics  int
	failNext bool
}

func (s *fakeMetricSink) Export(ctx context.Context, metrics []collector.Metric, attrs map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		return errors.New("export failed")
	}
	s.batches++
	s.metrics += len(metrics)
	return nil
}

// fakePromSink records UpdateMetrics calls.
type fakePromSink struct {
	mu     sync.Mutex
	called int
}

func (s *fakePromSink) UpdateMetrics(metrics []collector.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called++
}

func sampleMetrics() []collector.Metric {
	now := time.Now()
	return []collector.Metric{
		{Name: "cpu_usage", Type: collector.MetricTypeGauge, Value: 12.5, Timestamp: now, Unit: "percent", Labels: map[string]string{"host": "a"}},
		{Name: "requests_total", Type: collector.MetricTypeCounter, Value: 100, Timestamp: now, Labels: map[string]string{"code": "200"}},
		{Name: "cpu_usage", Type: collector.MetricTypeGauge, Value: 15.0, Timestamp: now, Unit: "percent", Labels: map[string]string{"host": "b"}},
	}
}

func TestMetricForwarder_NewDefaults(t *testing.T) {
	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{})
	require.NotNil(t, f)
	assert.False(t, f.IsRunning())
	stats := f.Stats()
	assert.False(t, stats.Running)
	assert.Zero(t, stats.TotalExports)
}

func TestMetricForwarder_StartForwardStop(t *testing.T) {
	col := &fakeCollector{name: "c1", running: true, metrics: sampleMetrics()}
	idle := &fakeCollector{name: "idle", running: false, metrics: sampleMetrics()}
	otlp := &fakeMetricSink{}
	prom := &fakePromSink{}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{col, idle},
		OTLPSink:   otlp,
		PromSink:   prom,
		Interval:   20 * time.Millisecond,
		Logger:     zap.NewNop(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, f.Start(ctx))
	// Starting again is a no-op.
	require.NoError(t, f.Start(ctx))
	assert.True(t, f.IsRunning())

	require.Eventually(t, func() bool {
		return f.Stats().TotalExports >= 1
	}, time.Second, 5*time.Millisecond)

	require.NoError(t, f.Stop())
	// Stopping again is a no-op.
	require.NoError(t, f.Stop())
	assert.False(t, f.IsRunning())

	stats := f.Stats()
	assert.GreaterOrEqual(t, stats.TotalExports, int64(1))
	assert.GreaterOrEqual(t, stats.TotalMetrics, int64(3))
	prom.mu.Lock()
	assert.GreaterOrEqual(t, prom.called, 1)
	prom.mu.Unlock()
}

func TestMetricForwarder_CollectErrorAndEmpty(t *testing.T) {
	errCol := &fakeCollector{name: "err", running: true, err: errors.New("boom")}
	emptyCol := &fakeCollector{name: "empty", running: true, metrics: nil}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{errCol, emptyCol},
		Interval:   20 * time.Millisecond,
		Logger:     zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, f.Start(ctx))
	time.Sleep(60 * time.Millisecond)
	require.NoError(t, f.Stop())

	stats := f.Stats()
	assert.Zero(t, stats.TotalExports)
	assert.Zero(t, stats.TotalMetrics)
}

func TestMetricForwarder_ExportError(t *testing.T) {
	col := &fakeCollector{name: "c1", running: true, metrics: sampleMetrics()}
	otlp := &fakeMetricSink{failNext: true}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{col},
		OTLPSink:   otlp,
		Interval:   15 * time.Millisecond,
		Logger:     zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, f.Start(ctx))
	require.Eventually(t, func() bool {
		return f.Stats().TotalErrors >= 1
	}, time.Second, 5*time.Millisecond)
	require.NoError(t, f.Stop())
	assert.Zero(t, f.Stats().TotalExports)
}

func TestMetricForwarder_ContextCancelStopsLoop(t *testing.T) {
	col := &fakeCollector{name: "c1", running: true, metrics: sampleMetrics()}
	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{col},
		OTLPSink:   &fakeMetricSink{},
		Interval:   time.Hour, // never ticks; only the initial forwardAll runs
		Logger:     zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, f.Start(ctx))
	require.Eventually(t, func() bool {
		return f.Stats().TotalExports >= 1
	}, time.Second, 5*time.Millisecond)
	cancel() // loop returns via ctx.Done()
	time.Sleep(20 * time.Millisecond)
	_ = f.Stop()
}
