// Package exporter_test contains unit tests for the metric forwarder.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// mockCollector implements collector.Collector for testing.
type mockCollector struct {
	name    string
	running bool
	mu      sync.Mutex
	metrics []collector.Metric
	err     error
	calls   int64
}

func (m *mockCollector) Name() string { return m.name }

func (m *mockCollector) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = true
	return nil
}

func (m *mockCollector) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	return nil
}

func (m *mockCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	atomic.AddInt64(&m.calls, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	return m.metrics, nil
}

func (m *mockCollector) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// mockOTLPSink implements exporter.MetricSink.
type mockOTLPSink struct {
	mu         sync.Mutex
	exports    int64
	totalMetrs int64
	lastBatch  []collector.Metric
	err        error
}

func (m *mockOTLPSink) Export(ctx context.Context, metrics []collector.Metric, resourceAttrs map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exports++
	m.totalMetrs += int64(len(metrics))
	m.lastBatch = metrics
	if m.err != nil {
		return m.err
	}
	return nil
}

// mockPromSink implements exporter.PrometheusSink.
type mockPromSink struct {
	mu        sync.Mutex
	updates   int64
	lastBatch []collector.Metric
}

func (m *mockPromSink) UpdateMetrics(metrics []collector.Metric) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates++
	m.lastBatch = metrics
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMetricForwarderNewDefaults(t *testing.T) {
	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: nil,
	})
	if f == nil {
		t.Fatal("expected non-nil forwarder")
	}
	if f.IsRunning() {
		t.Error("expected forwarder not running initially")
	}
	stats := f.Stats()
	if stats.Running {
		t.Error("expected stats.Running=false")
	}
}

func TestMetricForwarderStartStop(t *testing.T) {
	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{},
		Interval:   50 * time.Millisecond,
	})
	if err := f.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !f.IsRunning() {
		t.Error("expected running after Start")
	}
	// Double start should be safe
	if err := f.Start(context.Background()); err != nil {
		t.Errorf("second Start() error = %v", err)
	}
	if err := f.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
	if f.IsRunning() {
		t.Error("expected not running after Stop")
	}
	// Double stop should be safe
	if err := f.Stop(); err != nil {
		t.Errorf("second Stop() error = %v", err)
	}
}

func TestMetricForwarderCollectsAndForwards(t *testing.T) {
	mc := &mockCollector{
		name:    "test-collector",
		running: true,
		metrics: []collector.Metric{
			collector.NewMetric("test.metric.one", 1.0, collector.MetricTypeGauge),
			collector.NewMetric("test.metric.two", 2.0, collector.MetricTypeCounter),
		},
	}
	otlp := &mockOTLPSink{}
	prom := &mockPromSink{}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc},
		OTLPSink:   otlp,
		PromSink:   prom,
		Interval:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = f.Start(ctx)
	defer func() { _ = f.Stop() }()

	// Wait for at least one cycle
	time.Sleep(150 * time.Millisecond)
	_ = f.Stop()

	otlp.mu.Lock()
	defer otlp.mu.Unlock()
	if otlp.exports == 0 {
		t.Error("expected at least 1 OTLP export")
	}
	if otlp.totalMetrs == 0 {
		t.Error("expected metrics forwarded to OTLP")
	}
	if len(otlp.lastBatch) != 2 {
		t.Errorf("expected 2 metrics in last batch, got %d", len(otlp.lastBatch))
	}

	prom.mu.Lock()
	defer prom.mu.Unlock()
	if prom.updates == 0 {
		t.Error("expected at least 1 Prometheus update")
	}
	if len(prom.lastBatch) != 2 {
		t.Errorf("expected 2 metrics in last prom batch, got %d", len(prom.lastBatch))
	}
}

func TestMetricForwarderSkipsNotRunningCollectors(t *testing.T) {
	mc := &mockCollector{
		name:    "stopped-collector",
		running: false, // not running — should be skipped
		metrics: []collector.Metric{
			collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge),
		},
	}
	otlp := &mockOTLPSink{}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc},
		OTLPSink:   otlp,
		Interval:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = f.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	_ = f.Stop()

	otlp.mu.Lock()
	defer otlp.mu.Unlock()
	if otlp.exports > 0 {
		t.Errorf("expected 0 exports for non-running collector, got %d", otlp.exports)
	}
}

func TestMetricForwarderHandlesCollectError(t *testing.T) {
	mc := &mockCollector{
		name:    "error-collector",
		running: true,
		err:     errors.New("collect failed"),
	}
	otlp := &mockOTLPSink{}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc},
		OTLPSink:   otlp,
		Interval:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = f.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	_ = f.Stop()

	// Should not crash, should not export anything
	otlp.mu.Lock()
	defer otlp.mu.Unlock()
	if otlp.exports > 0 {
		t.Errorf("expected 0 exports on error, got %d", otlp.exports)
	}

	stats := f.Stats()
	if stats.TotalErrors != 0 {
		t.Errorf("expected 0 errors (collect error is skipped, not counted), got %d", stats.TotalErrors)
	}
}

func TestMetricForwarderCountsOTLPErrors(t *testing.T) {
	mc := &mockCollector{
		name:    "ok-collector",
		running: true,
		metrics: []collector.Metric{
			collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge),
		},
	}
	otlp := &mockOTLPSink{
		err: errors.New("network error"),
	}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc},
		OTLPSink:   otlp,
		Interval:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = f.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	_ = f.Stop()

	stats := f.Stats()
	if stats.TotalErrors == 0 {
		t.Error("expected error count > 0")
	}
	if stats.TotalExports != 0 {
		t.Errorf("expected 0 successful exports, got %d", stats.TotalExports)
	}
}

func TestMetricForwarderNoSinks(t *testing.T) {
	mc := &mockCollector{
		name:    "collector",
		running: true,
		metrics: []collector.Metric{
			collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge),
		},
	}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc},
		Interval:   50 * time.Millisecond,
		// No sinks
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = f.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	_ = f.Stop()

	// Should not crash even without sinks
	stats := f.Stats()
	if stats.TotalExports != 0 {
		t.Errorf("expected 0 exports, got %d", stats.TotalExports)
	}
}

func TestMetricForwarderEmptyMetrics(t *testing.T) {
	mc := &mockCollector{
		name:    "empty-collector",
		running: true,
		metrics: []collector.Metric{}, // no metrics
	}
	otlp := &mockOTLPSink{}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc},
		OTLPSink:   otlp,
		Interval:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = f.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	_ = f.Stop()

	otlp.mu.Lock()
	defer otlp.mu.Unlock()
	if otlp.exports > 0 {
		t.Errorf("expected 0 exports for empty metrics, got %d", otlp.exports)
	}
}

func TestMetricForwarderContextCancel(t *testing.T) {
	mc := &mockCollector{
		name:    "collector",
		running: true,
		metrics: []collector.Metric{
			collector.NewMetric("test.metric", 1.0, collector.MetricTypeGauge),
		},
	}
	otlp := &mockOTLPSink{}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc},
		OTLPSink:   otlp,
		Interval:   100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	_ = f.Start(ctx)

	// Cancel context — forwarder loop should exit
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Stopping should still be safe
	_ = f.Stop()
}

func TestMetricForwarderMultipleCollectors(t *testing.T) {
	mc1 := &mockCollector{
		name:    "collector-1",
		running: true,
		metrics: []collector.Metric{
			collector.NewMetric("metric.one", 1.0, collector.MetricTypeGauge),
		},
	}
	mc2 := &mockCollector{
		name:    "collector-2",
		running: true,
		metrics: []collector.Metric{
			collector.NewMetric("metric.two", 2.0, collector.MetricTypeGauge),
			collector.NewMetric("metric.three", 3.0, collector.MetricTypeGauge),
		},
	}
	otlp := &mockOTLPSink{}

	f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
		Collectors: []collector.Collector{mc1, mc2},
		OTLPSink:   otlp,
		Interval:   50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = f.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	_ = f.Stop()

	otlp.mu.Lock()
	defer otlp.mu.Unlock()
	if otlp.exports == 0 {
		t.Fatal("expected at least 1 export")
	}
	if len(otlp.lastBatch) != 3 {
		t.Errorf("expected 3 metrics (1+2), got %d", len(otlp.lastBatch))
	}
}
