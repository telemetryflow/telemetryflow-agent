// Package qan_test contains unit tests for the QAN forwarder and exporter.
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

package qan_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// mockQANCollector implements qan.QANCollector for testing.
type mockQANCollector struct {
	name      string
	agentType qan.AgentType
	running   bool
	mu        sync.Mutex
	buckets   []qan.QANMetricsBucket
	err       error
	calls     int64
}

func (m *mockQANCollector) Name() string { return m.name }

func (m *mockQANCollector) AgentType() qan.AgentType { return m.agentType }

func (m *mockQANCollector) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *mockQANCollector) CollectQAN(ctx context.Context) ([]qan.QANMetricsBucket, error) {
	atomic.AddInt64(&m.calls, 1)
	if m.err != nil {
		return nil, m.err
	}
	return m.buckets, nil
}

func (m *mockQANCollector) Calls() int64 { return atomic.LoadInt64(&m.calls) }

func (m *mockQANCollector) setRunning(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = v
}

func (m *mockQANCollector) setBuckets(b []qan.QANMetricsBucket) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.buckets = b
}

// mockSink implements qan.QANSink for testing.
type mockSink struct {
	mu      sync.Mutex
	batches [][]qan.QANMetricsBucket
	err     error
	calls   int64
}

func (m *mockSink) Collect(ctx context.Context, buckets []qan.QANMetricsBucket) error {
	atomic.AddInt64(&m.calls, 1)
	if m.err != nil {
		return m.err
	}
	m.mu.Lock()
	m.batches = append(m.batches, buckets)
	m.mu.Unlock()
	return nil
}

func (m *mockSink) Calls() int64 { return atomic.LoadInt64(&m.calls) }

func (m *mockSink) TotalBuckets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, b := range m.batches {
		total += len(b)
	}
	return total
}

// ---------------------------------------------------------------------------
// Tests: QANForwarder
// ---------------------------------------------------------------------------

func TestQANForwarder_StartStop(t *testing.T) {
	logger := zap.NewNop()
	sink := &mockSink{}
	collector := &mockQANCollector{
		name:      "test-collector",
		agentType: qan.AgentTypePostgreSQLPgStatements,
	}

	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: []qan.QANCollector{collector},
		Sink:       sink,
		Interval:   100 * time.Millisecond,
		Logger:     logger,
	})

	if fwd.IsRunning() {
		t.Fatal("forwarder should not be running before Start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !fwd.IsRunning() {
		t.Fatal("forwarder should be running after Start")
	}

	// Starting again should be idempotent
	if err := fwd.Start(ctx); err != nil {
		t.Fatalf("double Start failed: %v", err)
	}

	if err := fwd.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if fwd.IsRunning() {
		t.Fatal("forwarder should not be running after Stop")
	}
}

func TestQANForwarder_CollectAndForward(t *testing.T) {
	logger := zap.NewNop()
	sink := &mockSink{}

	buckets := []qan.QANMetricsBucket{
		{QueryID: "q1", AgentType: qan.AgentTypePostgreSQLPgStatements, NumQueries: 10},
		{QueryID: "q2", AgentType: qan.AgentTypePostgreSQLPgStatements, NumQueries: 5},
	}

	collector := &mockQANCollector{
		name:      "pg",
		agentType: qan.AgentTypePostgreSQLPgStatements,
	}
	collector.setRunning(true)
	collector.setBuckets(buckets)

	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: []qan.QANCollector{collector},
		Sink:       sink,
		Interval:   50 * time.Millisecond,
		Logger:     logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = fwd.Start(ctx)

	// Wait for at least one collect cycle
	time.Sleep(200 * time.Millisecond)

	cancel()
	_ = fwd.Stop()

	if collector.Calls() < 1 {
		t.Fatalf("expected at least 1 CollectQAN call, got %d", collector.Calls())
	}

	if sink.Calls() < 1 {
		t.Fatalf("expected at least 1 sink Collect call, got %d", sink.Calls())
	}

	if sink.TotalBuckets() < 2 {
		t.Fatalf("expected at least 2 total buckets, got %d", sink.TotalBuckets())
	}
}

func TestQANForwarder_SkipsNotRunningCollectors(t *testing.T) {
	logger := zap.NewNop()
	sink := &mockSink{}

	collector := &mockQANCollector{
		name:      "stopped",
		agentType: qan.AgentTypeMySQLPerfSchema,
		running:   false, // not running — should be skipped
	}

	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: []qan.QANCollector{collector},
		Sink:       sink,
		Interval:   50 * time.Millisecond,
		Logger:     logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = fwd.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	cancel()
	_ = fwd.Stop()

	if collector.Calls() != 0 {
		t.Fatalf("CollectQAN should not be called on stopped collector, got %d calls", collector.Calls())
	}

	if sink.Calls() != 0 {
		t.Fatalf("sink should not be called when no collectors are running, got %d calls", sink.Calls())
	}
}

func TestQANForwarder_CollectErrorContinues(t *testing.T) {
	logger := zap.NewNop()
	sink := &mockSink{}

	errCollector := &mockQANCollector{
		name:      "erroring",
		agentType: qan.AgentTypeMySQLPerfSchema,
		err:       errors.New("connection refused"),
	}
	errCollector.setRunning(true)

	goodBuckets := []qan.QANMetricsBucket{{QueryID: "ok", NumQueries: 1}}
	goodCollector := &mockQANCollector{
		name:      "good",
		agentType: qan.AgentTypePostgreSQLPgStatements,
	}
	goodCollector.setRunning(true)
	goodCollector.setBuckets(goodBuckets)

	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: []qan.QANCollector{errCollector, goodCollector},
		Sink:       sink,
		Interval:   50 * time.Millisecond,
		Logger:     logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = fwd.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cancel()
	_ = fwd.Stop()

	if errCollector.Calls() < 1 {
		t.Fatal("erroring collector should still be called")
	}

	if sink.TotalBuckets() == 0 {
		t.Fatal("sink should still receive buckets from the good collector")
	}
}

func TestQANForwarder_NilSink(t *testing.T) {
	logger := zap.NewNop()

	collector := &mockQANCollector{
		name:      "nil-sink-test",
		agentType: qan.AgentTypePostgreSQLPgStatements,
	}
	collector.setRunning(true)
	collector.setBuckets([]qan.QANMetricsBucket{{QueryID: "q1"}})

	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: []qan.QANCollector{collector},
		Sink:       nil, // no sink
		Interval:   50 * time.Millisecond,
		Logger:     logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = fwd.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	cancel()
	_ = fwd.Stop()

	if collector.Calls() < 1 {
		t.Fatal("collector should still be called even without sink")
	}
}

func TestQANForwarder_Stats(t *testing.T) {
	logger := zap.NewNop()
	sink := &mockSink{}

	buckets := []qan.QANMetricsBucket{{QueryID: "q1"}, {QueryID: "q2"}}
	collector := &mockQANCollector{
		name:      "stats-test",
		agentType: qan.AgentTypePostgreSQLPgStatements,
	}
	collector.setRunning(true)
	collector.setBuckets(buckets)

	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: []qan.QANCollector{collector},
		Sink:       sink,
		Interval:   50 * time.Millisecond,
		Logger:     logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = fwd.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cancel()
	_ = fwd.Stop()

	stats := fwd.Stats()
	if stats.TotalBuckets < 2 {
		t.Fatalf("expected total_buckets >= 2, got %d", stats.TotalBuckets)
	}
	if stats.TotalCollects < 1 {
		t.Fatalf("expected total_collects >= 1, got %d", stats.TotalCollects)
	}
}

func TestQANForwarder_DefaultInterval(t *testing.T) {
	logger := zap.NewNop()
	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: nil,
		Sink:       &mockSink{},
		Interval:   0, // should default to 60s
		Logger:     logger,
	})
	if fwd.IsRunning() {
		t.Fatal("should not be running")
	}
}

func TestQANForwarder_NoCollectors(t *testing.T) {
	logger := zap.NewNop()
	fwd := qan.NewQANForwarder(qan.QANForwarderConfig{
		Collectors: nil,
		Sink:       &mockSink{},
		Interval:   50 * time.Millisecond,
		Logger:     logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = fwd.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()
	_ = fwd.Stop()

	// Should not crash with no collectors
}
