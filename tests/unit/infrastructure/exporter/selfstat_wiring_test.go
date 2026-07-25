// Package exporter_test verifies that internal/selfstat agent counters are
// wired into the live MetricForwarder and BufferRetrySink code paths so
// they increment on real Export calls (M3.8).
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/selfstat"
)

// makeNMetrics returns n synthetic metrics for table-driven assertions.
func makeNMetrics(n int) []collector.Metric {
	now := time.Now()
	out := make([]collector.Metric, n)
	for i := range out {
		out[i] = collector.Metric{
			Name:      "selfstat_test_metric",
			Type:      collector.MetricTypeGauge,
			Value:     float64(i),
			Timestamp: now,
		}
	}
	return out
}

// controlledSink toggles between failure and success via failCount, mirroring
// failingSink but with an atomic counter so concurrent retries can be observed.
type controlledSink struct {
	failCount int32
	calls     atomic.Int32
}

func (s *controlledSink) Export(_ context.Context, _ []collector.Metric, _ map[string]string) error {
	if s.calls.Add(1) <= s.failCount {
		return errors.New("controlledSink: simulated failure")
	}
	return nil
}

// TestSelfStatWiring_ForwarderCounters verifies that the MetricForwarder
// increments AgentMetricsGathered, AgentMetricsWritten, and AgentWriteErrors
// after a single forwardAll cycle against a mocked MetricSink.
func TestSelfStatWiring_ForwarderCounters(t *testing.T) {
	tests := []struct {
		name         string
		sinkFail     bool
		metricCount  int
		wantWritten  int64
		wantErrors   int64
		wantGathered int64
	}{
		{
			name:         "successful export bumps written and gathered",
			sinkFail:     false,
			metricCount:  4,
			wantWritten:  4,
			wantErrors:   0,
			wantGathered: 4,
		},
		{
			name:         "failed export bumps errors and gathered only",
			sinkFail:     true,
			metricCount:  3,
			wantWritten:  0,
			wantErrors:   1,
			wantGathered: 3,
		},
		{
			name:         "empty gather cycle still records gathered=0",
			sinkFail:     false,
			metricCount:  0,
			wantWritten:  0,
			wantErrors:   0,
			wantGathered: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			preWritten := selfstat.AgentMetricsWritten.Get()
			preErrors := selfstat.AgentWriteErrors.Get()
			preGathered := selfstat.AgentMetricsGathered.Get()

			col := &fakeCollector{name: "selfstat_src", running: true, metrics: makeNMetrics(tc.metricCount)}
			sink := &fakeMetricSink{failNext: tc.sinkFail}

			f := exporter.NewMetricForwarder(exporter.MetricForwarderConfig{
				Collectors: []collector.Collector{col},
				OTLPSink:   sink,
				// Long interval so only the initial forwardAll runs.
				Interval: time.Hour,
				Logger:   zap.NewNop(),
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			require.NoError(t, f.Start(ctx))

			// Wait for the initial forwardAll cycle to complete. GatherCycles
			// is incremented via defer at the end of every cycle, so it is a
			// deterministic completion signal even when 0 metrics are gathered
			// (in which case TotalExports/TotalErrors never move).
			require.Eventually(t, func() bool {
				return f.Stats().GatherCycles >= 1
			}, time.Second, 5*time.Millisecond)
			require.NoError(t, f.Stop())

			assert.Equal(t, tc.wantWritten, selfstat.AgentMetricsWritten.Get()-preWritten,
				"agent.metrics_written delta")
			assert.Equal(t, tc.wantErrors, selfstat.AgentWriteErrors.Get()-preErrors,
				"agent.write_errors delta")
			assert.Equal(t, tc.wantGathered, selfstat.AgentMetricsGathered.Get()-preGathered,
				"agent.metrics_gathered delta")
		})
	}
}

// TestSelfStatWiring_BufferRetryDroppedOnBuffering verifies that a failed
// inner Export increments AgentMetricsDropped by the batch size.
func TestSelfStatWiring_BufferRetryDroppedOnBuffering(t *testing.T) {
	tests := []struct {
		name        string
		batchSize   int
		batchCount  int
		wantDropped int64
	}{
		{
			name:        "single failed batch of 5",
			batchSize:   5,
			batchCount:  1,
			wantDropped: 5,
		},
		{
			name:        "two failed batches of 3",
			batchSize:   3,
			batchCount:  2,
			wantDropped: 6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			preDropped := selfstat.AgentMetricsDropped.Get()

			inner := &controlledSink{failCount: int32(tc.batchCount)}
			sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
				Enabled: true,
				Buffer:  newTestBuffer(t),
				Logger:  zap.NewNop(),
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			for i := 0; i < tc.batchCount; i++ {
				require.NoError(t, sink.Export(ctx, makeNMetrics(tc.batchSize), nil))
			}

			assert.Equal(t, tc.wantDropped, selfstat.AgentMetricsDropped.Get()-preDropped,
				"agent.metrics_dropped delta after buffering")
		})
	}
}

// TestSelfStatWiring_InMemoryOverflowDrops verifies that overflowing the
// in-memory retry queue increments AgentMetricsDropped for each evicted
// oldest entry, in addition to the per-batch buffering increments.
func TestSelfStatWiring_InMemoryOverflowDrops(t *testing.T) {
	const batchSize = 2
	const overflows = 5
	const batches = 100 + overflows // 100 fills the queue, then overflows

	preDropped := selfstat.AgentMetricsDropped.Get()

	inner := &controlledSink{failCount: int32(batches)}
	sink := exporter.NewBufferRetrySink(inner, exporter.BufferRetryConfig{
		Enabled: true,
		// Buffer == nil forces the in-memory fallback so we can drive the
		// 100-entry cap deterministically without disk I/O timing.
		Buffer: nil,
		Logger: zap.NewNop(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < batches; i++ {
		require.NoError(t, sink.Export(ctx, makeNMetrics(batchSize), nil))
	}

	// Every batch contributes batchSize to AgentMetricsDropped via the
	// buffering path (batches * batchSize), plus each overflow evicts the
	// oldest entry which contributes another batchSize per eviction
	// (overflows * batchSize).
	wantDropped := int64(batches+overflows) * batchSize
	assert.Equal(t, wantDropped, selfstat.AgentMetricsDropped.Get()-preDropped,
		"agent.metrics_dropped delta after queue overflow")
}
