// Package exporter: buffer_retry_sink.go wraps a MetricSink with disk-backed
// retry. When the wrapped sink's Export call fails, metrics are pushed into
// an internal/buffer.Buffer; a background goroutine periodically retries.
//
// This wires the existing-but-unused internal/buffer package into the main
// pipeline (M1.2 quick win). It is non-invasive: agent.go can swap
// otlpBridge directly for bufferRetrySink without touching MetricForwarder.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/buffer"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/selfstat"
)

// BufferRetryConfig controls the retry wrapper.
type BufferRetryConfig struct {
	// Enabled gates retry behaviour. When false, BufferRetrySink is a thin
	// pass-through to the underlying sink.
	Enabled bool

	// Buffer is the disk-backed buffer used to persist failed batches.
	Buffer *buffer.Buffer

	// RetryInterval is how often the retry goroutine flushes the buffer.
	// Default 5s.
	RetryInterval time.Duration

	// MaxRetries caps the retry count per entry before it is dropped.
	// 0 = unlimited. Default 0.
	MaxRetries int

	// Logger receives structured warnings when batches fail or are dropped.
	Logger *zap.Logger
}

// BufferRetrySink wraps a MetricSink with disk-backed retry semantics.
// Implements MetricSink so it can be swapped in transparently.
type BufferRetrySink struct {
	inner MetricSink
	cfg   BufferRetryConfig
	log   *zap.Logger
	mu    sync.Mutex
	// retryQueue holds entries that could not be persisted to disk (or have
	// been popped from disk and failed re-export). Bounded by both
	// maxQueueEntries and maxQueueMetrics (RCA-20260828-001: the old
	// count-only cap allowed ~100 entries x ~5k metrics ≈ 250 MiB).
	retryQueue   []retryEntry
	retryMetrics int
}

// retryEntry pairs a marshalled batch with its retry count.
type retryEntry struct {
	MsgType       string             `json:"type"`
	Metrics       []collector.Metric `json:"metrics"`
	ResourceAttrs map[string]string  `json:"resource_attrs,omitempty"`
	Retries       int                `json:"retries"`
}

// Retry-loop budgets. drainDisk/drainInMemory export at most maxDrainPerTick
// entries per tick and stop at the FIRST failed export: while the backend is
// down, further attempts in the same tick would also fail, so retrying them
// only burns CPU. The 1.3.1 code re-persisted failed entries and immediately
// re-popped them in a tight loop, pinning CPU at its limit
// (RCA-20260828-001).
const (
	maxDrainPerTick = 25
	maxQueueEntries = 100
	maxQueueMetrics = 25_000
)

// NewBufferRetrySink wraps inner with disk-backed retry. If cfg.Enabled is
// false, the wrapper is a no-op pass-through.
func NewBufferRetrySink(inner MetricSink, cfg BufferRetryConfig) *BufferRetrySink {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 5 * time.Second
	}
	return &BufferRetrySink{
		inner: inner,
		cfg:   cfg,
		log:   logger.Named("buffer_retry"),
	}
}

// Export attempts a direct write; on failure pushes the batch into the
// disk buffer for later retry.
func (s *BufferRetrySink) Export(ctx context.Context, metrics []collector.Metric, attrs map[string]string) error {
	if !s.cfg.Enabled || s.inner == nil {
		if s.inner == nil {
			return nil
		}
		return s.inner.Export(ctx, metrics, attrs)
	}

	if err := s.inner.Export(ctx, metrics, attrs); err != nil {
		s.log.Warn("export failed, buffering for retry",
			zap.Int("metrics", len(metrics)),
			zap.Error(err))
		selfstat.AgentMetricsDropped.Incr(int64(len(metrics)))
		entry := retryEntry{MsgType: "metrics", Metrics: metrics, ResourceAttrs: attrs}
		if s.cfg.Buffer != nil {
			if perr := s.persist(entry); perr != nil {
				s.log.Error("buffer persist failed — metrics lost",
					zap.Int("metrics", len(metrics)), zap.Error(perr))
				s.enqueueInMemoryRetry(entry)
			}
		} else {
			s.enqueueInMemoryRetry(entry)
		}
		return nil // we absorbed the error
	}
	return nil
}

// persist pushes the entry into the disk buffer.
func (s *BufferRetrySink) persist(e retryEntry) error {
	payload := map[string]interface{}{
		"metrics":        e.Metrics,
		"resource_attrs": e.ResourceAttrs,
		"retries":        e.Retries,
	}
	return s.cfg.Buffer.Push("metrics_retry", payload)
}

// enqueueInMemoryRetry is the fallback when the disk buffer is unavailable.
// Bounded by MaxRetries and dual queue budgets (entries + total metrics).
func (s *BufferRetrySink) enqueueInMemoryRetry(e retryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryQueue = append(s.retryQueue, e)
	s.retryMetrics += len(e.Metrics)
	// Evict from the front until both budgets hold. Always keep at least
	// one entry so a single oversized batch is still retried (and dropped
	// by MaxRetries rather than silently discarded here).
	for len(s.retryQueue) > 1 &&
		(len(s.retryQueue) > maxQueueEntries || s.retryMetrics > maxQueueMetrics) {
		evicted := s.retryQueue[0]
		s.retryQueue = s.retryQueue[1:]
		s.retryMetrics -= len(evicted.Metrics)
		s.log.Warn("in-memory retry queue over budget, dropping oldest",
			zap.Int("metrics", len(evicted.Metrics)),
			zap.Int("retries", evicted.Retries))
		selfstat.AgentMetricsDropped.Incr(int64(len(evicted.Metrics)))
	}
}

// dequeueInMemory pops the oldest queued entry, if any.
func (s *BufferRetrySink) dequeueInMemory() (retryEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.retryQueue) == 0 {
		return retryEntry{}, false
	}
	e := s.retryQueue[0]
	s.retryQueue = s.retryQueue[1:]
	s.retryMetrics -= len(e.Metrics)
	return e, true
}

// StartRetryLoop launches a background goroutine that drains the buffer and
// the in-memory fallback queue, calling inner.Export on each entry. Stops
// when ctx is cancelled.
func (s *BufferRetrySink) StartRetryLoop(ctx context.Context) {
	if !s.cfg.Enabled || s.inner == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(s.cfg.RetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.drainInMemory(ctx)
				if s.cfg.Buffer != nil {
					s.drainDisk(ctx)
				}
			}
		}
	}()
}

// drainInMemory retries queued entries one at a time, removing the ones
// that succeed. It stops at the first failed export: while the backend is
// down, retrying the rest of the queue every tick only burns CPU
// (RCA-20260828-001).
func (s *BufferRetrySink) drainInMemory(ctx context.Context) {
	for range maxDrainPerTick {
		e, ok := s.dequeueInMemory()
		if !ok {
			return
		}
		if s.cfg.MaxRetries > 0 && e.Retries >= s.cfg.MaxRetries {
			s.dropEntry(e, "dropping entry after max retries")
			continue
		}
		if err := s.inner.Export(ctx, e.Metrics, e.ResourceAttrs); err != nil {
			e.Retries++
			if s.cfg.MaxRetries > 0 && e.Retries >= s.cfg.MaxRetries {
				s.dropEntry(e, "dropping entry after max retries")
				return
			}
			s.enqueueInMemoryRetry(e)
			return // first failure ends this tick's drain
		}
	}
}

// drainDisk retries buffered entries one at a time, up to maxDrainPerTick
// successful exports per tick. On the first failed export it re-persists
// that single entry (or drops it at the retry cap) and returns — the 1.3.1
// version re-persisted inside a `for { Pop(50) }` loop, so the freshly
// re-pushed entries were popped again immediately and the loop never
// terminated while the backend was failing (RCA-20260828-001).
func (s *BufferRetrySink) drainDisk(ctx context.Context) {
	for range maxDrainPerTick {
		entries := s.cfg.Buffer.Pop(1)
		if len(entries) == 0 {
			return
		}
		ent := entries[0]
		e, err := decodeBufferEntry(ent)
		if err != nil {
			s.log.Warn("dropping unparseable buffer entry", zap.Error(err))
			continue
		}
		if err := s.inner.Export(ctx, e.Metrics, e.ResourceAttrs); err != nil {
			// NOTE: the retry count lives in the payload, not in
			// buffer.Entry.Retries — Buffer.Push always zeroes the outer
			// field, so reading it here (as 1.3.1 did) reset the counter
			// every tick and MaxRetries never fired on the disk path.
			retries := e.Retries + 1
			if s.cfg.MaxRetries > 0 && retries >= s.cfg.MaxRetries {
				e.Retries = retries
				s.dropEntry(e, "dropping buffered entry after max retries")
				return
			}
			e.Retries = retries
			if perr := s.persist(e); perr != nil {
				s.log.Error("re-persist failed — metrics lost",
					zap.Int("metrics", len(e.Metrics)), zap.Error(perr))
				selfstat.AgentMetricsDropped.Incr(int64(len(e.Metrics)))
			}
			return // first failure ends this tick's drain
		}
	}
}

// dropEntry discards an entry that exceeded its retry budget.
func (s *BufferRetrySink) dropEntry(e retryEntry, msg string) {
	s.log.Warn(msg,
		zap.Int("metrics", len(e.Metrics)),
		zap.Int("retries", e.Retries))
	selfstat.AgentMetricsDropped.Incr(int64(len(e.Metrics)))
}

// decodeBufferEntry reconstructs a retryEntry from the disk buffer payload.
// The payload's "retries" field is the retry-count source of truth.
func decodeBufferEntry(ent buffer.Entry) (retryEntry, error) {
	raw, err := json.Marshal(ent.Data)
	if err != nil {
		return retryEntry{}, fmt.Errorf("re-marshal buffer payload: %w", err)
	}
	var decoded retryEntry
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return retryEntry{}, fmt.Errorf("unmarshal retry entry: %w", err)
	}
	return decoded, nil
}

// Stats exposes counters for selfstat emission (wired in a later iteration).
type BufferRetryStats struct {
	InMemoryQueueDepth   int `json:"in_memory_queue_depth"`
	InMemoryQueueMetrics int `json:"in_memory_queue_metrics"`
}

// Stats returns a snapshot of the in-memory retry queue.
func (s *BufferRetrySink) Stats() BufferRetryStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return BufferRetryStats{
		InMemoryQueueDepth:   len(s.retryQueue),
		InMemoryQueueMetrics: s.retryMetrics,
	}
}
