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
	inner      MetricSink
	cfg        BufferRetryConfig
	log        *zap.Logger
	mu         sync.Mutex
	retryQueue []retryEntry
}

// retryEntry pairs a marshalled batch with its retry count.
type retryEntry struct {
	MsgType       string             `json:"type"`
	Metrics       []collector.Metric `json:"metrics"`
	ResourceAttrs map[string]string  `json:"resource_attrs,omitempty"`
	Retries       int                `json:"retries"`
}

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
// Bounded by MaxRetries and a queue cap of 100 entries.
func (s *BufferRetrySink) enqueueInMemoryRetry(e retryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.retryQueue) >= 100 {
		s.log.Warn("in-memory retry queue full, dropping oldest")
		s.retryQueue = s.retryQueue[1:]
	}
	s.retryQueue = append(s.retryQueue, e)
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

// drainInMemory retries every queued entry, removing the ones that succeed.
func (s *BufferRetrySink) drainInMemory(ctx context.Context) {
	s.mu.Lock()
	queue := s.retryQueue
	s.retryQueue = nil
	s.mu.Unlock()

	for _, e := range queue {
		if s.cfg.MaxRetries > 0 && e.Retries >= s.cfg.MaxRetries {
			s.log.Warn("dropping entry after max retries",
				zap.Int("metrics", len(e.Metrics)),
				zap.Int("retries", e.Retries))
			continue
		}
		if err := s.inner.Export(ctx, e.Metrics, e.ResourceAttrs); err != nil {
			e.Retries++
			s.enqueueInMemoryRetry(e)
		}
	}
}

// drainDisk pops entries from the disk buffer and retries them.
func (s *BufferRetrySink) drainDisk(ctx context.Context) {
	for {
		entries := s.cfg.Buffer.Pop(50)
		if len(entries) == 0 {
			return
		}
		for _, ent := range entries {
			metrics, attrs, err := decodeBufferEntry(ent)
			if err != nil {
				s.log.Warn("dropping unparseable buffer entry", zap.Error(err))
				continue
			}
			if err := s.inner.Export(ctx, metrics, attrs); err != nil {
				// Re-enqueue for next tick.
				if perr := s.persist(retryEntry{
					MsgType:       "metrics",
					Metrics:       metrics,
					ResourceAttrs: attrs,
					Retries:       ent.Retries + 1,
				}); perr != nil {
					s.log.Error("re-persist failed — metrics lost", zap.Error(perr))
				}
			}
		}
	}
}

// decodeBufferEntry reconstructs a retryEntry from the disk buffer payload.
func decodeBufferEntry(ent buffer.Entry) ([]collector.Metric, map[string]string, error) {
	raw, err := json.Marshal(ent.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("re-marshal buffer payload: %w", err)
	}
	var decoded retryEntry
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, nil, fmt.Errorf("unmarshal retry entry: %w", err)
	}
	return decoded.Metrics, decoded.ResourceAttrs, nil
}

// Stats exposes counters for selfstat emission (wired in a later iteration).
type BufferRetryStats struct {
	InMemoryQueueDepth int `json:"in_memory_queue_depth"`
}

// Stats returns a snapshot of the in-memory retry queue depth.
func (s *BufferRetrySink) Stats() BufferRetryStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return BufferRetryStats{InMemoryQueueDepth: len(s.retryQueue)}
}
