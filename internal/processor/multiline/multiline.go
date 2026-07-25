// Package multiline implements a StreamingProcessor that aggregates
// consecutive metrics describing continuation log lines into a single
// metric. A header line starts a new record; subsequent continuation lines
// (matched by Pattern, or non-matching when Negate is true) within the same
// stream are appended to the buffered metric's Description separated by
// "\n". Buffered records are flushed when a new header arrives or when no
// continuation is received within Timeout.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package multiline

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// DefaultTimeout is how long to wait for the next continuation before
// flushing the buffered record when Timeout is unset.
const DefaultTimeout = 5 * time.Second

func init() {
	plugin.MustAddProcessor("multiline", func() plugin.StreamingProcessor {
		p, _ := New(DefaultConfig())
		return p
	})
}

// Config controls the multiline processor.
type Config struct {
	// Pattern is a regex matched against metric.Description. By default a
	// match identifies a continuation line; combined with Negate=true, a
	// match identifies a header line (and non-matching lines are
	// continuations). Required.
	Pattern string `yaml:"pattern" json:"pattern"`

	// Negate inverts Pattern semantics: matching lines START a new record,
	// non-matching lines are continuations.
	Negate bool `yaml:"negate" json:"negate"`

	// Timeout is how long to wait for the next continuation before flushing
	// the buffered record. Default 5s.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// StreamKey is the label used to group related lines (e.g. container_id,
	// pod_name). Lines with different StreamKey values are aggregated
	// independently. Empty = single global stream.
	StreamKey string `yaml:"stream_key" json:"stream_key"`
}

// DefaultConfig returns a 5s-timeout config with no pattern. New will reject
// an empty Pattern, so this is only useful as a base to overlay.
func DefaultConfig() Config { return Config{Timeout: DefaultTimeout} }

// Multiline is a StreamingProcessor.
type Multiline struct {
	cfg Config
	re  *regexp.Regexp
	acc plugin.Accumulator

	mu      sync.Mutex
	buffers map[string]*plugin.Metric
	timers  map[string]*time.Timer
	stopped bool
}

// New compiles the pattern and returns the processor.
func New(cfg Config) (*Multiline, error) {
	if cfg.Pattern == "" {
		return nil, fmt.Errorf("multiline: pattern is required")
	}
	re, err := regexp.Compile(cfg.Pattern)
	if err != nil {
		return nil, fmt.Errorf("multiline: invalid pattern %q: %w", cfg.Pattern, err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Multiline{
		cfg:     cfg,
		re:      re,
		buffers: make(map[string]*plugin.Metric),
		timers:  make(map[string]*time.Timer),
	}, nil
}

// Name implements plugin.StreamingProcessor.
func (m *Multiline) Name() string { return "multiline" }

// Start stores the downstream accumulator.
func (m *Multiline) Start(acc plugin.Accumulator) error { m.acc = acc; return nil }

// Add either appends to the buffered record (continuation) or flushes the
// buffer and starts a new one (header). StreamKey partitions the state.
func (m *Multiline) Add(metric plugin.Metric, _ plugin.Accumulator) error {
	key := m.streamKey(metric)
	isContinuation := m.isContinuation(metric.Description)

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		if m.acc != nil {
			m.acc.Add(metric)
		}
		return nil
	}

	buffered, hasBuffer := m.buffers[key]

	switch {
	case !hasBuffer:
		// No record yet → this line starts a new buffer.
		m.startBuffer(key, metric)
	case hasBuffer && isContinuation:
		// Append to the existing record.
		buffered.Description = buffered.Description + "\n" + metric.Description
		m.resetTimerLocked(key)
	default:
		// Header on a stream that already has a buffered record → flush
		// the old record, start a new one.
		m.flushLocked(key)
		m.startBuffer(key, metric)
	}
	return nil
}

// Stop flushes any buffered records and stops pending timers. Safe to call
// once; subsequent calls are no-ops.
func (m *Multiline) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return nil
	}
	m.stopped = true
	for key := range m.buffers {
		if timer, ok := m.timers[key]; ok {
			timer.Stop()
			delete(m.timers, key)
		}
		m.emitLocked(key)
	}
	return nil
}

// Flush forces any buffered records to be emitted immediately. Useful from
// tests and from pipeline drain hooks.
func (m *Multiline) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.buffers {
		if timer, ok := m.timers[key]; ok {
			timer.Stop()
			delete(m.timers, key)
		}
		m.emitLocked(key)
	}
}

// streamKey returns the grouping key for a metric. Empty StreamKey collapses
// everything into a single global stream.
func (m *Multiline) streamKey(metric plugin.Metric) string {
	if m.cfg.StreamKey == "" {
		return ""
	}
	if metric.Labels == nil {
		return ""
	}
	return metric.Labels[m.cfg.StreamKey]
}

// isContinuation returns true when a line is a continuation of the previous
// record (Negate inverts the semantics).
func (m *Multiline) isContinuation(desc string) bool {
	matched := m.re.MatchString(desc)
	if m.cfg.Negate {
		return !matched
	}
	return matched
}

// startBuffer stores metric under key and arms the timeout flush. The caller
// must hold m.mu.
func (m *Multiline) startBuffer(key string, metric plugin.Metric) {
	buf := metric.Copy()
	m.buffers[key] = &buf
	m.resetTimerLocked(key)
}

// resetTimerLocked (re)arms the flush timer for key. The caller must hold
// m.mu.
func (m *Multiline) resetTimerLocked(key string) {
	if t, ok := m.timers[key]; ok {
		t.Stop()
	}
	m.timers[key] = time.AfterFunc(m.cfg.Timeout, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.stopped {
			return
		}
		delete(m.timers, key)
		m.emitLocked(key)
	})
}

// flushLocked stops the timer for key and emits the buffered record. The
// caller must hold m.mu.
func (m *Multiline) flushLocked(key string) {
	if t, ok := m.timers[key]; ok {
		t.Stop()
		delete(m.timers, key)
	}
	m.emitLocked(key)
}

// emitLocked forwards the buffered record (if any) to the accumulator and
// clears the slot. The caller must hold m.mu.
func (m *Multiline) emitLocked(key string) {
	buf, ok := m.buffers[key]
	if !ok {
		return
	}
	delete(m.buffers, key)
	if m.acc != nil {
		m.acc.Add(*buf)
	}
}
