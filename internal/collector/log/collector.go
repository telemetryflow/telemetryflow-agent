// Package log implements file-based and journald log collection for TFO-Agent.
//
// The LogCollector tails configured file paths and optionally follows systemd
// journal entries, batching them and exporting via the OTLP logs pipeline.
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
package log

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// LogCollector collects logs from file paths and journald, exporting them via OTLP.
//
// LogCollector implements the plugin.StatefulPlugin mixin (GetState/SetState)
// so file tail offsets can be persisted across agent restarts by the
// persister framework. It continues to satisfy the legacy collector.Collector
// interface as well.
type LogCollector struct {
	cfg        config.LogCollectorConfig
	logger     *zap.Logger
	tailers    []*FileTailer
	journald   *JournaldCollector
	mu         sync.RWMutex
	running    bool
	stopCh     chan struct{}
	hostname   string
	agentID    string
	linesTotal atomic.Int64
	bytesTotal atomic.Int64

	// restoredState is populated by SetState() at agent startup (before Start
	// creates tailers). Start() consults it to seed each FileTailer with its
	// saved offset/inode so collection resumes instead of skipping to EOF.
	restoredState *CollectorState

	// logCallback is called for each collected log line.
	// Set by the agent to wire into the OTLP LoggerProvider.
	logCallback func(timestamp time.Time, severity, body, source string, attrs map[string]string)
}

// Compile-time assertions that LogCollector satisfies both the legacy
// collector.Collector interface and the plugin.StatefulPlugin mixin.
var (
	_ collector.Collector   = (*LogCollector)(nil)
	_ plugin.StatefulPlugin = (*LogCollector)(nil)
)

// NewLogCollector creates a log collector with the given configuration.
func NewLogCollector(cfg config.LogCollectorConfig, agentID string, logger *zap.Logger) *LogCollector {
	hostname, _ := os.Hostname()
	return &LogCollector{
		cfg:      cfg,
		logger:   logger,
		hostname: hostname,
		agentID:  agentID,
		stopCh:   make(chan struct{}),
	}
}

// SetLogCallback sets the function called for each collected log line.
// This should be wired to the OTLP log export pipeline.
func (c *LogCollector) SetLogCallback(fn func(timestamp time.Time, severity, body, source string, attrs map[string]string)) {
	c.logCallback = fn
}

// Name returns the collector name.
func (c *LogCollector) Name() string { return "logs" }

// IsRunning returns whether the collector is active.
func (c *LogCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start begins log collection. Blocks until context is cancelled or Stop is called.
func (c *LogCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	c.running = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	// Compile include/exclude patterns
	includeRe := compilePatterns(c.cfg.IncludePatterns)
	excludeRe := compilePatterns(c.cfg.ExcludePatterns)

	// Expand glob patterns to concrete file paths
	paths := ExpandGlobs(c.cfg.Paths)
	maxLine := c.cfg.MaxLineSize
	if maxLine <= 0 {
		maxLine = 64 * 1024
	}

	// Create file tailers. Seed each one with its persisted offset (if any)
	// BEFORE calling Start() so the tailer can resume from the saved offset
	// instead of skipping to EOF. The restoredState map is keyed by the same
	// expanded path that ExpandGlobs returns, so the lookup is stable across
	// restarts for non-glob configs.
	c.mu.Lock()
	for _, p := range paths {
		tailer := NewFileTailer(p, maxLine, c.logger)
		if c.restoredState != nil {
			if ts, ok := c.restoredState.Tailers[p]; ok {
				tailer.SetOffset(ts.Offset, ts.Inode)
			}
		}
		c.tailers = append(c.tailers, tailer)
		go func(t *FileTailer) {
			if err := t.Start(ctx); err != nil && err != context.Canceled {
				c.logger.Warn("File tailer stopped", zap.String("path", t.Path()), zap.Error(err))
			}
		}(tailer)
	}
	c.mu.Unlock()

	// Start journald collector if enabled and on Linux
	if c.cfg.Journald.Enabled && runtime.GOOS == "linux" {
		c.journald = NewJournaldCollector(c.cfg.Journald, c.logger)
		go func() {
			if err := c.journald.Start(ctx); err != nil && err != context.Canceled {
				c.logger.Warn("Journald collector stopped", zap.Error(err))
			}
		}()
	}

	c.logger.Info("Log collector started",
		zap.Int("file_tailers", len(c.tailers)),
		zap.Bool("journald", c.cfg.Journald.Enabled && runtime.GOOS == "linux"),
	)

	// Main loop: read from all sources, filter, and emit
	interval := c.cfg.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			// Drain file tailer channels
			for _, t := range c.tailers {
				c.drainFileTailer(t, includeRe, excludeRe)
			}
			// Drain journald channel
			if c.journald != nil {
				c.drainJournald(c.journald, includeRe, excludeRe)
			}
		}
	}
}

// Stop signals the collector to stop.
func (c *LogCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		close(c.stopCh)
		for _, t := range c.tailers {
			t.Stop()
		}
		if c.journald != nil {
			c.journald.Stop()
		}
	}
	return nil
}

// Collect returns self-monitoring metrics.
func (c *LogCollector) Collect(_ context.Context) ([]collector.Metric, error) {
	lines := c.linesTotal.Load()
	bytes := c.bytesTotal.Load()

	return []collector.Metric{
		collector.NewMetric("tfo.log_collector.lines_total", float64(lines), collector.MetricTypeCounter).
			WithDescription("Total log lines collected"),
		collector.NewMetric("tfo.log_collector.bytes_total", float64(bytes), collector.MetricTypeCounter).
			WithDescription("Total log bytes collected"),
	}, nil
}

// GetState returns the current per-tailer (path, inode, offset) snapshot for
// persistence by the persister framework. It implements plugin.StatefulPlugin.
// The returned value is always a non-nil *CollectorState, even when no tailers
// are configured, so the persister has a stable shape to serialize.
func (c *LogCollector) GetState() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state := NewCollectorState()
	for _, t := range c.tailers {
		ts := t.State()
		state.Tailers[ts.Path] = ts
	}
	return state
}

// SetState restores tailer offsets from persisted state. It is called by the
// persister at agent startup BEFORE Start() creates the FileTailers, so the
// restored state is consulted when each tailer is constructed. It implements
// plugin.StatefulPlugin.
//
// The persister decodes the on-disk JSON into generic interface{} values, so
// SetState accepts both *CollectorState (direct programmatic calls) and
// map[string]interface{} (the shape produced by encoding/json). Unknown or
// malformed payloads are ignored rather than panicking — the worst case is
// that tailers start from EOF as they would on a first run.
func (c *LogCollector) SetState(s interface{}) {
	if s == nil {
		return
	}
	switch v := s.(type) {
	case *CollectorState:
		c.mu.Lock()
		c.restoredState = v
		c.mu.Unlock()
	case CollectorState:
		c.mu.Lock()
		c.restoredState = &v
		c.mu.Unlock()
	case map[string]interface{}:
		state, err := collectorStateFromMap(v)
		if err != nil {
			c.logger.Warn("log collector: ignoring malformed persisted state",
				zap.Error(err))
			return
		}
		c.mu.Lock()
		c.restoredState = state
		c.mu.Unlock()
	default:
		// Unknown shape — ignore silently. This matches the persister's
		// design that SetState must never panic on unexpected input.
	}
}

// collectorStateFromMap decodes the generic map[string]interface{} shape
// produced by encoding/json back into a typed CollectorState. It is lenient:
// missing fields default to zero values, and type mismatches cause the
// offending entry to be skipped rather than failing the whole decode.
func collectorStateFromMap(m map[string]interface{}) (*CollectorState, error) {
	state := NewCollectorState()
	rawTailers, ok := m["tailers"]
	if !ok {
		return state, nil
	}
	tailersMap, ok := rawTailers.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("persister state: 'tailers' is not an object")
	}
	for path, raw := range tailersMap {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		ts := TailerState{Path: path}
		if v, err := toUint64(entry["inode"]); err == nil {
			ts.Inode = v
		}
		if v, err := toInt64(entry["offset"]); err == nil {
			ts.Offset = v
		}
		if fp, ok := entry["fingerprint"].(string); ok {
			ts.Fingerprint = fp
		}
		state.Tailers[path] = ts
	}
	return state, nil
}

// toUint64 coerces a JSON-decoded numeric value to uint64.
func toUint64(v interface{}) (uint64, error) {
	switch n := v.(type) {
	case float64:
		return uint64(n), nil
	case int:
		return uint64(n), nil
	case int64:
		return uint64(n), nil
	case uint64:
		return n, nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, err
		}
		return uint64(i), nil
	}
	return 0, fmt.Errorf("not a number")
}

// toInt64 coerces a JSON-decoded numeric value to int64.
func toInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case uint64:
		return int64(n), nil
	case json.Number:
		return n.Int64()
	}
	return 0, fmt.Errorf("not a number")
}

// drainFileTailer reads all pending lines from a file tailer.
func (c *LogCollector) drainFileTailer(t *FileTailer, include, exclude []*regexp.Regexp) {
	now := time.Now()
	for {
		select {
		case line := <-t.Lines():
			if !matchesFilter(line, include, exclude) {
				continue
			}
			c.linesTotal.Add(1)
			c.bytesTotal.Add(int64(len(line)))
			if c.logCallback != nil {
				c.logCallback(now, "INFO", line, t.Path(), map[string]string{
					"host.name":              c.hostname,
					"telemetryflow.agent.id": c.agentID,
					"log.file.path":          t.Path(),
				})
			}
		default:
			return
		}
	}
}

// drainJournald reads all pending entries from the journald collector.
func (c *LogCollector) drainJournald(j *JournaldCollector, include, exclude []*regexp.Regexp) {
	ch := j.Lines()
	if ch == nil {
		return
	}
	now := time.Now()
	for {
		select {
		case entry := <-ch:
			if !matchesFilter(entry.Message, include, exclude) {
				continue
			}
			c.linesTotal.Add(1)
			c.bytesTotal.Add(int64(len(entry.Message)))
			severity := "INFO"
			switch entry.Priority {
			case "fatal":
				severity = "FATAL"
			case "error":
				severity = "ERROR"
			case "warn":
				severity = "WARN"
			case "debug":
				severity = "DEBUG"
			}
			if c.logCallback != nil {
				c.logCallback(now, severity, entry.Message, "journald", map[string]string{
					"host.name":              c.hostname,
					"telemetryflow.agent.id": c.agentID,
					"log.source":             "journald",
					"log.systemd.unit":       entry.Unit,
				})
			}
		default:
			return
		}
	}
}

// compilePatterns compiles a list of regex patterns, skipping invalid ones.
func compilePatterns(patterns []string) []*regexp.Regexp {
	var result []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			result = append(result, re)
		}
	}
	return result
}

// matchesFilter returns true if the line passes include/exclude filters.
// If no include patterns, all lines pass. If any exclude pattern matches, line is dropped.
func matchesFilter(line string, include, exclude []*regexp.Regexp) bool {
	if len(include) > 0 {
		matched := false
		for _, re := range include {
			if re.MatchString(line) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, re := range exclude {
		if re.MatchString(line) {
			return false
		}
	}
	return true
}
