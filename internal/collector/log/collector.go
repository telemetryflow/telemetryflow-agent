// Package log implements file-based and journald log collection for TFO-Agent.
//
// The LogCollector tails configured file paths and optionally follows systemd
// journal entries, batching them and exporting via the OTLP logs pipeline.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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
	"os"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// LogCollector collects logs from file paths and journald, exporting them via OTLP.
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

	// logCallback is called for each collected log line.
	// Set by the agent to wire into the OTLP LoggerProvider.
	logCallback func(timestamp time.Time, severity, body, source string, attrs map[string]string)
}

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

	// Create file tailers
	for _, p := range paths {
		tailer := NewFileTailer(p, maxLine, c.logger)
		c.tailers = append(c.tailers, tailer)
		go func(t *FileTailer) {
			if err := t.Start(ctx); err != nil && err != context.Canceled {
				c.logger.Warn("File tailer stopped", zap.String("path", t.Path()), zap.Error(err))
			}
		}(tailer)
	}

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
