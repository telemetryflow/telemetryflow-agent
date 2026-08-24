// Package log implements file-based and journald log collection for TFO-Agent.
//
// journald_linux follows the systemd journal via journalctl --follow --output=json,
// parsing structured entries and emitting them as LogEntry values.
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

//go:build linux

package log

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// JournaldCollector follows the systemd journal and emits structured log entries.
type JournaldCollector struct {
	cfg    config.JournaldConfig
	logger *zap.Logger
	lines  chan LogEntry

	// mu guards cancel/stopped: Start runs on its own goroutine while Stop is
	// called from the agent lifecycle goroutine, so the handoff of the cancel
	// func must be synchronized (race detector: context.WithCancel writes and
	// the concurrent cancel() call would otherwise race).
	mu      sync.Mutex
	cancel  context.CancelFunc
	stopped bool
}

// LogEntry is a structured log line from journald.
type LogEntry struct {
	Unit     string // systemd unit name
	Priority string // emerg, alert, crit, err, warning, notice, info, debug
	Message  string
}

// NewJournaldCollector creates a journald collector.
func NewJournaldCollector(cfg config.JournaldConfig, logger *zap.Logger) *JournaldCollector {
	return &JournaldCollector{
		cfg:    cfg,
		logger: logger,
		lines:  make(chan LogEntry, 2048),
	}
}

// Lines returns the channel of structured log entries.
func (j *JournaldCollector) Lines() <-chan LogEntry { return j.lines }

// Start begins following the journal. Blocks until context is cancelled.
func (j *JournaldCollector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)

	j.mu.Lock()
	if j.stopped {
		// Stop() was called before Start(): self-cancel and bail out.
		j.mu.Unlock()
		cancel()
		return ctx.Err()
	}
	j.cancel = cancel
	j.mu.Unlock()

	args := []string{"--follow", "--output=json", "--no-pager", "--boot=0"}

	// Add unit filters
	for _, unit := range j.cfg.Units {
		args = append(args, "-u", unit)
	}

	// Add priority filter
	if len(j.cfg.Priorities) > 0 {
		args = append(args, fmt.Sprintf("--priority=%s", strings.Join(j.cfg.Priorities, ",")))
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl start: %w", err)
	}

	j.logger.Info("Journald collector started",
		zap.Strings("units", j.cfg.Units),
		zap.Strings("priorities", j.cfg.Priorities),
	)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	go func() {
		defer func() { _ = cmd.Wait() }()

		for scanner.Scan() {
			var entry map[string]interface{}
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				continue // Skip non-JSON lines
			}

			msg, _ := entry["MESSAGE"].(string)
			if msg == "" {
				continue
			}

			unit, _ := entry["_SYSTEMD_UNIT"].(string)
			if unit == "" {
				unit, _ = entry["SYSLOG_IDENTIFIER"].(string)
			}

			priority := "info"
			if p, ok := entry["PRIORITY"].(string); ok {
				priority = journalPriorityToLevel(p)
			}

			select {
			case j.lines <- LogEntry{Unit: unit, Priority: priority, Message: msg}:
			default:
				// Channel full — drop to prevent backpressure
			}
		}
	}()

	<-ctx.Done()
	return ctx.Err()
}

// Stop cancels the journald follower. Safe to call before or while Start is
// running, and idempotent.
func (j *JournaldCollector) Stop() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.stopped = true
	if j.cancel != nil {
		j.cancel()
	}
}

// journalPriorityToLevel maps numeric journal priority to severity name.
func journalPriorityToLevel(p string) string {
	switch p {
	case "0", "1", "2":
		return "fatal"
	case "3":
		return "error"
	case "4":
		return "warn"
	case "5", "6":
		return "info"
	case "7":
		return "debug"
	default:
		return "info"
	}
}
