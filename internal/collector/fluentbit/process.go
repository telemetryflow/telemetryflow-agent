// Package fluentbit embeds Fluent Bit as a managed subprocess log collector.
//
// process.go manages the Fluent Bit subprocess lifecycle: start, stop, health
// check, and automatic restart on crash with configurable backoff.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
package fluentbit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	stderrBufferSize = 50 // number of recent stderr lines to keep
	shutdownTimeout  = 10 * time.Second
)

// ProcessManager manages a Fluent Bit subprocess.
type ProcessManager struct {
	binaryPath   string
	configPath   string
	logger       *zap.Logger
	healthPort   int
	restartCrash bool
	restartDelay time.Duration
	maxRestarts  int

	mu           sync.Mutex
	cmd          *exec.Cmd
	running      bool
	restartCount int
	startTime    time.Time
	stderrLines  []string // circular buffer of recent stderr
}

// NewProcessManager creates a new Fluent Bit process manager.
func NewProcessManager(binaryPath, configPath string, healthPort int, restartCrash bool, restartDelay time.Duration, maxRestarts int, logger *zap.Logger) *ProcessManager {
	return &ProcessManager{
		binaryPath:   binaryPath,
		configPath:   configPath,
		logger:       logger,
		healthPort:   healthPort,
		restartCrash: restartCrash,
		restartDelay: restartDelay,
		maxRestarts:  maxRestarts,
		stderrLines:  make([]string, 0, stderrBufferSize),
	}
}

// RunWithAutoRestart starts Fluent Bit and restarts it on crash. Blocks until ctx is done.
func (p *ProcessManager) RunWithAutoRestart(ctx context.Context) error {
	for {
		err := p.startProcess(ctx)

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			p.logger.Warn("Fluent Bit process exited",
				zap.Error(err),
				zap.Int("restart_count", p.restartCount),
			)

			// Fail fast if the binary is missing — retrying won't help
			if errors.Is(err, exec.ErrNotFound) {
				return fmt.Errorf("fluent-bit binary not found at %s: %w", p.binaryPath, err)
			}
		}

		if !p.restartCrash {
			return fmt.Errorf("fluent-bit exited and restart_on_crash is disabled: %w", err)
		}

		p.mu.Lock()
		p.restartCount++
		count := p.restartCount
		p.mu.Unlock()

		if p.maxRestarts > 0 && count > p.maxRestarts {
			return fmt.Errorf("fluent-bit exceeded max restarts (%d)", p.maxRestarts)
		}

		p.logger.Info("Restarting Fluent Bit after crash",
			zap.Int("restart_count", count),
			zap.Duration("delay", p.restartDelay),
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(p.restartDelay):
		}
	}
}

// startProcess spawns Fluent Bit and waits for it to exit.
func (p *ProcessManager) startProcess(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, p.binaryPath, "-c", p.configPath)

	// Capture stderr for diagnostics
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start fluent-bit: %w", err)
	}

	p.mu.Lock()
	p.cmd = cmd
	p.running = true
	p.startTime = time.Now()
	p.mu.Unlock()

	p.logger.Info("Fluent Bit started",
		zap.Int("pid", cmd.Process.Pid),
		zap.String("config", p.configPath),
	)

	// Read stderr in background
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			p.appendStderr(line)
			p.logger.Debug("fluent-bit", zap.String("stderr", line))
		}
	}()

	// Wait for process to exit
	waitErr := cmd.Wait()

	p.mu.Lock()
	p.running = false
	p.cmd = nil
	p.mu.Unlock()

	return waitErr
}

// Stop gracefully stops the Fluent Bit process.
func (p *ProcessManager) Stop() error {
	p.mu.Lock()
	cmd := p.cmd
	p.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	p.logger.Info("Stopping Fluent Bit", zap.Int("pid", cmd.Process.Pid))

	// Send SIGTERM for graceful shutdown
	if err := cmd.Process.Signal(sigterm()); err != nil {
		p.logger.Debug("SIGTERM failed, killing", zap.Error(err))
		return cmd.Process.Kill()
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		return nil
	case <-time.After(shutdownTimeout):
		p.logger.Warn("Fluent Bit did not stop gracefully, killing")
		return cmd.Process.Kill()
	}
}

// IsRunning returns whether Fluent Bit is currently running.
func (p *ProcessManager) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// PID returns the current Fluent Bit process ID, or 0 if not running.
func (p *ProcessManager) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// RestartCount returns the number of times Fluent Bit has been restarted.
func (p *ProcessManager) RestartCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.restartCount
}

// UptimeSeconds returns seconds since the current process started.
func (p *ProcessManager) UptimeSeconds() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running || p.startTime.IsZero() {
		return 0
	}
	return time.Since(p.startTime).Seconds()
}

// IsHealthy checks Fluent Bit's health endpoint.
func (p *ProcessManager) IsHealthy() bool {
	if p.healthPort <= 0 {
		return p.IsRunning()
	}
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", p.healthPort))
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// RecentStderr returns the most recent stderr lines for diagnostics.
func (p *ProcessManager) RecentStderr() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.stderrLines))
	copy(out, p.stderrLines)
	return out
}

func (p *ProcessManager) appendStderr(line string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.stderrLines) >= stderrBufferSize {
		p.stderrLines = p.stderrLines[1:]
	}
	p.stderrLines = append(p.stderrLines, line)
}
