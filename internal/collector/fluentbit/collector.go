// Package fluentbit embeds Fluent Bit as a managed subprocess log collector.
//
// FluentBitCollector implements the collector.Collector interface, managing
// the Fluent Bit subprocess lifecycle: config generation, process spawning,
// health monitoring, auto-restart on crash, and self-monitoring metrics.
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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// FluentBitCollector manages a Fluent Bit subprocess for production-grade log collection.
type FluentBitCollector struct {
	cfg     config.FluentBitCollectorConfig
	tfCfg   config.TelemetryFlowConfig
	logger  *zap.Logger
	process *ProcessManager
	mu      sync.RWMutex
	running bool
	agentID string
}

// NewFluentBitCollector creates and validates a Fluent Bit collector.
// Returns an error if the fluent-bit binary cannot be found.
func NewFluentBitCollector(
	cfg config.FluentBitCollectorConfig,
	tfCfg config.TelemetryFlowConfig,
	agentID string,
	logger *zap.Logger,
) (*FluentBitCollector, error) {
	// Resolve binary path
	binaryPath := cfg.BinaryPath
	if binaryPath == "" {
		resolved, err := exec.LookPath("fluent-bit")
		if err != nil {
			return nil, fmt.Errorf("fluent-bit binary not found in PATH: %w", err)
		}
		binaryPath = resolved
	} else {
		if _, err := os.Stat(binaryPath); err != nil {
			return nil, fmt.Errorf("fluent-bit binary not found at %s: %w", binaryPath, err)
		}
	}
	cfg.BinaryPath = binaryPath

	// Apply config defaults
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = "/tmp/tfo-agent-fluentbit"
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.HealthPort <= 0 {
		cfg.HealthPort = 2020
	}
	if cfg.RestartDelay <= 0 {
		cfg.RestartDelay = 5e9 // 5 seconds
	}

	// Auto-detect Kubernetes if not explicitly set
	if !cfg.Kubernetes.Enabled && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		cfg.Kubernetes.Enabled = true
		logger.Info("Auto-detected Kubernetes environment, enabling Fluent Bit K8s filter")
	}

	return &FluentBitCollector{
		cfg:     cfg,
		tfCfg:   tfCfg,
		logger:  logger,
		agentID: agentID,
	}, nil
}

// Name returns the collector name.
func (c *FluentBitCollector) Name() string { return "fluent-bit" }

// IsRunning returns whether Fluent Bit is currently running.
func (c *FluentBitCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start generates Fluent Bit config, spawns the subprocess, and blocks until ctx is done.
func (c *FluentBitCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	c.running = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	// Generate config files
	conf, parsers, err := GenerateConfig(c.cfg, c.tfCfg)
	if err != nil {
		return fmt.Errorf("generate fluent-bit config: %w", err)
	}

	if err := WriteConfigs(c.cfg.ConfigDir, conf, parsers); err != nil {
		return fmt.Errorf("write fluent-bit config: %w", err)
	}

	configPath := filepath.Join(c.cfg.ConfigDir, "fluent-bit.conf")
	c.logger.Info("Fluent Bit config generated",
		zap.String("config_dir", c.cfg.ConfigDir),
		zap.String("binary", c.cfg.BinaryPath),
	)

	// Create and start process manager
	c.process = NewProcessManager(
		c.cfg.BinaryPath,
		configPath,
		c.cfg.HealthPort,
		c.cfg.RestartOnCrash,
		c.cfg.RestartDelay,
		c.cfg.MaxRestarts,
		c.logger,
	)

	return c.process.RunWithAutoRestart(ctx)
}

// Stop terminates the Fluent Bit subprocess and cleans up config files.
func (c *FluentBitCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.process != nil {
		if err := c.process.Stop(); err != nil {
			c.logger.Warn("Failed to stop Fluent Bit gracefully", zap.Error(err))
		}
	}

	// Clean up generated config files (non-fatal)
	if c.cfg.ConfigDir != "" {
		_ = os.RemoveAll(c.cfg.ConfigDir)
	}

	c.running = false
	return nil
}

// Collect returns self-monitoring metrics for the Fluent Bit subprocess.
func (c *FluentBitCollector) Collect(_ context.Context) ([]collector.Metric, error) {
	var metrics []collector.Metric

	running := 0.0
	if c.process != nil && c.process.IsRunning() {
		running = 1.0
	}

	metrics = append(metrics,
		collector.NewMetric("tfo.fluentbit.running", running, collector.MetricTypeGauge).
			WithDescription("Fluent Bit process running state (1=running, 0=stopped)"),
	)

	if c.process != nil {
		metrics = append(metrics,
			collector.NewMetric("tfo.fluentbit.pid", float64(c.process.PID()), collector.MetricTypeGauge).
				WithDescription("Fluent Bit process ID"),
			collector.NewMetric("tfo.fluentbit.restart_count", float64(c.process.RestartCount()), collector.MetricTypeCounter).
				WithDescription("Number of Fluent Bit process restarts"),
			collector.NewMetric("tfo.fluentbit.uptime_seconds", c.process.UptimeSeconds(), collector.MetricTypeGauge).
				WithDescription("Fluent Bit process uptime in seconds"),
		)

		if c.process.IsHealthy() {
			metrics = append(metrics,
				collector.NewMetric("tfo.fluentbit.healthy", 1.0, collector.MetricTypeGauge).
					WithDescription("Fluent Bit health check status (1=healthy, 0=unhealthy)"),
			)
		} else {
			metrics = append(metrics,
				collector.NewMetric("tfo.fluentbit.healthy", 0.0, collector.MetricTypeGauge).
					WithDescription("Fluent Bit health check status (1=healthy, 0=unhealthy)"),
			)
		}
	}

	return metrics, nil
}
