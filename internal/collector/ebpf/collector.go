// Package ebpf implements a kernel-level metrics collector using eBPF programs
// attached to tracepoints and kprobes. It captures syscall counts, TCP/UDP
// connections, file I/O, scheduler events, memory page faults, and — optionally
// — Cilium Hubble network-flow data. On non-Linux platforms the collector is a
// no-op stub.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
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
package ebpf

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// EBPFCollector collects kernel-level metrics using eBPF programs.
// It implements the collector.Collector interface.
//
// On non-Linux platforms, Collect() returns empty metrics.
// On Linux, it attaches BPF programs to tracepoints and kprobes,
// reads aggregated data from BPF maps, and converts them to metrics.
type EBPFCollector struct {
	cfg    *collectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}

	// hubble is the optional Cilium Hubble gRPC client (nil when disabled)
	hubble *hubbleClient
}

// NewEBPFCollector creates a new eBPF collector.
// Returns an error if configuration is invalid or platform checks fail.
func NewEBPFCollector(cfg config.EBPFCollectorConfig, logger *zap.Logger) (*EBPFCollector, error) {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}

	cc := newCollectorConfig(cfg, logger)
	if err := cc.validate(); err != nil {
		return nil, err
	}

	if !isLinux() {
		logger.Info("eBPF collector: not running on Linux, metrics will be empty")
	}

	c := &EBPFCollector{
		cfg:      cc,
		logger:   logger,
		stopChan: make(chan struct{}),
	}

	if cfg.Cilium.Enabled {
		c.hubble = newHubbleClient(cfg.Cilium, logger)
	}

	return c, nil
}

// Name returns the collector name.
func (c *EBPFCollector) Name() string {
	return "ebpf"
}

// Start starts the eBPF collector. It loads BPF programs (on Linux),
// then enters a collection loop at the configured interval.
func (c *EBPFCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	c.logger.Info("Starting eBPF collector",
		zap.Duration("interval", c.cfg.raw.Interval),
		zap.Bool("syscalls", c.cfg.raw.CollectSyscalls),
		zap.Bool("network", c.cfg.raw.CollectNetwork),
		zap.Bool("fileio", c.cfg.raw.CollectFileIO),
		zap.Bool("scheduler", c.cfg.raw.CollectScheduler),
		zap.Bool("memory", c.cfg.raw.CollectMemory),
		zap.Bool("tcp_events", c.cfg.raw.CollectTCPEvents),
		zap.Bool("cilium", c.cfg.raw.Cilium.Enabled),
	)

	// Load BPF programs (Linux-only, no-op on other platforms)
	if err := c.loadPrograms(); err != nil {
		c.logger.Error("Failed to load eBPF programs", zap.Error(err))
		return err
	}
	defer c.closePrograms()

	// Connect to Hubble Relay if enabled
	if c.hubble != nil {
		if err := c.hubble.connect(ctx); err != nil {
			c.logger.Warn("Failed to connect to Hubble Relay, disabling Cilium metrics", zap.Error(err))
		}
		defer c.hubble.close()
	}

	ticker := time.NewTicker(c.cfg.raw.Interval)
	defer ticker.Stop()

	// Initial collection
	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial eBPF collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopChan:
			return nil
		case <-ticker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("eBPF collection failed", zap.Error(err))
			}
		}
	}
}

// Stop stops the eBPF collector.
func (c *EBPFCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.running = false
	c.logger.Info("eBPF collector stopped")
	return nil
}

// IsRunning returns whether the collector is running.
func (c *EBPFCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Collect performs a single collection cycle, dispatching to enabled
// sub-collectors. On non-Linux platforms, returns empty metrics.
func (c *EBPFCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if !isLinux() {
		return nil, nil
	}

	if !c.cfg.hasAnySubCollector() {
		return nil, nil
	}

	metrics := c.collectAll(ctx)
	c.logger.Debug("eBPF collected metrics", zap.Int("count", len(metrics)))
	return metrics, nil
}
