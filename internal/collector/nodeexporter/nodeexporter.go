// Package nodeexporter provides a prometheus/node_exporter-equivalent collector.
// When enabled, it exposes detailed system metrics (per-CPU, per-device,
// per-interface, per-mount) as continuous time-series that flow through
// OTLP export and the Prometheus /metrics endpoint.
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
package nodeexporter

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// NodeExporterCollector collects detailed system metrics equivalent to
// prometheus/node_exporter. Each sub-collector can be individually toggled.
type NodeExporterCollector struct {
	cfg    *collectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewNodeExporterCollector creates a new node exporter collector.
func NewNodeExporterCollector(cfg config.NodeExporterConfig, logger *zap.Logger) *NodeExporterCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	return &NodeExporterCollector{
		cfg:      newCollectorConfig(cfg, logger),
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// Name returns the collector name.
func (c *NodeExporterCollector) Name() string {
	return "node_exporter"
}

// Start starts the collector.
func (c *NodeExporterCollector) Start(ctx context.Context) error {
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

	c.logger.Info("Starting node exporter collector",
		zap.Duration("interval", c.cfg.raw.Interval),
	)

	ticker := time.NewTicker(c.cfg.raw.Interval)
	defer ticker.Stop()

	// Initial collection
	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial node exporter collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopChan:
			return nil
		case <-ticker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("Node exporter collection failed", zap.Error(err))
			}
		}
	}
}

// Stop stops the collector.
func (c *NodeExporterCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.running = false
	c.logger.Info("Node exporter collector stopped")
	return nil
}

// IsRunning returns whether the collector is running.
func (c *NodeExporterCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Collect performs a single collection cycle, dispatching to enabled sub-collectors.
func (c *NodeExporterCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	var metrics []collector.Metric

	if c.cfg.raw.CPU {
		if m, err := c.collectCPU(ctx); err != nil {
			c.logger.Debug("CPU sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.LoadAvg {
		if m, err := c.collectLoadAvg(); err != nil {
			c.logger.Debug("LoadAvg sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.Memory {
		if m, err := c.collectMemory(); err != nil {
			c.logger.Debug("Memory sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.DiskIO {
		if m, err := c.collectDiskIO(); err != nil {
			c.logger.Debug("DiskIO sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.Filesystem {
		if m, err := c.collectFilesystem(); err != nil {
			c.logger.Debug("Filesystem sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.Network {
		if m, err := c.collectNetwork(); err != nil {
			c.logger.Debug("Network sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.Thermal {
		if m, err := c.collectThermal(); err != nil {
			c.logger.Debug("Thermal sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	// Linux-only sub-collectors
	if m := c.collectLinux(); len(m) > 0 {
		metrics = append(metrics, m...)
	}

	if c.cfg.raw.Textfile {
		if m, err := c.collectTextfile(); err != nil {
			c.logger.Debug("Textfile sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	c.logger.Debug("Node exporter collected metrics", zap.Int("count", len(metrics)))
	return metrics, nil
}
