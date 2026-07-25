// Package internalstats implements the Telegraf-compatible "internal" selfstat
// collector. On every Collect cycle it snapshots the global selfstat registry
// (agent/collector/exporter/plugin counters and timings) into the normal
// metric pipeline.
//
// The package name avoids the reserved Go identifier "internal"; the
// collector NAME returned by Name() is "internal" for Telegraf compatibility.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package internalstats

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
	"github.com/telemetryflow/telemetryflow-agent/internal/selfstat"
)

// collectorName is the user-visible collector name. Mirrors Telegraf's
// "internal" input plugin so existing dashboards keep working.
const collectorName = "internal"

// InternalStatsCollector snapshots the selfstat registry into the metric
// pipeline on each Collect call.
type InternalStatsCollector struct {
	cfg      config.InternalStatsCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewInternalStatsCollector returns a collector bound to the supplied config.
// The logger is sub-named under the collector name.
func NewInternalStatsCollector(cfg config.InternalStatsCollectorConfig, logger *zap.Logger) *InternalStatsCollector {
	return &InternalStatsCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

// Name returns "internal" (Telegraf-compatible).
func (c *InternalStatsCollector) Name() string { return collectorName }

// IsRunning reports whether the collector is in the started state.
func (c *InternalStatsCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Start marks the collector as running.
func (c *InternalStatsCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("internal collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("internal stats collector starting")
	return nil
}

// Stop marks the collector as stopped. Safe to call multiple times.
func (c *InternalStatsCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect returns the current snapshot of all selfstat metrics, converted to
// the legacy collector.Metric type via the plugin adapter. Returns an empty
// slice when no stats are registered.
func (c *InternalStatsCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	pluginMetrics := selfstat.AllMetrics()
	out := make([]collector.Metric, 0, len(pluginMetrics))
	for _, m := range pluginMetrics {
		out = append(out, plugin.ToLegacyMetric(m))
	}
	return out, nil
}
