// Package exporter provides the metric forwarder that bridges collectors
// to export destinations (OTLP HTTP bridge + Prometheus bridge).
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
package exporter

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// MetricSink is the interface for exporting collected metrics.
type MetricSink interface {
	Export(ctx context.Context, metrics []collector.Metric, resourceAttrs map[string]string) error
}

// PrometheusSink is the interface for pushing metrics into the Prometheus bridge.
type PrometheusSink interface {
	UpdateMetrics(metrics []collector.Metric)
}

// MetricForwarder periodically collects metrics from all collectors and
// forwards them to one or more sinks (OTLP bridge, Prometheus bridge).
//
// It is the missing piece that connects the collector data path to the
// export pipeline. Without it, collectors collect metrics and discard them.
type MetricForwarder struct {
	collectors []collector.Collector
	otlpSink   MetricSink
	promSink   PrometheusSink
	logger     *zap.Logger
	interval   time.Duration

	mu            sync.RWMutex
	running       bool
	stopChan      chan struct{}
	totalExport   atomic.Int64
	totalError    atomic.Int64
	totalMetric   atomic.Int64
	firstExportOK atomic.Bool
}

// MetricForwarderConfig holds configuration for the forwarder.
type MetricForwarderConfig struct {
	Collectors []collector.Collector
	OTLPSink   MetricSink
	PromSink   PrometheusSink
	Interval   time.Duration
	Logger     *zap.Logger
}

// NewMetricForwarder creates a new metric forwarder.
func NewMetricForwarder(cfg MetricForwarderConfig) *MetricForwarder {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	return &MetricForwarder{
		collectors: cfg.Collectors,
		otlpSink:   cfg.OTLPSink,
		promSink:   cfg.PromSink,
		logger:     logger.Named("forwarder"),
		interval:   cfg.Interval,
		stopChan:   make(chan struct{}),
	}
}

// Start begins the periodic collection-and-forward loop.
func (f *MetricForwarder) Start(ctx context.Context) error {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return nil
	}
	f.running = true
	f.stopChan = make(chan struct{})
	f.mu.Unlock()

	f.logger.Info("metric forwarder starting",
		zap.Int("collectors", len(f.collectors)),
		zap.Duration("interval", f.interval),
		zap.Bool("otlp_enabled", f.otlpSink != nil),
		zap.Bool("prom_enabled", f.promSink != nil),
	)

	go f.loop(ctx)
	return nil
}

// Stop signals the forwarder to stop.
func (f *MetricForwarder) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.running {
		return nil
	}
	close(f.stopChan)
	f.running = false
	f.logger.Info("metric forwarder stopped",
		zap.Int64("total_exports", f.totalExport.Load()),
		zap.Int64("total_metrics", f.totalMetric.Load()),
		zap.Int64("total_errors", f.totalError.Load()),
	)
	return nil
}

// IsRunning returns whether the forwarder is running.
func (f *MetricForwarder) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}

// Stats returns forwarder statistics.
func (f *MetricForwarder) Stats() ForwarderStats {
	return ForwarderStats{
		Running:      f.IsRunning(),
		TotalExports: f.totalExport.Load(),
		TotalMetrics: f.totalMetric.Load(),
		TotalErrors:  f.totalError.Load(),
	}
}

// ForwarderStats contains forwarder statistics.
type ForwarderStats struct {
	Running      bool  `json:"running"`
	TotalExports int64 `json:"totalExports"`
	TotalMetrics int64 `json:"totalMetrics"`
	TotalErrors  int64 `json:"totalErrors"`
}

func (f *MetricForwarder) loop(ctx context.Context) {
	f.forwardAll(ctx)

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-f.stopChan:
			return
		case <-ticker.C:
			f.forwardAll(ctx)
		}
	}
}

func (f *MetricForwarder) forwardAll(ctx context.Context) {
	var allMetrics []collector.Metric

	for _, c := range f.collectors {
		if !c.IsRunning() {
			continue
		}
		metrics, err := c.Collect(ctx)
		if err != nil {
			f.logger.Warn("collect failed",
				zap.String("collector", c.Name()),
				zap.Error(err),
			)
			continue
		}
		if len(metrics) > 0 {
			allMetrics = append(allMetrics, metrics...)
		}
	}
	if len(allMetrics) == 0 {
		f.logger.Debug("no metrics collected in this cycle",
			zap.Int("collectors_running", f.runningCollectorCount()),
		)
		return
	}

	breakdown := summarizeMetrics(allMetrics)

	if !f.firstExportOK.Swap(true) {
		for _, e := range breakdown {
			f.logger.Info("metric registered",
				zap.String("name", e.name),
				zap.Int("series", e.count),
				zap.Strings("labels", e.labelKeys),
				zap.String("unit", e.unit),
			)
		}
	} else {
		f.logger.Debug("metric breakdown",
			zap.Int("series", len(breakdown)),
		)
		for _, e := range breakdown {
			f.logger.Debug("metric",
				zap.String("name", e.name),
				zap.Int("series", e.count),
				zap.Strings("labels", e.labelKeys),
			)
		}
	}

	if f.promSink != nil {
		f.promSink.UpdateMetrics(allMetrics)
	}

	if f.otlpSink != nil {
		if err := f.otlpSink.Export(ctx, allMetrics, nil); err != nil {
			f.totalError.Add(1)
			f.logger.Warn("OTLP export failed",
				zap.Int("metrics", len(allMetrics)),
				zap.Int("unique_names", len(breakdown)),
				zap.Error(err),
			)
		} else {
			f.totalExport.Add(1)
			f.totalMetric.Add(int64(len(allMetrics)))

			f.logger.Info("metrics forwarded",
				zap.Int("metrics", len(allMetrics)),
				zap.Int("unique_names", len(breakdown)),
				zap.Int64("total_exports", f.totalExport.Load()),
				zap.Int64("total_metrics", f.totalMetric.Load()),
			)
		}
	}
}

func (f *MetricForwarder) runningCollectorCount() int {
	count := 0
	for _, c := range f.collectors {
		if c.IsRunning() {
			count++
		}
	}
	return count
}

type metricEntry struct {
	name      string
	count     int
	labelKeys []string
	unit      string
}

func summarizeMetrics(metrics []collector.Metric) []metricEntry {
	type agg struct {
		count    int
		labelSet map[string]bool
		unit     string
	}
	byName := make(map[string]*agg)

	for _, m := range metrics {
		key := m.Name
		if m.Unit != "" {
			key += "[" + m.Unit + "]"
		}
		a, ok := byName[key]
		if !ok {
			a = &agg{labelSet: make(map[string]bool)}
			byName[key] = a
		}
		a.count++
		a.unit = m.Unit
		for k := range m.Labels {
			a.labelSet[k] = true
		}
	}

	entries := make([]metricEntry, 0, len(byName))
	for name, a := range byName {
		cleanName := name
		if idx := strings.Index(name, "["); idx >= 0 {
			cleanName = name[:idx]
		}
		keys := make([]string, 0, len(a.labelSet))
		for k := range a.labelSet {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		entries = append(entries, metricEntry{
			name:      cleanName,
			count:     a.count,
			labelKeys: keys,
			unit:      a.unit,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})
	return entries
}
