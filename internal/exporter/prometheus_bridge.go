// Package exporter contains all outbound data-path components: OTLP metric/
// trace/log export, periodic heartbeat to the TelemetryFlow backend, Kubernetes
// cluster-state sync, and the self-observability Prometheus registry and
// HTTP /metrics server.
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
package exporter

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// MetricsBridge translates collector.Metric into Prometheus metrics.
type MetricsBridge struct {
	mu       sync.RWMutex
	registry *prometheus.Registry
	gauges   map[string]*prometheus.GaugeVec
	counters map[string]*prometheus.CounterVec
	prefix   string
	logger   *zap.Logger
}

// NewMetricsBridge creates a new MetricsBridge that translates internal metrics
// to Prometheus format and registers them in the given registry.
func NewMetricsBridge(prefix string, registry *prometheus.Registry, logger *zap.Logger) *MetricsBridge {
	return &MetricsBridge{
		registry: registry,
		gauges:   make(map[string]*prometheus.GaugeVec),
		counters: make(map[string]*prometheus.CounterVec),
		prefix:   prefix,
		logger:   logger,
	}
}

// UpdateMetrics accepts a batch of collector.Metric and updates the Prometheus
// registry accordingly. New metrics are lazily registered on first encounter.
func (b *MetricsBridge) UpdateMetrics(metrics []collector.Metric) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, m := range metrics {
		promName := b.translateName(m.Name, m.Unit)
		labelNames := b.labelNames(m.Labels)

		switch m.Type {
		case collector.MetricTypeGauge:
			gv := b.getOrCreateGauge(promName, m.Description, labelNames)
			if gv != nil {
				gv.With(m.Labels).Set(m.Value)
			}
		case collector.MetricTypeCounter:
			cv := b.getOrCreateCounter(promName, m.Description, labelNames)
			if cv != nil {
				cv.With(m.Labels).Add(m.Value)
			}
		default:
			// Treat unknown types as gauge
			gv := b.getOrCreateGauge(promName, m.Description, labelNames)
			if gv != nil {
				gv.With(m.Labels).Set(m.Value)
			}
		}
	}
}

// ResetAll unregisters all dynamic metrics and clears internal state.
// This is useful before a full metric refresh to avoid stale series.
func (b *MetricsBridge) ResetAll() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for name, gv := range b.gauges {
		b.registry.Unregister(gv)
		delete(b.gauges, name)
	}
	for name, cv := range b.counters {
		b.registry.Unregister(cv)
		delete(b.counters, name)
	}
}

// translateName converts an internal metric name to a Prometheus-compatible name.
// Rules: prefix + dots→underscores + unit suffix for bytes/seconds.
func (b *MetricsBridge) translateName(name, unit string) string {
	promName := b.prefix + "_" + strings.ReplaceAll(name, ".", "_")

	// Add standard suffixes per Prometheus naming conventions
	switch unit {
	case "bytes":
		if !strings.HasSuffix(promName, "_bytes") {
			promName += "_bytes"
		}
	case "seconds":
		if !strings.HasSuffix(promName, "_seconds") {
			promName += "_seconds"
		}
	}

	return promName
}

// labelNames extracts sorted label keys from a label map.
func (b *MetricsBridge) labelNames(labels map[string]string) []string {
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	return names
}

// getOrCreateGauge returns an existing GaugeVec or creates and registers a new one.
func (b *MetricsBridge) getOrCreateGauge(name, help string, labelNames []string) *prometheus.GaugeVec {
	if gv, ok := b.gauges[name]; ok {
		return gv
	}

	if help == "" {
		help = name
	}

	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labelNames)

	if err := b.registry.Register(gv); err != nil {
		// Already registered (possibly with different labels) — log and skip
		b.logger.Debug("Failed to register gauge",
			zap.String("metric", name),
			zap.Error(err),
		)
		return nil
	}

	b.gauges[name] = gv
	return gv
}

// getOrCreateCounter returns an existing CounterVec or creates and registers a new one.
func (b *MetricsBridge) getOrCreateCounter(name, help string, labelNames []string) *prometheus.CounterVec {
	if cv, ok := b.counters[name]; ok {
		return cv
	}

	if help == "" {
		help = name
	}

	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, labelNames)

	if err := b.registry.Register(cv); err != nil {
		b.logger.Debug("Failed to register counter",
			zap.String("metric", name),
			zap.Error(err),
		)
		return nil
	}

	b.counters[name] = cv
	return cv
}
