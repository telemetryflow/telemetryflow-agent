// Package exporter contains all outbound data-path components: OTLP metric/
// trace/log export, periodic heartbeat to the TelemetryFlow backend, Kubernetes
// cluster-state sync, and the self-observability Prometheus registry and
// HTTP /metrics server.
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
package exporter

import (
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// MetricsBridge translates collector.Metric into Prometheus metrics.
type MetricsBridge struct {
	mu            sync.RWMutex
	registry      *prometheus.Registry
	gauges        map[string]*prometheus.GaugeVec
	gaugeLabels   map[string][]string
	counters      map[string]*prometheus.CounterVec
	counterLabels map[string][]string
	prefix        string
	logger        *zap.Logger
}

// NewMetricsBridge creates a new MetricsBridge that translates internal metrics
// to Prometheus format and registers them in the given registry.
func NewMetricsBridge(prefix string, registry *prometheus.Registry, logger *zap.Logger) *MetricsBridge {
	return &MetricsBridge{
		registry:      registry,
		gauges:        make(map[string]*prometheus.GaugeVec),
		gaugeLabels:   make(map[string][]string),
		counters:      make(map[string]*prometheus.CounterVec),
		counterLabels: make(map[string][]string),
		prefix:        prefix,
		logger:        logger,
	}
}

// UpdateMetrics accepts a batch of collector.Metric and updates the Prometheus
// registry accordingly. New metrics are lazily registered on first encounter.
//
// This method is panic-safe: if two instances of the same metric arrive with
// different label cardinality (e.g. one pod has a "node" label and another
// does not), the bridge normalizes labels by padding missing ones with "" and
// expanding the GaugeVec/CounterVec when new labels are discovered.
func (b *MetricsBridge) UpdateMetrics(metrics []collector.Metric) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, m := range metrics {
		promName := b.translateName(m.Name, m.Unit)
		incomingLabels := sortedLabelKeys(m.Labels)

		switch m.Type {
		case collector.MetricTypeCounter:
			cv := b.getOrCreateCounter(promName, m.Description, incomingLabels)
			if cv != nil {
				normalized := normalizeLabels(m.Labels, b.counterLabels[promName])
				cv.With(normalized).Add(m.Value)
			}
		default:
			gv := b.getOrCreateGauge(promName, m.Description, incomingLabels)
			if gv != nil {
				normalized := normalizeLabels(m.Labels, b.gaugeLabels[promName])
				gv.With(normalized).Set(m.Value)
			}
		}
	}
}

// ResetAll unregisters all dynamic metrics and clears internal state.
func (b *MetricsBridge) ResetAll() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for name, gv := range b.gauges {
		b.registry.Unregister(gv)
		delete(b.gauges, name)
		delete(b.gaugeLabels, name)
	}
	for name, cv := range b.counters {
		b.registry.Unregister(cv)
		delete(b.counters, name)
		delete(b.counterLabels, name)
	}
}

// translateName converts an internal metric name to a Prometheus-compatible name.
func (b *MetricsBridge) translateName(name, unit string) string {
	promName := b.prefix + "_" + strings.ReplaceAll(name, ".", "_")

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

// sortedLabelKeys returns the keys of a label map, sorted alphabetically.
func sortedLabelKeys(labels prometheus.Labels) []string {
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// normalizeLabels adapts a metric's labels to match the canonical label set.
// Missing labels are padded with "" so that .With() never panics on
// cardinality mismatch. Extra labels not in the canonical set are dropped.
func normalizeLabels(labels prometheus.Labels, canonical []string) prometheus.Labels {
	result := make(prometheus.Labels, len(canonical))
	for _, name := range canonical {
		if v, ok := labels[name]; ok {
			result[name] = v
		} else {
			result[name] = ""
		}
	}
	return result
}

// getOrCreateGauge returns an existing GaugeVec or creates and registers a new one.
// The label set from the FIRST metric with a given name becomes canonical —
// subsequent metrics are normalized (padded/dropped) before calling .With().
// This avoids panics from label cardinality mismatch without the complexity
// of unregister/re-register churn.
func (b *MetricsBridge) getOrCreateGauge(name, help string, incomingLabels []string) *prometheus.GaugeVec {
	if gv, ok := b.gauges[name]; ok {
		return gv
	}

	if help == "" {
		help = name
	}

	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, incomingLabels)

	if err := b.registry.Register(gv); err != nil {
		b.logger.Debug("Failed to register gauge",
			zap.String("metric", name),
			zap.Error(err),
		)
		return nil
	}

	b.gauges[name] = gv
	b.gaugeLabels[name] = incomingLabels
	return gv
}

// getOrCreateCounter returns an existing CounterVec or creates and registers a new one.
// Uses the same canonical-label approach as getOrCreateGauge.
func (b *MetricsBridge) getOrCreateCounter(name, help string, incomingLabels []string) *prometheus.CounterVec {
	if cv, ok := b.counters[name]; ok {
		return cv
	}

	if help == "" {
		help = name
	}

	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, incomingLabels)

	if err := b.registry.Register(cv); err != nil {
		b.logger.Debug("Failed to register counter",
			zap.String("metric", name),
			zap.Error(err),
		)
		return nil
	}

	b.counters[name] = cv
	b.counterLabels[name] = incomingLabels
	return cv
}
