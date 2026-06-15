// Package exporter_test contains unit tests for OTLP export, heartbeat,
// Prometheus bridge, and Prometheus server components.
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
package exporter_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func TestMetricsBridgeTranslateName(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	// Feed a metric to trigger registration
	metrics := []collector.Metric{
		collector.NewMetric("system.cpu.usage", 45.5, collector.MetricTypeGauge),
	}
	bridge.UpdateMetrics(metrics)

	// Gather registered metrics
	families, err := registry.Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, f := range families {
		names[*f.Name] = true
	}
	assert.True(t, names["tfo_system_cpu_usage"],
		"expected system.cpu.usage → tfo_system_cpu_usage, got: %v", names)
}

func TestMetricsBridgeByteSuffix(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metrics := []collector.Metric{
		collector.NewMetric("system.memory.total", 8589934592, collector.MetricTypeGauge).
			WithUnit("bytes"),
	}
	bridge.UpdateMetrics(metrics)

	families, err := registry.Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, f := range families {
		names[*f.Name] = true
	}
	assert.True(t, names["tfo_system_memory_total_bytes"],
		"expected bytes unit to add _bytes suffix, got: %v", names)
}

func TestMetricsBridgeLabels(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metrics := []collector.Metric{
		collector.NewMetric("k8s.node.status", 1.0, collector.MetricTypeGauge).
			WithLabel("cluster", "production").
			WithLabel("node", "worker-1"),
	}
	bridge.UpdateMetrics(metrics)

	families, err := registry.Gather()
	require.NoError(t, err)

	for _, f := range families {
		if *f.Name == "tfo_k8s_node_status" {
			require.NotEmpty(t, f.Metric)
			m := f.Metric[0]
			labels := make(map[string]string)
			for _, lp := range m.Label {
				labels[*lp.Name] = *lp.Value
			}
			assert.Equal(t, "production", labels["cluster"])
			assert.Equal(t, "worker-1", labels["node"])
			return
		}
	}
	t.Fatal("expected tfo_k8s_node_status metric family not found")
}

func TestMetricsBridgeMultipleMetrics(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metrics := []collector.Metric{
		collector.NewMetric("system.cpu.usage", 45.0, collector.MetricTypeGauge),
		collector.NewMetric("system.memory.usage", 60.0, collector.MetricTypeGauge),
		collector.NewMetric("k8s.node.status", 1.0, collector.MetricTypeGauge).
			WithLabel("node", "worker-1"),
		collector.NewMetric("k8s.node.status", 0.0, collector.MetricTypeGauge).
			WithLabel("node", "worker-2"),
	}
	bridge.UpdateMetrics(metrics)

	families, err := registry.Gather()
	require.NoError(t, err)

	// Should have 3 unique metric families
	assert.GreaterOrEqual(t, len(families), 3, "expected at least 3 metric families")
}

func TestMetricsBridgeResetAll(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metrics := []collector.Metric{
		collector.NewMetric("system.cpu.usage", 45.0, collector.MetricTypeGauge),
	}
	bridge.UpdateMetrics(metrics)

	families, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)

	bridge.ResetAll()

	families, err = registry.Gather()
	require.NoError(t, err)
	assert.Empty(t, families, "after reset, no metrics should remain")
}

func TestMetricsBridgeCustomPrefix(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("myapp", registry, logger)

	metrics := []collector.Metric{
		collector.NewMetric("system.cpu.usage", 45.0, collector.MetricTypeGauge),
	}
	bridge.UpdateMetrics(metrics)

	families, err := registry.Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, f := range families {
		names[*f.Name] = true
	}
	assert.True(t, names["myapp_system_cpu_usage"],
		"custom prefix should be applied, got: %v", names)
}

func TestMetricsBridgeLabelCardinalityMismatch_NoPanic(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metrics := []collector.Metric{
		collector.NewMetric("k8s.pod.status", 1.0, collector.MetricTypeGauge).
			WithLabel("cluster", "prod").
			WithLabel("namespace", "calico-system").
			WithLabel("pod", "pod-1").
			WithLabel("container", "container-1").
			WithLabel("node", "worker-1"),
		collector.NewMetric("k8s.pod.status", 1.0, collector.MetricTypeGauge).
			WithLabel("cluster", "prod").
			WithLabel("namespace", "calico-system").
			WithLabel("pod", "pod-2").
			WithLabel("container", "container-2"),
	}

	assert.NotPanics(t, func() {
		bridge.UpdateMetrics(metrics)
	})

	families, err := registry.Gather()
	require.NoError(t, err)

	var found bool
	for _, f := range families {
		if *f.Name == "tfo_k8s_pod_status" {
			found = true
			for _, m := range f.Metric {
				labels := make(map[string]string)
				for _, lp := range m.Label {
					labels[*lp.Name] = *lp.Value
				}
				if labels["pod"] == "pod-2" {
					if v, ok := labels["node"]; ok {
						assert.Equal(t, "", v, "missing node label should be padded with empty string")
					}
				}
			}
		}
	}
	assert.True(t, found, "expected tfo_k8s_pod_status metric family")
}

func TestMetricsBridgeLabelExpansionOrderReversed(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metricsBatch1 := []collector.Metric{
		collector.NewMetric("k8s.pod.cpu", 50.0, collector.MetricTypeGauge).
			WithLabel("cluster", "prod").
			WithLabel("pod", "pod-a"),
	}
	bridge.UpdateMetrics(metricsBatch1)

	metricsBatch2 := []collector.Metric{
		collector.NewMetric("k8s.pod.cpu", 80.0, collector.MetricTypeGauge).
			WithLabel("cluster", "prod").
			WithLabel("pod", "pod-b").
			WithLabel("node", "worker-2").
			WithLabel("container", "c1"),
	}
	assert.NotPanics(t, func() {
		bridge.UpdateMetrics(metricsBatch2)
	})

	families, err := registry.Gather()
	require.NoError(t, err)

	var found bool
	for _, f := range families {
		if *f.Name == "tfo_k8s_pod_cpu" {
			found = true
			assert.GreaterOrEqual(t, len(f.Metric), 2)
		}
	}
	assert.True(t, found, "expected tfo_k8s_pod_cpu metric family")
}

func TestMetricsBridgeExtraLabelsDropped(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metricsBatch1 := []collector.Metric{
		collector.NewMetric("system.disk.usage", 42.0, collector.MetricTypeGauge).
			WithLabel("host", "server-1"),
	}
	bridge.UpdateMetrics(metricsBatch1)

	metricsBatch2 := []collector.Metric{
		collector.NewMetric("system.disk.usage", 88.0, collector.MetricTypeGauge).
			WithLabel("host", "server-2").
			WithLabel("device", "/dev/sda1").
			WithLabel("mountpoint", "/data"),
	}
	assert.NotPanics(t, func() {
		bridge.UpdateMetrics(metricsBatch2)
	})

	families, err := registry.Gather()
	require.NoError(t, err)

	var found bool
	for _, f := range families {
		if *f.Name == "tfo_system_disk_usage" {
			found = true
			assert.GreaterOrEqual(t, len(f.Metric), 2)
		}
	}
	assert.True(t, found, "expected tfo_system_disk_usage metric family")
}

func TestMetricsBridgeCounterLabelMismatch(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	metrics := []collector.Metric{
		collector.NewMetric("k8s.pod.requests", 100.0, collector.MetricTypeCounter).
			WithLabel("namespace", "default").
			WithLabel("pod", "pod-1"),
		collector.NewMetric("k8s.pod.requests", 200.0, collector.MetricTypeCounter).
			WithLabel("namespace", "default").
			WithLabel("pod", "pod-2").
			WithLabel("container", "sidecar"),
	}

	assert.NotPanics(t, func() {
		bridge.UpdateMetrics(metrics)
	})
}

func TestMetricsBridgeRepeatedLabelMismatch(t *testing.T) {
	logger := zap.NewNop()
	registry := prometheus.NewRegistry()
	bridge := exporter.NewMetricsBridge("tfo", registry, logger)

	for i := 0; i < 5; i++ {
		m := collector.NewMetric("system.net.bytes", float64(i), collector.MetricTypeGauge).
			WithLabel("host", "server-1")
		for j := 0; j <= i; j++ {
			m = m.WithLabel(string(rune('a'+j)), "val")
		}
		assert.NotPanics(t, func() {
			bridge.UpdateMetrics([]collector.Metric{m})
		})
	}

	families, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)

	var found bool
	for _, f := range families {
		if *f.Name == "tfo_system_net_bytes" {
			found = true
			assert.NotEmpty(t, f.Metric)
		}
	}
	assert.True(t, found, "expected tfo_system_net_bytes metric family after repeated mismatched updates")
}
