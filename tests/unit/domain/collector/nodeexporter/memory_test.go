// Package nodeexporter_test contains unit tests for the node exporter collector
// verifying per-CPU, memory, filesystem, network, and platform-specific metrics.
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
package nodeexporter_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nodeexporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func memoryOnlyConfig() config.NodeExporterConfig {
	return config.NodeExporterConfig{
		Enabled:  true,
		CPU:      false,
		Memory:   true,
		DiskIO:   false,
		LoadAvg:  false,
		Network:  false,
		Thermal:  false,
		Textfile: false,
	}
}

func TestCollectMemoryMetrics(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(memoryOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "expected memory metrics")

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	// Core memory metrics should always be present
	expectedMetrics := []string{
		"node.memory.total_bytes",
		"node.memory.free_bytes",
		"node.memory.available_bytes",
	}
	for _, name := range expectedMetrics {
		assert.True(t, metricNames[name], "expected metric %s", name)
	}
}

func TestMemoryMetricTypes(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(memoryOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		switch m.Name {
		case "node.memory.total_bytes",
			"node.memory.free_bytes",
			"node.memory.available_bytes",
			"node.memory.buffers_bytes",
			"node.memory.cached_bytes",
			"node.memory.active_bytes",
			"node.memory.inactive_bytes",
			"node.memory.wired_bytes",
			"node.memory.shared_bytes",
			"node.memory.slab_bytes",
			"node.memory.swap_total_bytes",
			"node.memory.swap_used_bytes",
			"node.memory.swap_free_bytes":
			assert.Equal(t, collector.MetricTypeGauge, m.Type,
				"metric %s should be gauge", m.Name)
			assert.Equal(t, "bytes", m.Unit,
				"metric %s should have bytes unit", m.Name)
		case "node.memory.swap_in_bytes",
			"node.memory.swap_out_bytes":
			assert.Equal(t, collector.MetricTypeCounter, m.Type,
				"metric %s should be counter", m.Name)
		}
	}
}

func TestMemoryValues(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(memoryOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "node.memory.total_bytes" {
			assert.Greater(t, m.Value, 0.0,
				"total memory should be positive")
		}
		if m.Name == "node.memory.free_bytes" {
			assert.GreaterOrEqual(t, m.Value, 0.0,
				"free memory should be non-negative")
		}
	}
}

func TestSwapMetrics(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(memoryOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// Swap metrics should be present (even if swap is 0)
	swapFound := false
	for _, m := range metrics {
		if m.Name == "node.memory.swap_total_bytes" {
			swapFound = true
			assert.GreaterOrEqual(t, m.Value, 0.0,
				"swap total should be non-negative")
			break
		}
	}
	assert.True(t, swapFound, "expected swap metrics to be present")
}
