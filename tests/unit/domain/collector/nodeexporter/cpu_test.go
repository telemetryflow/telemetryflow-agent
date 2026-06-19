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

func TestCollectCPUMetrics(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:  true,
		CPU:      true,
		Memory:   false,
		DiskIO:   false,
		LoadAvg:  false,
		Network:  false,
		Thermal:  false,
		Textfile: false,
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, logger)
	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "expected CPU metrics")

	// Verify node.cpu.seconds metrics exist
	cpuSecondsFound := false
	for _, m := range metrics {
		if m.Name == "node.cpu.seconds" {
			cpuSecondsFound = true
			assert.Equal(t, collector.MetricTypeCounter, m.Type)
			assert.Equal(t, "seconds", m.Unit)

			// Should have cpu and mode labels
			_, hasCPU := m.Labels["cpu"]
			_, hasMode := m.Labels["mode"]
			assert.True(t, hasCPU, "CPU seconds metric should have 'cpu' label")
			assert.True(t, hasMode, "CPU seconds metric should have 'mode' label")
			break
		}
	}
	assert.True(t, cpuSecondsFound, "expected node.cpu.seconds metric")
}

func TestCPUModes(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:  true,
		CPU:      true,
		Memory:   false,
		DiskIO:   false,
		LoadAvg:  false,
		Network:  false,
		Thermal:  false,
		Textfile: false,
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, logger)
	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// Collect all CPU modes reported
	modes := make(map[string]bool)
	for _, m := range metrics {
		if m.Name == "node.cpu.seconds" {
			if mode, ok := m.Labels["mode"]; ok {
				modes[mode] = true
			}
		}
	}

	// All 9 CPU modes should be present for at least one CPU
	expectedModes := []string{"user", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "nice"}
	for _, mode := range expectedModes {
		assert.True(t, modes[mode], "expected CPU mode '%s' to be present", mode)
	}
}

func TestCPUPerCoreLabels(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:  true,
		CPU:      true,
		Memory:   false,
		DiskIO:   false,
		LoadAvg:  false,
		Network:  false,
		Thermal:  false,
		Textfile: false,
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, logger)
	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// Track unique CPU labels
	cpuLabels := make(map[string]bool)
	for _, m := range metrics {
		if m.Name == "node.cpu.seconds" {
			if cpu, ok := m.Labels["cpu"]; ok {
				cpuLabels[cpu] = true
			}
		}
	}

	// Should have at least 1 CPU (0-indexed)
	assert.Contains(t, cpuLabels, "0", "expected at least CPU 0")
	assert.GreaterOrEqual(t, len(cpuLabels), 1, "expected at least 1 CPU core")
}

func TestCPUFrequency(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:  true,
		CPU:      true,
		Memory:   false,
		DiskIO:   false,
		LoadAvg:  false,
		Network:  false,
		Thermal:  false,
		Textfile: false,
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, logger)
	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// CPU frequency may or may not be available depending on platform
	for _, m := range metrics {
		if m.Name == "node.cpu.frequency_hz" {
			assert.Equal(t, collector.MetricTypeGauge, m.Type)
			assert.Equal(t, "hertz", m.Unit)
			assert.Greater(t, m.Value, 0.0, "CPU frequency should be positive")

			_, hasCPU := m.Labels["cpu"]
			assert.True(t, hasCPU, "frequency metric should have 'cpu' label")
			return
		}
	}
	// It's OK if frequency is not available on some platforms
	t.Log("node.cpu.frequency_hz not available on this platform (this is OK)")
}
