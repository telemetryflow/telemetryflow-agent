// Package nodeexporter_test contains unit tests for the node exporter collector
// verifying per-CPU, memory, filesystem, network, and platform-specific metrics.
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
package nodeexporter_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nodeexporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func linuxOnlyConfig() config.NodeExporterConfig {
	return config.NodeExporterConfig{
		Enabled:   true,
		CPU:       false,
		Memory:    false,
		DiskIO:    false,
		LoadAvg:   false,
		Network:   false,
		Thermal:   false,
		Textfile:  false,
		Conntrack: true,
		PSI:       true,
		VMStat:    true,
		Sockstat:  true,
		Entropy:   true,
		FileDesc:  true,
		Stat:      true,
	}
}

func TestLinuxSubCollectorsOnCurrentPlatform(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(linuxOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	if runtime.GOOS != "linux" {
		// On non-Linux, Linux-specific collectors should return nothing
		linuxMetrics := 0
		for _, m := range metrics {
			switch m.Name {
			case "node.conntrack.entries",
				"node.conntrack.entries_limit",
				"node.pressure.some.seconds_total",
				"node.pressure.full.seconds_total",
				"node.vmstat.pgpgin",
				"node.entropy.available_bits",
				"node.sockstat.sockets_used",
				"node.filefd.allocated",
				"node.context_switches_total":
				linuxMetrics++
			}
		}
		assert.Equal(t, 0, linuxMetrics,
			"expected no Linux-specific metrics on %s", runtime.GOOS)
		t.Logf("Running on %s — Linux sub-collectors correctly returned no metrics", runtime.GOOS)
		return
	}

	// On Linux, we expect at least some of these metrics
	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	// These should be available on most Linux systems
	t.Log("Running on Linux — checking Linux-specific metrics")

	// Context switches and interrupts from /proc/stat (always available)
	assert.True(t, metricNames["node.context_switches_total"],
		"expected node.context_switches_total on Linux")
	assert.True(t, metricNames["node.interrupts_total"],
		"expected node.interrupts_total on Linux")
	assert.True(t, metricNames["node.forks_total"],
		"expected node.forks_total on Linux")
	assert.True(t, metricNames["node.procs_running"],
		"expected node.procs_running on Linux")
}

func TestLinuxStatMetricTypes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test, skipping on " + runtime.GOOS)
	}

	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(linuxOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		switch m.Name {
		case "node.context_switches_total",
			"node.interrupts_total",
			"node.softirq_total",
			"node.forks_total":
			assert.Equal(t, collector.MetricTypeCounter, m.Type,
				"metric %s should be counter", m.Name)
		case "node.procs_running",
			"node.procs_blocked":
			assert.Equal(t, collector.MetricTypeGauge, m.Type,
				"metric %s should be gauge", m.Name)
		}
	}
}

func TestLinuxVMStatMetrics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test, skipping on " + runtime.GOOS)
	}

	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(linuxOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	vmstatMetrics := make(map[string]bool)
	for _, m := range metrics {
		if m.Name == "node.vmstat.pgpgin" ||
			m.Name == "node.vmstat.pgpgout" ||
			m.Name == "node.vmstat.pswpin" ||
			m.Name == "node.vmstat.pswpout" ||
			m.Name == "node.vmstat.pgfault" ||
			m.Name == "node.vmstat.pgmajfault" {
			vmstatMetrics[m.Name] = true
			assert.Equal(t, collector.MetricTypeCounter, m.Type,
				"vmstat metric %s should be counter", m.Name)
		}
	}

	// At minimum pgfault should be present on any Linux system
	assert.True(t, vmstatMetrics["node.vmstat.pgfault"],
		"expected node.vmstat.pgfault on Linux")
}

func TestLinuxSockstatMetrics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test, skipping on " + runtime.GOOS)
	}

	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(linuxOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "node.sockstat.sockets_used" {
			assert.Equal(t, collector.MetricTypeGauge, m.Type)
			assert.GreaterOrEqual(t, m.Value, 0.0,
				"sockets used should be non-negative")
			return
		}
	}
	t.Log("node.sockstat.sockets_used not found (may depend on kernel)")
}

func TestLinuxEntropyMetrics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test, skipping on " + runtime.GOOS)
	}

	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(linuxOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "node.entropy.available_bits" {
			assert.Equal(t, collector.MetricTypeGauge, m.Type)
			assert.Greater(t, m.Value, 0.0,
				"entropy should be positive on a running system")
			return
		}
	}
	t.Log("node.entropy.available_bits not found (may not be available)")
}

func TestLinuxFileDescMetrics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test, skipping on " + runtime.GOOS)
	}

	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(linuxOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	assert.True(t, metricNames["node.filefd.allocated"],
		"expected node.filefd.allocated on Linux")
	assert.True(t, metricNames["node.filefd.maximum"],
		"expected node.filefd.maximum on Linux")
}

func TestCollectLoadAvgMetrics(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled: true,
		LoadAvg: true,
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	assert.True(t, metricNames["node.load1"], "expected node.load1")
	assert.True(t, metricNames["node.load5"], "expected node.load5")
	assert.True(t, metricNames["node.load15"], "expected node.load15")
}

func TestLoadAvgMetricTypes(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled: true,
		LoadAvg: true,
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "node.load1" || m.Name == "node.load5" || m.Name == "node.load15" {
			assert.Equal(t, collector.MetricTypeGauge, m.Type,
				"load average metric %s should be gauge", m.Name)
			assert.GreaterOrEqual(t, m.Value, 0.0,
				"load average should be non-negative")
		}
	}
}

func TestCollectNetworkMetrics(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:              true,
		Network:              true,
		NetworkDeviceExclude: `^(veth|docker|br-|lo).*$`,
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// We might not have non-excluded network interfaces on all test hosts
	// but we should at least not error
	for _, m := range metrics {
		if m.Name == "node.network.receive_bytes_total" {
			assert.Equal(t, collector.MetricTypeCounter, m.Type)
			assert.Equal(t, "bytes", m.Unit)
			_, hasDevice := m.Labels["device"]
			assert.True(t, hasDevice, "network metric should have 'device' label")

			// Verify excluded devices are not present
			device := m.Labels["device"]
			assert.NotEqual(t, "lo", device, "loopback should be excluded")
			return
		}
	}
}

func TestCollectDiskIOMetrics(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:           true,
		DiskIO:            true,
		DiskDeviceExclude: `^(ram|loop|fd|sr)\d+$`,
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "node.disk.read_bytes_total" {
			assert.Equal(t, collector.MetricTypeCounter, m.Type)
			assert.Equal(t, "bytes", m.Unit)
			_, hasDevice := m.Labels["device"]
			assert.True(t, hasDevice, "disk metric should have 'device' label")
			return
		}
	}
}

func TestCollectThermalMetrics(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled: true,
		Thermal: true,
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// Thermal metrics may or may not be available
	for _, m := range metrics {
		if m.Name == "node.thermal.temperature_celsius" {
			assert.Equal(t, collector.MetricTypeGauge, m.Type)
			assert.Equal(t, "celsius", m.Unit)
			_, hasSensor := m.Labels["sensor"]
			assert.True(t, hasSensor, "thermal metric should have 'sensor' label")
			return
		}
	}
	t.Log("node.thermal.temperature_celsius not available on this platform (this is OK)")
}
