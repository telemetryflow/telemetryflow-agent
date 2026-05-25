// Package nodeexporter_test contains unit tests for the node exporter collector
// verifying per-CPU, memory, filesystem, network, and platform-specific metrics.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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

func filesystemOnlyConfig() config.NodeExporterConfig {
	return config.NodeExporterConfig{
		Enabled:                true,
		CPU:                    false,
		Memory:                 false,
		DiskIO:                 false,
		Filesystem:             true,
		LoadAvg:                false,
		Network:                false,
		Thermal:                false,
		Textfile:               false,
		FilesystemMountExclude: `^/(dev|proc|sys|run)($|/)`,
		FilesystemTypeExclude:  `^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs|tmpfs)$`,
	}
}

func TestCollectFilesystemMetrics(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(filesystemOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "expected filesystem metrics")

	metricNames := make(map[string]bool)
	for _, m := range metrics {
		metricNames[m.Name] = true
	}

	// At least some filesystem metrics should be present
	assert.True(t, metricNames["node.filesystem.size_bytes"], "expected node.filesystem.size_bytes")
	assert.True(t, metricNames["node.filesystem.free_bytes"], "expected node.filesystem.free_bytes")
}

func TestFilesystemLabels(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(filesystemOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "node.filesystem.size_bytes" {
			_, hasDevice := m.Labels["device"]
			_, hasMountpoint := m.Labels["mountpoint"]
			_, hasFSType := m.Labels["fstype"]
			assert.True(t, hasDevice, "filesystem metric should have 'device' label")
			assert.True(t, hasMountpoint, "filesystem metric should have 'mountpoint' label")
			assert.True(t, hasFSType, "filesystem metric should have 'fstype' label")
			break
		}
	}
}

func TestFilesystemMetricTypes(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(filesystemOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		switch m.Name {
		case "node.filesystem.size_bytes",
			"node.filesystem.free_bytes",
			"node.filesystem.avail_bytes":
			assert.Equal(t, collector.MetricTypeGauge, m.Type,
				"metric %s should be gauge", m.Name)
			assert.Equal(t, "bytes", m.Unit,
				"metric %s should have bytes unit", m.Name)
		case "node.filesystem.files",
			"node.filesystem.files_free":
			assert.Equal(t, collector.MetricTypeGauge, m.Type,
				"metric %s should be gauge", m.Name)
		}
	}
}

func TestFilesystemMountExclusion(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(filesystemOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// Verify excluded mounts are not present
	excludedPrefixes := []string{"/dev", "/proc", "/sys", "/run"}
	for _, m := range metrics {
		if mp, ok := m.Labels["mountpoint"]; ok {
			for _, prefix := range excludedPrefixes {
				assert.NotEqual(t, prefix, mp,
					"mountpoint %s should be excluded by regex", mp)
			}
		}
	}
}

func TestFilesystemNoExclusion(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:                true,
		Filesystem:             true,
		FilesystemMountExclude: "", // No exclusion
		FilesystemTypeExclude:  "", // No exclusion
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	// Should have more metrics when nothing is excluded
	assert.NotEmpty(t, metrics, "expected filesystem metrics without exclusions")
}

func TestFilesystemSizeValues(t *testing.T) {
	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(filesystemOnlyConfig(), logger)

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	for _, m := range metrics {
		if m.Name == "node.filesystem.size_bytes" {
			assert.Greater(t, m.Value, 0.0,
				"filesystem size should be positive for mountpoint %s", m.Labels["mountpoint"])
		}
	}
}
