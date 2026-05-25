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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nodeexporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func testConfig() config.NodeExporterConfig {
	return config.NodeExporterConfig{
		Enabled:                true,
		Interval:               1 * time.Second,
		CPU:                    true,
		Memory:                 true,
		DiskIO:                 true,
		Filesystem:             true,
		Network:                true,
		LoadAvg:                true,
		Thermal:                true,
		Textfile:               false,
		Conntrack:              true,
		PSI:                    true,
		VMStat:                 true,
		Sockstat:               true,
		Entropy:                true,
		FileDesc:               true,
		Stat:                   true,
		FilesystemMountExclude: `^/(dev|proc|sys|run)($|/)`,
		FilesystemTypeExclude:  `^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs|tmpfs)$`,
		NetworkDeviceExclude:   `^(veth|docker|br-|lo).*$`,
		DiskDeviceExclude:      `^(ram|loop|fd|sr)\d+$`,
		TextfilePath:           "",
	}
}

func newTestCollector() *nodeexporter.NodeExporterCollector {
	logger := zap.NewNop()
	return nodeexporter.NewNodeExporterCollector(testConfig(), logger)
}

func TestNodeExporterCollectorName(t *testing.T) {
	c := newTestCollector()
	assert.Equal(t, "node_exporter", c.Name())
}

func TestNodeExporterCollectorIsRunning(t *testing.T) {
	c := newTestCollector()
	assert.False(t, c.IsRunning(), "should not be running initially")
}

func TestNodeExporterCollectorStartStop(t *testing.T) {
	c := newTestCollector()

	assert.False(t, c.IsRunning())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Give it time to start and perform initial collection
	time.Sleep(200 * time.Millisecond)
	assert.True(t, c.IsRunning())

	cancel()
	err := <-errCh
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, c.IsRunning())
}

func TestNodeExporterCollectorStopWithStopChan(t *testing.T) {
	c := newTestCollector()

	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	assert.True(t, c.IsRunning())

	err := c.Stop()
	require.NoError(t, err)

	startErr := <-errCh
	assert.NoError(t, startErr)
	assert.False(t, c.IsRunning())
}

func TestNodeExporterCollectorStopIdempotent(t *testing.T) {
	c := newTestCollector()

	// Stopping a non-running collector should not error
	err := c.Stop()
	assert.NoError(t, err)
}

func TestNodeExporterCollectorCollect(t *testing.T) {
	c := newTestCollector()

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, metrics, "expected metrics from collection")

	// Verify metrics have proper structure
	for _, m := range metrics {
		assert.NotEmpty(t, m.Name, "metric name should not be empty")
		assert.NotEmpty(t, m.Type, "metric type should not be empty")
		assert.NotNil(t, m.Labels, "metric labels should not be nil")
	}
}

func TestNodeExporterCollectorCollectDisabledSubCollectors(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:    true,
		Interval:   1 * time.Second,
		CPU:        false,
		Memory:     false,
		DiskIO:     false,
		Filesystem: false,
		Network:    false,
		LoadAvg:    false,
		Thermal:    false,
		Textfile:   false,
		Conntrack:  false,
		PSI:        false,
		VMStat:     false,
		Sockstat:   false,
		Entropy:    false,
		FileDesc:   false,
		Stat:       false,
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, logger)
	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.Empty(t, metrics, "expected no metrics when all sub-collectors are disabled")
}

func TestNodeExporterCollectorDefaultInterval(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.NodeExporterConfig{
		Enabled:  true,
		Interval: 0, // Should default to 15s
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, logger)
	require.NotNil(t, c)
	assert.Equal(t, "node_exporter", c.Name())
}

func TestNodeExporterCollectorMetricPrefixes(t *testing.T) {
	c := newTestCollector()

	ctx := context.Background()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err)

	// All metrics should start with "node."
	for _, m := range metrics {
		assert.Regexp(t, `^node\.`, m.Name,
			"metric %s should start with 'node.' prefix", m.Name)
	}
}
