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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nodeexporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// textfileConfig builds a config that enables ONLY the textfile sub-collector,
// pointing it at the supplied directory. This isolates the textfile parser so
// that the collected metrics can be asserted deterministically.
func textfileConfig(path string) config.NodeExporterConfig {
	return config.NodeExporterConfig{
		Enabled:      true,
		Interval:     1 * time.Second,
		Textfile:     true,
		TextfilePath: path,
	}
}

// metricByName returns the first metric with the given name, or ok=false.
func metricByName(metrics []collector.Metric, name string) (collector.Metric, bool) {
	for _, m := range metrics {
		if m.Name == name {
			return m, true
		}
	}
	return collector.Metric{}, false
}

// TestTextfileParsesAllLineForms stages a *.prom fixture exercising every
// branch of parsePromLine / parseLabels / parsePromFloat: labeled metrics,
// unlabeled metrics, comments, blank lines, integers, decimals, and negatives.
func TestTextfileParsesAllLineForms(t *testing.T) {
	dir := t.TempDir()

	content := "" +
		"# HELP custom_metric a help comment that must be skipped\n" +
		"# TYPE custom_metric gauge\n" +
		"\n" +
		"   \n" +
		"custom_unlabeled 42\n" +
		"custom_decimal 3.5\n" +
		"custom_negative -1.5\n" +
		"custom_labeled{env=\"prod\",region=\"us\"} 123.25\n" +
		"custom_singlelabel{host=\"node1\"} 7\n"

	require.NoError(t, os.WriteFile(filepath.Join(dir, "metrics.prom"), []byte(content), 0o644))
	// A non-.prom file must be ignored entirely.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("ignored_metric 999\n"), 0o644))
	// A nested directory entry must be skipped (not descended into).
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir.prom"), 0o755))

	logger := zap.NewNop()
	c := nodeexporter.NewNodeExporterCollector(textfileConfig(dir), logger)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	unlabeled, ok := metricByName(metrics, "custom_unlabeled")
	require.True(t, ok, "unlabeled metric should be parsed")
	assert.Equal(t, 42.0, unlabeled.Value)

	dec, ok := metricByName(metrics, "custom_decimal")
	require.True(t, ok)
	assert.InDelta(t, 3.5, dec.Value, 1e-9)

	neg, ok := metricByName(metrics, "custom_negative")
	require.True(t, ok)
	assert.InDelta(t, -1.5, neg.Value, 1e-9)

	labeled, ok := metricByName(metrics, "custom_labeled")
	require.True(t, ok)
	assert.InDelta(t, 123.25, labeled.Value, 1e-9)
	assert.Equal(t, "prod", labeled.Labels["env"])
	assert.Equal(t, "us", labeled.Labels["region"])

	_, ignored := metricByName(metrics, "ignored_metric")
	assert.False(t, ignored, "non-.prom files must not be parsed")
}

// TestTextfileMalformedLinesSkipped verifies that malformed exposition lines
// are silently dropped (parsePromLine returns ok=false) without failing the
// whole collection.
func TestTextfileMalformedLinesSkipped(t *testing.T) {
	dir := t.TempDir()

	content := "" +
		"lonely_name_without_value\n" + // < 2 fields, no braces
		"broken_labels{env=\"prod\" 5\n" + // missing closing brace
		"empty_value_after_labels{env=\"prod\"}\n" + // no value token after }
		"good_metric 10\n"

	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.prom"), []byte(content), 0o644))

	c := nodeexporter.NewNodeExporterCollector(textfileConfig(dir), zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	good, ok := metricByName(metrics, "good_metric")
	require.True(t, ok, "the single valid line should still be collected")
	assert.Equal(t, 10.0, good.Value)

	for _, bad := range []string{"lonely_name_without_value", "broken_labels", "empty_value_after_labels"} {
		_, present := metricByName(metrics, bad)
		assert.Falsef(t, present, "malformed metric %q must be skipped", bad)
	}
}

// TestTextfileEmptyPathReturnsNothing verifies the early-return when no
// textfile path is configured (dir == "").
func TestTextfileEmptyPathReturnsNothing(t *testing.T) {
	c := nodeexporter.NewNodeExporterCollector(textfileConfig(""), zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// TestTextfileMissingDirReturnsNothing verifies that a non-existent directory
// is treated as "no metrics" rather than an error (os.IsNotExist branch).
func TestTextfileMissingDirReturnsNothing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	c := nodeexporter.NewNodeExporterCollector(textfileConfig(missing), zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// TestTextfileEmptyDirReturnsNothing verifies an existing but empty directory
// yields no metrics (the read succeeds, zero entries).
func TestTextfileEmptyDirReturnsNothing(t *testing.T) {
	c := nodeexporter.NewNodeExporterCollector(textfileConfig(t.TempDir()), zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// TestTextfilePathIsAFileReturnsError drives the ReadDir error branch that is
// NOT os.IsNotExist: pointing TextfilePath at a regular file makes os.ReadDir
// fail with "not a directory". The error propagates to collectTextfile's
// wrapped error and is then swallowed/logged by Collect's textfile branch.
func TestTextfilePathIsAFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir.prom")
	require.NoError(t, os.WriteFile(filePath, []byte("x 1\n"), 0o644))

	c := nodeexporter.NewNodeExporterCollector(textfileConfig(filePath), zap.NewNop())
	// Collect must not fail overall even though the textfile sub-collector errors.
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// TestTextfileUnreadableEntrySkipped stages a *.prom directory entry that
// cannot be read (a dangling symlink), exercising the per-file os.ReadFile
// error branch which logs and continues. A sibling valid file confirms
// collection proceeds.
func TestTextfileUnreadableEntrySkipped(t *testing.T) {
	dir := t.TempDir()

	// Dangling symlink whose name ends in .prom: not a dir, has the suffix,
	// but os.ReadFile fails because the target does not exist.
	dangling := filepath.Join(dir, "dangling.prom")
	require.NoError(t, os.Symlink(filepath.Join(dir, "nonexistent-target"), dangling))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "valid.prom"), []byte("still_here 5\n"), 0o644))

	c := nodeexporter.NewNodeExporterCollector(textfileConfig(dir), zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	m, ok := metricByName(metrics, "still_here")
	require.True(t, ok, "valid sibling file should still be collected")
	assert.Equal(t, 5.0, m.Value)
}

// TestTextfileLabelSegmentWithoutEquals covers parseLabels' branch that skips
// a label segment lacking an '=' sign.
func TestTextfileLabelSegmentWithoutEquals(t *testing.T) {
	dir := t.TempDir()
	// The "orphan" segment has no '=' and must be skipped; "a"/"b" survives.
	content := "labeled_metric{orphan,a=\"b\"} 9\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "labels.prom"), []byte(content), 0o644))

	c := nodeexporter.NewNodeExporterCollector(textfileConfig(dir), zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	m, ok := metricByName(metrics, "labeled_metric")
	require.True(t, ok)
	assert.Equal(t, "b", m.Labels["a"])
	_, hasOrphan := m.Labels["orphan"]
	assert.False(t, hasOrphan, "segment without '=' must not become a label")
}

// TestDiskDeviceExcludeMatchesAll enables DiskIO with a catch-all exclusion so
// that, on hosts exposing disk devices, the shouldExcludeDisk skip branch is
// exercised. On hosts without disk counters this is a no-op but still safe.
func TestDiskDeviceExcludeMatchesAll(t *testing.T) {
	cfg := config.NodeExporterConfig{
		Enabled:           true,
		Interval:          1 * time.Second,
		DiskIO:            true,
		DiskDeviceExclude: `.*`,
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	// Every disk device is excluded, so no node.disk.* metrics should remain.
	for _, m := range metrics {
		assert.NotContains(t, m.Name, "node.disk.")
	}
}

// TestInvalidRegexPatternsIgnored drives the compileRegex error path with
// syntactically invalid regex patterns for every exclusion field. The
// collector must construct successfully (invalid patterns are logged and
// ignored, not fatal).
func TestInvalidRegexPatternsIgnored(t *testing.T) {
	cfg := config.NodeExporterConfig{
		Enabled:                true,
		Interval:               1 * time.Second,
		DiskIO:                 true,
		Filesystem:             true,
		Network:                true,
		FilesystemMountExclude: "[invalid(",
		FilesystemTypeExclude:  "*bad",
		NetworkDeviceExclude:   "(unclosed",
		DiskDeviceExclude:      "a{2,1}",
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, zap.NewNop())
	require.NotNil(t, c)

	// Collection must still succeed with the invalid (ignored) patterns.
	_, err := c.Collect(context.Background())
	require.NoError(t, err)
}

// TestValidRegexExclusionsApplied exercises the shouldExclude* matchers with
// valid patterns through the public Collect path.
func TestValidRegexExclusionsApplied(t *testing.T) {
	cfg := config.NodeExporterConfig{
		Enabled:                true,
		Interval:               1 * time.Second,
		DiskIO:                 true,
		Filesystem:             true,
		Network:                true,
		FilesystemMountExclude: `^/(dev|proc|sys)($|/)`,
		FilesystemTypeExclude:  `^(tmpfs|devfs)$`,
		NetworkDeviceExclude:   `^(lo|utun).*$`,
		DiskDeviceExclude:      `^(ram|loop)\d+$`,
	}

	c := nodeexporter.NewNodeExporterCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	// Any filesystem metrics that survive exclusion must not be on excluded mounts.
	for _, m := range metrics {
		if mp, ok := m.Labels["mountpoint"]; ok {
			assert.NotContains(t, []string{"/dev", "/proc", "/sys"}, mp)
		}
	}
}

// TestStartIsIdempotentWhileRunning covers the "already running" early return
// branch of Start: a second Start call returns nil immediately without
// disturbing the first.
func TestStartIsIdempotentWhileRunning(t *testing.T) {
	c := nodeexporter.NewNodeExporterCollector(textfileConfig(""), zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()

	require.Eventually(t, c.IsRunning, time.Second, 10*time.Millisecond)

	// Second Start while already running returns nil immediately.
	require.NoError(t, c.Start(ctx))
	assert.True(t, c.IsRunning())

	cancel()
	<-errCh
	assert.False(t, c.IsRunning())
}

// TestCollectWithContextCancelled ensures Collect still returns cleanly even
// when handed an already-cancelled context (CPU sub-collector tolerates it).
func TestCollectWithContextCancelled(t *testing.T) {
	cfg := config.NodeExporterConfig{
		Enabled:  true,
		Interval: 1 * time.Second,
		CPU:      true,
		Memory:   true,
		LoadAvg:  true,
	}
	c := nodeexporter.NewNodeExporterCollector(cfg, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Collect(ctx)
	require.NoError(t, err)
}
