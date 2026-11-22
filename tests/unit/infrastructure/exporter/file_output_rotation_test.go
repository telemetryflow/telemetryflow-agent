// Package exporter_test — file output rotation/retention coverage: gzip
// compression of rotated files, backup shifting + overflow pruning, and
// age-based retention. All operations are local filesystem only.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package exporter_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// TestFileOutput_RotationCompressAndOverflow drives four rotations with
// MaxSizeMB=0 (rotate on every write) and MaxBackups=2 + Compress, exercising
// gzipFile, the .gz backup shift, and the overflow-removal branch.
func TestFileOutput_RotationCompressAndOverflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		Logger: zap.NewNop(),
		Rotation: exporter.RotationConfig{
			MaxSizeMB:  0, // rotate after every content-producing write
			MaxBackups: 2,
			Compress:   true,
			MaxAgeDays: 30,
		},
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	m := []plugin.Metric{{Name: "x", Type: plugin.MetricTypeGauge, Value: 1, Timestamp: time.Now().UTC()}}
	for i := 0; i < 4; i++ {
		require.NoError(t, out.Write(m))
	}
	require.NoError(t, out.Close())

	_, err1 := os.Stat(path + ".1.gz")
	assert.NoError(t, err1, "newest compressed backup kept")
	_, err2 := os.Stat(path + ".2.gz")
	assert.NoError(t, err2, "second compressed backup kept")
	_, err3 := os.Stat(path + ".3.gz")
	assert.True(t, os.IsNotExist(err3), "overflow backup pruned (MaxBackups=2)")
}

// TestFileOutput_EnforceMaxAgeRemovesOldBackup pre-seeds an aged backup and
// verifies a rotation's enforceMaxAge sweep deletes it.
func TestFileOutput_EnforceMaxAgeRemovesOldBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")

	aged := path + ".9.gz" // idx 9 > MaxBackups so the shift loop never touches it
	require.NoError(t, os.WriteFile(aged, []byte("old"), 0o600))
	past := time.Now().Add(-72 * time.Hour)
	require.NoError(t, os.Chtimes(aged, past, past))

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		Logger: zap.NewNop(),
		Rotation: exporter.RotationConfig{
			MaxSizeMB:  0,
			MaxBackups: 5,
			MaxAgeDays: 1, // 72h-old backup is well past the 1-day window
		},
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	m := []plugin.Metric{{Name: "x", Type: plugin.MetricTypeGauge, Value: 1, Timestamp: time.Now().UTC()}}
	require.NoError(t, out.Write(m))
	require.NoError(t, out.Write(m)) // second write triggers rotate -> enforceMaxAge
	require.NoError(t, out.Close())

	_, statErr := os.Stat(aged)
	assert.True(t, os.IsNotExist(statErr), "aged backup removed by enforceMaxAge")
}
