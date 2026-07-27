// Package exporter_test contains unit tests for the file output (JSON Lines,
// InfluxDB line protocol, Prometheus text exposition, rotation, retention,
// and gzip compression).
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
package exporter_test

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

func TestFileOutput_JSONHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	now := time.UnixMilli(1_700_000_000_000).UTC()
	metrics := []plugin.Metric{
		{
			Name:      "system.cpu.usage",
			Type:      plugin.MetricTypeGauge,
			Value:     0.42,
			Timestamp: now,
			Labels:    map[string]string{"host": "node-1"},
			Unit:      "percent",
		},
		{
			Name:      "system.mem.used",
			Type:      plugin.MetricTypeGauge,
			Value:     1024,
			Timestamp: now,
			Labels:    map[string]string{"host": "node-1"},
			Unit:      "bytes",
		},
		{
			Name:      "http.requests_total",
			Type:      plugin.MetricTypeCounter,
			Value:     7,
			Timestamp: now,
			Labels:    map[string]string{"method": "GET"},
		},
	}
	require.NoError(t, out.Write(metrics))
	require.NoError(t, out.Close())

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	var parsed []map[string]any
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var obj map[string]any
		require.NoError(t, json.Unmarshal(line, &obj), "each line must be valid JSON: %q", string(line))
		parsed = append(parsed, obj)
	}
	require.NoError(t, scanner.Err())
	require.Len(t, parsed, 3)

	assert.Equal(t, "system.cpu.usage", parsed[0]["name"])
	assert.Equal(t, "gauge", parsed[0]["type"])
	assert.EqualValues(t, 0.42, parsed[0]["value"])
	assert.Equal(t, "percent", parsed[0]["unit"])
	labels, ok := parsed[0]["labels"].(map[string]any)
	require.True(t, ok, "labels must be an object")
	assert.Equal(t, "node-1", labels["host"])
	assert.Equal(t, now.Format(time.RFC3339Nano), parsed[0]["timestamp"])

	assert.Equal(t, "http.requests_total", parsed[2]["name"])
	assert.Equal(t, "counter", parsed[2]["type"])
}

func TestFileOutput_InfluxLineProtocol(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.lp")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "influx_lp",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	// 1_700_000_000 seconds -> 1_700_000_000_000_000_000 nanoseconds.
	ts := time.Unix(1_700_000_000, 0).UTC()
	metrics := []plugin.Metric{
		{
			Name:      "system.cpu.usage",
			Type:      plugin.MetricTypeGauge,
			Value:     0.42,
			Timestamp: ts,
			Labels:    map[string]string{"host": "node-1", "region": "us-east"},
		},
	}
	require.NoError(t, out.Write(metrics))
	require.NoError(t, out.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	line := strings.TrimRight(string(data), "\n")

	const want = "system_cpu_usage,host=node-1,region=us-east value=0.42 1700000000000000000"
	assert.Equal(t, want, line)
}

func TestFileOutput_InfluxEscapesSpecialChars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.lp")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "influx_lp",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	ts := time.Unix(1_700_000_000, 0).UTC()
	require.NoError(t, out.Write([]plugin.Metric{{
		Name:      "net.rx.bytes",
		Value:     1,
		Timestamp: ts,
		Labels:    map[string]string{"k": "a,b=c d"},
	}}))
	require.NoError(t, out.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "net_rx_bytes,k=a\\,b\\=c\\ d value=1")
}

func TestFileOutput_PrometheusTextFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.prom")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "prometheus_text",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	ts := time.UnixMilli(1_700_000_000_000).UTC()
	metrics := []plugin.Metric{
		{
			Name:        "system_cpu_usage",
			Description: "CPU usage ratio",
			Type:        plugin.MetricTypeGauge,
			Value:       0.42,
			Timestamp:   ts,
			Labels:      map[string]string{"host": "node-1"},
		},
	}
	require.NoError(t, out.Write(metrics))
	require.NoError(t, out.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	const want = "# HELP system_cpu_usage CPU usage ratio\n" +
		"# TYPE system_cpu_usage gauge\n" +
		"system_cpu_usage{host=\"node-1\"} 0.42 1700000000000\n"
	assert.Equal(t, want, string(data))
}

func TestFileOutput_PrometheusOmitsHelpWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.prom")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "prometheus_text",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	ts := time.UnixMilli(1_700_000_000_000).UTC()
	require.NoError(t, out.Write([]plugin.Metric{{
		Name:      "no_help_metric",
		Type:      plugin.MetricTypeCounter,
		Value:     3,
		Timestamp: ts,
	}}))
	require.NoError(t, out.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	const want = "# TYPE no_help_metric counter\n" +
		"no_help_metric 3 1700000000000\n"
	assert.Equal(t, want, string(data))
}

func TestFileOutput_RotationTriggeredOnSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		Rotation: exporter.RotationConfig{
			MaxSizeMB:  0, // rotate after every successful write
			MaxBackups: 5,
			Compress:   false,
		},
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	now := time.Now()
	// First write seeds the file; each subsequent write rotates the prior
	// contents into a numbered backup.
	for i := 0; i < 4; i++ {
		require.NoError(t, out.Write([]plugin.Metric{
			{Name: "test.metric", Value: float64(i), Timestamp: now},
		}))
	}
	require.NoError(t, out.Close())

	// 4 writes -> current file + .1, .2, .3 backups.
	for _, suffix := range []string{".1", ".2", ".3"} {
		_, err := os.Stat(path + suffix)
		assert.NoErrorf(t, err, "expected backup %s%s to exist", path, suffix)
	}
	_, err = os.Stat(path + ".4")
	assert.True(t, os.IsNotExist(err), "no .4 backup should exist yet")
}

func TestFileOutput_MaxBackupsEnforced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		Rotation: exporter.RotationConfig{
			MaxSizeMB:  0,
			MaxBackups: 2,
			Compress:   false,
		},
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	now := time.Now()
	for i := 0; i < 6; i++ {
		require.NoError(t, out.Write([]plugin.Metric{
			{Name: "test.metric", Value: float64(i), Timestamp: now},
		}))
	}
	require.NoError(t, out.Close())

	// MaxBackups=2 -> only .1 and .2 should exist.
	for _, suffix := range []string{".1", ".2"} {
		_, err := os.Stat(path + suffix)
		assert.NoErrorf(t, err, "backup %s%s should be retained", path, suffix)
	}
	for _, suffix := range []string{".3", ".4", ".5"} {
		_, err := os.Stat(path + suffix)
		assert.Truef(t, os.IsNotExist(err), "backup %s%s should have been pruned", path, suffix)
	}
}

func TestFileOutput_CompressProducesGzipBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		Rotation: exporter.RotationConfig{
			MaxSizeMB:  0,
			MaxBackups: 3,
			Compress:   true,
		},
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	now := time.Now()
	require.NoError(t, out.Write([]plugin.Metric{{Name: "first", Value: 1, Timestamp: now}}))
	require.NoError(t, out.Write([]plugin.Metric{{Name: "second", Value: 2, Timestamp: now}}))
	require.NoError(t, out.Close())

	compressed := path + ".1.gz"
	f, err := os.Open(compressed)
	require.NoErrorf(t, err, "expected compressed backup at %s", compressed)
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	body, err := io.ReadAll(gz)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"name":"first"`)

	// Plain (uncompressed) .1 backup must NOT exist alongside .1.gz.
	_, err = os.Stat(path + ".1")
	assert.True(t, os.IsNotExist(err), "plain .1 backup must not exist when Compress=true")
}

func TestFileOutput_ConnectAndCloseLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lifecycle.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		// Disable size-based rotation so reconnect appends rather than rotates.
		Rotation: exporter.RotationConfig{MaxSizeMB: 100},
		Logger:   zap.NewNop(),
	})
	require.NoError(t, err)

	require.NoError(t, out.Connect())
	require.NoError(t, out.Write([]plugin.Metric{{Name: "x", Value: 1, Timestamp: time.Now()}}))
	require.NoError(t, out.Close())

	// Writing after Close fails until reconnect.
	err = out.Write([]plugin.Metric{{Name: "x", Value: 2, Timestamp: time.Now()}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")

	// Reconnect picks up where we left off (append mode).
	require.NoError(t, out.Connect())
	require.NoError(t, out.Write([]plugin.Metric{{Name: "x", Value: 3, Timestamp: time.Now()}}))
	require.NoError(t, out.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	require.Len(t, lines, 2, "file should contain one line per successful Write")
}

func TestFileOutput_BadPathErrors(t *testing.T) {
	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   filepath.Join(t.TempDir(), "missing_dir", "metrics.jsonl"),
		Format: "json",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)

	err = out.Connect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open")
}

func TestFileOutput_NewRequiresPath(t *testing.T) {
	_, err := exporter.NewFileOutput(exporter.FileOutputConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path")
}

func TestFileOutput_NewRejectsUnsupportedFormat(t *testing.T) {
	_, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   filepath.Join(t.TempDir(), "x.jsonl"),
		Format: "yaml",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestFileOutput_EmptyBatchIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "json",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	require.NoError(t, out.Write(nil))
	require.NoError(t, out.Close())

	_, err = os.Stat(path)
	// File is created on Connect via O_CREATE, so it exists but is empty.
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size(), "no bytes should be written for an empty batch")
}

func TestFileOutput_DefaultFormatIsJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "default.jsonl")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())
	require.NoError(t, out.Write([]plugin.Metric{{
		Name: "default.metric", Value: 1, Timestamp: time.Now(),
	}}))
	require.NoError(t, out.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, json.Valid(data[:len(data)-1]), "default format should produce valid JSONL") // strip trailing \n
}

func TestFileOutput_RegisteredUnderName(t *testing.T) {
	inst, _, ok := plugin.GetOutput("file")
	require.True(t, ok, `"file" output must self-register`)
	require.NotNil(t, inst)
	assert.Equal(t, "file", inst.Name())
}
