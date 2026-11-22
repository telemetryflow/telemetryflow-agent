// Package exporter_test — file output Prometheus-text exposition coverage,
// focused on the HELP and label-value escaping helpers (backslash, quote,
// newline) per the Prometheus exposition spec.
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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/plugin"
)

// TestFileOutput_PrometheusTextEscaping writes a metric whose HELP text and
// label value contain backslash, double-quote and newline, forcing the
// escapePromHelp / escapePromLabelValue paths (not their early returns).
func TestFileOutput_PrometheusTextEscaping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.prom")

	out, err := exporter.NewFileOutput(exporter.FileOutputConfig{
		Path:   path,
		Format: "prometheus_text",
		Logger: zap.NewNop(),
	})
	require.NoError(t, err)
	require.NoError(t, out.Connect())

	require.NoError(t, out.Write([]plugin.Metric{
		{
			Name:        "app.requests.total",
			Description: "help with a \\ backslash and a \n newline",
			Type:        plugin.MetricTypeCounter,
			Value:       5,
			Timestamp:   time.Now().UTC(),
			Labels:      map[string]string{"route": "a\"b\\c\nd"},
		},
		{
			// A clean metric to also hit the escape early-return paths.
			Name:      "app.latency.seconds",
			Type:      plugin.MetricTypeGauge,
			Value:     0.12,
			Timestamp: time.Now().UTC(),
			Labels:    map[string]string{"route": "clean"},
		},
	}))
	require.NoError(t, out.Close())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	s := string(raw)

	// Escaped backslash + escaped quote must appear in the exposition output.
	assert.True(t, strings.Contains(s, `\\`), "escaped backslash present")
	assert.True(t, strings.Contains(s, `\"`), "escaped quote present")
	assert.True(t, strings.Contains(s, "app_requests_total") || strings.Contains(s, "app.requests.total"),
		"metric name present in output")
}
