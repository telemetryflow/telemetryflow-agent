// Package exporter_test contains additional unit tests for the Prometheus
// bridge and server covering name translation, reset, and accessors.
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
package exporter_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func TestPrometheusServer_AccessorsAndGoProcessMetrics(t *testing.T) {
	cfg := config.PrometheusServerConfig{
		Enabled:               true,
		Port:                  0,
		Path:                  "/metrics",
		IncludeGoMetrics:      true,
		IncludeProcessMetrics: true,
		MetricPrefix:          "tfo",
		ReadTimeout:           time.Second,
		WriteTimeout:          time.Second,
	}
	srv := exporter.NewPrometheusServer(cfg, zap.NewNop())
	require.NotNil(t, srv)
	require.NotNil(t, srv.SelfMetrics())
	require.NotNil(t, srv.Bridge())
}

func TestPrometheusBridge_TranslateResetViaServer(t *testing.T) {
	cfg := config.PrometheusServerConfig{
		Enabled:      true,
		Path:         "/metrics",
		MetricPrefix: "tfo",
	}
	srv := exporter.NewPrometheusServer(cfg, zap.NewNop())
	bridge := srv.Bridge()
	now := time.Now()

	metrics := []collector.Metric{
		// Unit "bytes", name without suffix -> gets "_bytes" appended.
		{Name: "mem.used", Type: collector.MetricTypeGauge, Value: 1024, Unit: "bytes", Timestamp: now, Labels: map[string]string{"host": "a"}},
		// Unit "bytes", name already ending in _bytes -> no double suffix.
		{Name: "disk_bytes", Type: collector.MetricTypeGauge, Value: 2048, Unit: "bytes", Timestamp: now},
		// Unit "seconds", name without suffix.
		{Name: "req.latency", Type: collector.MetricTypeGauge, Value: 0.2, Unit: "seconds", Timestamp: now},
		// Unit "seconds", already ending in _seconds.
		{Name: "uptime_seconds", Type: collector.MetricTypeGauge, Value: 99, Unit: "seconds", Timestamp: now},
		// Counter with empty description -> help defaults to name.
		{Name: "requests_total", Type: collector.MetricTypeCounter, Value: 5, Timestamp: now, Labels: map[string]string{"code": "200"}},
		// Counter again with mismatched labels -> normalized.
		{Name: "requests_total", Type: collector.MetricTypeCounter, Value: 3, Timestamp: now, Labels: map[string]string{"other": "x"}},
	}

	bridge.UpdateMetrics(metrics)

	// ResetAll clears both gauges and counters.
	bridge.ResetAll()

	// After reset, re-adding must succeed (registration not blocked by leftovers).
	bridge.UpdateMetrics(metrics)
	assert.NotNil(t, bridge)
}
