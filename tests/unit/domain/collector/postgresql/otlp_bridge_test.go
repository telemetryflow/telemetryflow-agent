// Package postgresql_test contains unit tests for the corresponding collector module.
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

package postgresql_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func newBridge(t *testing.T, status int) *exporter.OTLPMetricBridge {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)

	endpoint := strings.TrimPrefix(srv.URL, "http://")
	bridge, err := exporter.NewOTLPMetricBridge(context.Background(), exporter.OTLPMetricBridgeConfig{
		Endpoint: endpoint,
		Path:     "/v1/metrics",
		Logger:   zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("new bridge: %v", err)
	}
	return bridge
}

func sampleMetrics() []collector.Metric {
	return []collector.Metric{
		{
			Name:      "db.postgresql.connections.active",
			Type:      collector.MetricTypeGauge,
			Value:     3,
			Timestamp: time.Now(),
			Labels: map[string]string{
				"postgresql_instance": "prod",
				"postgresql_host":     "db1",
				"postgresql_version":  "16.2",
			},
		},
	}
}

func TestOTLPEmitter_EmitMetricsSuccess(t *testing.T) {
	bridge := newBridge(t, http.StatusOK)
	emitter := postgresql.NewOTLPEmitter(bridge, zap.NewNop())
	if err := emitter.EmitMetrics(context.Background(), sampleMetrics()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if err := emitter.Shutdown(context.Background()); err != nil {
		t.Errorf("shutdown error: %v", err)
	}
}

func TestOTLPEmitter_EmitMetricsExportError(t *testing.T) {
	// 400 is a permanent, non-retryable OTLP error -> Export returns quickly.
	bridge := newBridge(t, http.StatusBadRequest)
	emitter := postgresql.NewOTLPEmitter(bridge, zap.NewNop())
	if err := emitter.EmitMetrics(context.Background(), sampleMetrics()); err == nil {
		t.Fatal("expected export error")
	}
}

func TestOTLPEmitter_EmitMetricsForInstanceSuccess(t *testing.T) {
	bridge := newBridge(t, http.StatusOK)
	emitter := postgresql.NewOTLPEmitter(bridge, zap.NewNop())
	inst := &postgresql.PGTestInstance{
		Config:     config.PostgreSQLInstanceConfig{Name: "prod", Host: "db1", Port: 5432, DBName: "app"},
		VersionStr: "16.2",
	}
	if err := emitter.EmitMetricsForInstanceExported(context.Background(), sampleMetrics(), inst); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestOTLPEmitter_EmitMetricsForInstanceExportError(t *testing.T) {
	bridge := newBridge(t, http.StatusBadRequest)
	emitter := postgresql.NewOTLPEmitter(bridge, zap.NewNop())
	inst := &postgresql.PGTestInstance{
		Config: config.PostgreSQLInstanceConfig{Name: "prod", Host: "db1", Port: 5432},
	}
	if err := emitter.EmitMetricsForInstanceExported(context.Background(), sampleMetrics(), inst); err == nil {
		t.Fatal("expected export error")
	}
}
