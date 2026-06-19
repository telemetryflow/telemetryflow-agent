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
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestResourceAttrsFromMetric(t *testing.T) {
	m := collector.Metric{
		Name: "db.postgresql.connections.active",
		Labels: map[string]string{
			"postgresql_instance": "prod-primary",
			"postgresql_host":     "db1.example.com",
			"postgresql_version":  "16.2",
		},
	}

	attrs := postgresql.ResourceAttrsFromMetricExported(m)
	if attrs["service.name"] != "postgresql" {
		t.Errorf("service.name = %q, want postgresql", attrs["service.name"])
	}
	if attrs["db.system"] != "postgresql" {
		t.Errorf("db.system = %q, want postgresql", attrs["db.system"])
	}
	if attrs["db.instance.id"] != "prod-primary" {
		t.Errorf("db.instance.id = %q, want prod-primary", attrs["db.instance.id"])
	}
	if attrs["net.host.name"] != "db1.example.com" {
		t.Errorf("net.host.name = %q, want db1.example.com", attrs["net.host.name"])
	}
	if attrs["db.postgresql.version"] != "16.2" {
		t.Errorf("db.postgresql.version = %q, want 16.2", attrs["db.postgresql.version"])
	}
}

func TestResourceAttrsFromMetricMinimal(t *testing.T) {
	m := collector.Metric{
		Name:   "db.postgresql.test",
		Labels: map[string]string{},
	}

	attrs := postgresql.ResourceAttrsFromMetricExported(m)
	if attrs["service.name"] != "postgresql" {
		t.Errorf("service.name = %q, want postgresql", attrs["service.name"])
	}
	if attrs["db.system"] != "postgresql" {
		t.Errorf("db.system = %q, want postgresql", attrs["db.system"])
	}
	// Missing instance/host labels should result in empty values.
	if attrs["db.instance.id"] != "" {
		t.Errorf("db.instance.id = %q, want empty", attrs["db.instance.id"])
	}
}

func TestResourceAttrsFromInstance(t *testing.T) {
	inst := &postgresql.PGTestInstance{
		Config: config.PostgreSQLInstanceConfig{
			Name:   "staging-db",
			Host:   "staging.internal",
			Port:   5433,
			DBName: "app_staging",
		},
		VersionStr: "15.4",
	}

	attrs := postgresql.ResourceAttrsFromInstanceExported(inst)
	if attrs["service.name"] != "postgresql" {
		t.Errorf("service.name = %q, want postgresql", attrs["service.name"])
	}
	if attrs["db.system"] != "postgresql" {
		t.Errorf("db.system = %q, want postgresql", attrs["db.system"])
	}
	if attrs["db.instance.id"] != "staging-db" {
		t.Errorf("db.instance.id = %q, want staging-db", attrs["db.instance.id"])
	}
	if attrs["net.host.name"] != "staging.internal" {
		t.Errorf("net.host.name = %q, want staging.internal", attrs["net.host.name"])
	}
	if attrs["net.host.port"] != "5433" {
		t.Errorf("net.host.port = %q, want 5433", attrs["net.host.port"])
	}
	if attrs["db.name"] != "app_staging" {
		t.Errorf("db.name = %q, want app_staging", attrs["db.name"])
	}
	if attrs["db.postgresql.version"] != "15.4" {
		t.Errorf("db.postgresql.version = %q, want 15.4", attrs["db.postgresql.version"])
	}
}

func TestOTLPEmitterEmitMetricsEmpty(t *testing.T) {
	logger := zap.NewNop()
	emitter := postgresql.NewOTLPEmitter(nil, logger)
	// Should be no-op with nil bridge and empty metrics.
	if err := emitter.EmitMetrics(context.Background(), nil); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := emitter.EmitMetrics(context.Background(), []collector.Metric{}); err != nil {
		t.Errorf("expected no error for empty slice, got %v", err)
	}
}

func TestOTLPEmitterEmitMetricsForInstanceEmpty(t *testing.T) {
	logger := zap.NewNop()
	emitter := postgresql.NewOTLPEmitter(nil, logger)
	inst := &postgresql.PGTestInstance{
		Config: config.PostgreSQLInstanceConfig{Name: "test"},
	}
	if err := emitter.EmitMetricsForInstanceExported(context.Background(), nil, inst); err != nil {
		t.Errorf("expected no error for nil metrics, got %v", err)
	}
	if err := emitter.EmitMetricsForInstanceExported(context.Background(), []collector.Metric{}, inst); err != nil {
		t.Errorf("expected no error for empty metrics, got %v", err)
	}
}

func TestOTLPEmitterShutdown(t *testing.T) {
	logger := zap.NewNop()
	emitter := postgresql.NewOTLPEmitter(nil, logger)
	if err := emitter.Shutdown(context.Background()); err != nil {
		t.Errorf("expected no error on shutdown with nil bridge, got %v", err)
	}
}
