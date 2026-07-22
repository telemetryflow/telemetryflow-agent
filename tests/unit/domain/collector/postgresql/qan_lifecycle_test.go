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

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

func newQANCollector(t *testing.T, insts ...config.PostgreSQLInstanceConfig) *postgresql.QANPostgreSQLCollector {
	t.Helper()
	cfg := postgresql.QANConfig{
		Instances:       insts,
		TopQueriesLimit: 10,
		Labels:          map[string]string{"env": "test"},
	}
	return postgresql.NewQANPostgreSQLCollector(cfg, zap.NewNop())
}

// --- Constructor ---

func TestQAN_NewDefaultsTopQueriesLimit(t *testing.T) {
	c := postgresql.NewQANPostgreSQLCollector(postgresql.QANConfig{}, zap.NewNop())
	if c == nil {
		t.Fatal("expected collector")
	}
	if c.Name() != "qan-postgresql-pgstatements" {
		t.Errorf("Name() = %q", c.Name())
	}
}

func TestQAN_NewNilLoggerUsesProduction(t *testing.T) {
	c := postgresql.NewQANPostgreSQLCollector(postgresql.QANConfig{TopQueriesLimit: 5}, nil)
	if c == nil {
		t.Fatal("expected collector with production logger")
	}
}

// --- Name / AgentType / IsRunning ---

func TestQAN_NameAgentTypeState(t *testing.T) {
	c := newQANCollector(t)
	if c.Name() != "qan-postgresql-pgstatements" {
		t.Errorf("Name() = %q", c.Name())
	}
	if c.AgentType() != qan.AgentTypePostgreSQLPgStatements {
		t.Errorf("AgentType() = %v", c.AgentType())
	}
	if c.IsRunning() {
		t.Error("should not be running initially")
	}
}

// --- Start / Stop ---

func TestQAN_StartStopLifecycle(t *testing.T) {
	c := newQANCollector(t, unreachableInstance("q1"))

	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Error("should be running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Error("double Start should error")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.IsRunning() {
		t.Error("should not be running after Stop")
	}
	// Stop again is a no-op.
	if err := c.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

// --- CollectQAN ---

func TestQAN_CollectNoInstances(t *testing.T) {
	c := newQANCollector(t)
	buckets, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("CollectQAN: %v", err)
	}
	if len(buckets) != 0 {
		t.Errorf("expected no buckets, got %d", len(buckets))
	}
}

func TestQAN_CollectUnreachableInstanceSkipped(t *testing.T) {
	c := newQANCollector(t, unreachableInstance("q1"))
	buckets, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("CollectQAN should not error: %v", err)
	}
	if len(buckets) != 0 {
		t.Errorf("expected no buckets from unreachable instance, got %d", len(buckets))
	}
}

// --- instanceLabels ---

func TestQAN_InstanceLabels(t *testing.T) {
	cfg := postgresql.QANConfig{Labels: map[string]string{"team": "obs"}}
	labels := postgresql.QANInstanceLabelsExported(cfg, config.PostgreSQLInstanceConfig{
		Name: "prod-db",
		Host: "db.internal",
	})
	if labels["postgresql_instance"] != "prod-db" {
		t.Errorf("postgresql_instance = %q", labels["postgresql_instance"])
	}
	if labels["postgresql_host"] != "db.internal" {
		t.Errorf("postgresql_host = %q", labels["postgresql_host"])
	}
	if labels["db_system"] != "postgresql" {
		t.Errorf("db_system = %q", labels["db_system"])
	}
	if labels["team"] != "obs" {
		t.Errorf("custom label team = %q", labels["team"])
	}
}

// --- fingerprintQueryQAN ---

func TestQAN_FingerprintQuery(t *testing.T) {
	a := postgresql.FingerprintQueryQANExported("SELECT * FROM users WHERE id = 42")
	b := postgresql.FingerprintQueryQANExported("SELECT * FROM users WHERE id = 99")
	if a != b {
		t.Errorf("numeric-literal queries should share a fingerprint: %s vs %s", a, b)
	}
	if len(a) != 32 {
		t.Errorf("fingerprint length = %d, want 32 hex chars", len(a))
	}

	c := postgresql.FingerprintQueryQANExported("SELECT name FROM accounts WHERE tier IN (1,2,3)")
	d := postgresql.FingerprintQueryQANExported("SELECT name FROM accounts WHERE tier IN (7,8)")
	if c != d {
		t.Errorf("IN-list queries should share a fingerprint: %s vs %s", c, d)
	}

	e := postgresql.FingerprintQueryQANExported("SELECT 1")
	if e == a {
		t.Error("distinct queries should not collide")
	}
}
