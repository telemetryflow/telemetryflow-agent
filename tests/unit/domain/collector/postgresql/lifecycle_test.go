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
//
// These tests exercise the standard PostgreSQL collector lifecycle and the
// connection-error / back-off code paths without requiring a live database.
// The collector uses pgxpool (jackc/pgx), which is not compatible with
// database/sql sqlmock, so the DB-facing collect paths are driven through
// deterministic connection failures (loopback port 1 -> connection refused)
// rather than mocked result sets.

package postgresql_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// unreachableInstance returns an instance config pointing at a closed loopback
// port so that connection attempts fail fast (ECONNREFUSED) and deterministically.
func unreachableInstance(name string) config.PostgreSQLInstanceConfig {
	return config.PostgreSQLInstanceConfig{
		Name:     name,
		Host:     "127.0.0.1",
		Port:     1,
		User:     "postgres",
		Password: "secret",
		DBName:   "postgres",
		SSLMode:  "disable",
	}
}

func newStdCollector(t *testing.T, insts ...config.PostgreSQLInstanceConfig) *postgresql.PostgreSQLCollector {
	t.Helper()
	cfg := config.PostgreSQLCollectorConfig{
		Enabled:                 true,
		Instances:               insts,
		MaxConnections:          2,
		CollectPgStatStatements: true,
		TopQueriesLimit:         50,
		TopTablesLimit:          50,
	}
	return postgresql.NewPostgreSQLCollector(cfg, zap.NewNop())
}

// --- Name / IsRunning ---

func TestStdCollector_NameAndInitialState(t *testing.T) {
	c := newStdCollector(t)
	if c.Name() != "postgresql" {
		t.Errorf("Name() = %q, want postgresql", c.Name())
	}
	if c.IsRunning() {
		t.Error("collector should not be running before Start")
	}
}

// --- Start / Stop lifecycle ---

func TestStdCollector_StartCancelsWithContext(t *testing.T) {
	c := newStdCollector(t, unreachableInstance("i1"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	// Wait until Start marks the collector running.
	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector did not start in time")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
	if c.IsRunning() {
		t.Error("collector should not be running after context cancel")
	}
}

func TestStdCollector_DoubleStartFails(t *testing.T) {
	c := newStdCollector(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := c.Start(context.Background()); err == nil {
		t.Error("second Start should return an error")
	}

	cancel()
	<-done
}

func TestStdCollector_StopWhenNotRunning(t *testing.T) {
	c := newStdCollector(t, unreachableInstance("i1"))
	if err := c.Stop(); err != nil {
		t.Errorf("Stop on idle collector: %v", err)
	}
}

// --- Collect drives ensureConnection failure, collectInstance, and the
// collectAll* helpers through connection-refused fast paths. ---

func TestStdCollector_CollectEmptyInstances(t *testing.T) {
	c := newStdCollector(t)
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

func TestStdCollector_CollectUnreachableInstances(t *testing.T) {
	c := newStdCollector(t, unreachableInstance("i1"), unreachableInstance("i2"))
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should not error even when instances are unreachable: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics from unreachable instances, got %d", len(metrics))
	}
}

func TestStdCollector_CollectWithoutPgStatStatements(t *testing.T) {
	cfg := config.PostgreSQLCollectorConfig{
		Enabled:                 true,
		Instances:               []config.PostgreSQLInstanceConfig{unreachableInstance("i1")},
		MaxConnections:          2,
		CollectPgStatStatements: false,
	}
	c := postgresql.NewPostgreSQLCollector(cfg, zap.NewNop())
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}

// --- ensureConnection / closeConnection / advanceBackoff via test seams ---

func TestStdCollector_ConnectFailureAndBackoff(t *testing.T) {
	c := newStdCollector(t)
	first, second := c.ConnectFailurePathExported(context.Background(), unreachableInstance("i1"))
	if first == nil {
		t.Error("expected connect error on first attempt")
	}
	// The second attempt happens immediately, so it must hit the back-off branch.
	if second == nil {
		t.Error("expected back-off error on second attempt")
	}
}

func TestStdCollector_ConnectParseConfigError(t *testing.T) {
	c := newStdCollector(t)
	bad := unreachableInstance("bad")
	bad.SSLMode = "not-a-valid-sslmode"
	first, _ := c.ConnectFailurePathExported(context.Background(), bad)
	if first == nil {
		t.Error("expected parse-config error for invalid sslmode")
	}
}

func TestStdCollector_AdvanceBackoffGrows(t *testing.T) {
	c := newStdCollector(t)
	if got := c.AdvanceBackoffExported(1); got != time.Second {
		t.Errorf("backoff after 1 = %v, want 1s", got)
	}
	if got := c.AdvanceBackoffExported(2); got != 2*time.Second {
		t.Errorf("backoff after 2 = %v, want 2s", got)
	}
	// Saturates at 60s.
	if got := c.AdvanceBackoffExported(20); got != 60*time.Second {
		t.Errorf("backoff after 20 = %v, want 60s", got)
	}
}
