// Package postgresql_test — orchestration-path tests that drive the per-instance
// collect flow (collectInstance / collectAllQueryAnalytics / collectAllSchema)
// and the ensureConnection success path through an injected pgxmock pool via
// postgresql.SetPoolFactoryExported. Before the pool-factory seam these paths
// could only be reached with a live database; an expectation-less mock makes
// every query fail, which the collectors log-and-continue, so the full
// orchestration is walked deterministically without a DB.
//
// TelemetryFlow Agent — AI-Powered Observability & Incident Response Management.
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package postgresql_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// withMockPool installs a pgxmock pool as the package pool factory and returns
// the mock plus a restore func.
func withMockPool(t *testing.T) (pgxmock.PgxPoolIface, func()) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("new mock pool: %v", err)
	}
	// Unordered so each ensureConnection Ping matches an ExpectPing regardless
	// of the interleaved (expectation-less, therefore failing) queries. Queue
	// enough pings for connect + per-call reuse across the whole Collect.
	mock.MatchExpectationsInOrder(false)
	for range 8 {
		mock.ExpectPing()
	}
	postgresql.SetPoolFactoryExported(func(_ context.Context, _ *pgxpool.Config) (postgresql.PgxPool, error) {
		return mock, nil
	})
	return mock, func() {
		postgresql.SetPoolFactoryExported(nil)
		mock.Close()
	}
}

// TestCollect_OrchestrationViaMockPool drives the main collector's Collect ->
// collectInstance -> ensureConnection(success) -> every collect* sub-call
// (each log-and-continues on the mock's query errors), plus
// collectAllQueryAnalytics + collectAllSchema. No DB; no error expected.
func TestCollect_OrchestrationViaMockPool(t *testing.T) {
	_, restore := withMockPool(t)
	defer restore()

	cfg := config.PostgreSQLCollectorConfig{
		Enabled:                 true,
		Instances:               []config.PostgreSQLInstanceConfig{unreachableInstance("i1")},
		MaxConnections:          2,
		CollectPgStatStatements: true,
		TopQueriesLimit:         10,
		TopTablesLimit:          10,
	}
	c := postgresql.NewPostgreSQLCollector(cfg, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	// Queries all fail (no expectations) so no metrics are produced, but the
	// orchestration + connection-success paths are exercised.
	_ = metrics

	// Stop closes the (mock) connection, covering closeConnection with a live pool.
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestCollect_NoPgStatStatements covers the CollectPgStatStatements=false branch
// of collectAllQueryAnalytics (early return) while still walking collectInstance.
func TestCollect_NoPgStatStatements(t *testing.T) {
	_, restore := withMockPool(t)
	defer restore()

	cfg := config.PostgreSQLCollectorConfig{
		Enabled:                 true,
		Instances:               []config.PostgreSQLInstanceConfig{unreachableInstance("i2")},
		MaxConnections:          1,
		CollectPgStatStatements: false,
	}
	c := postgresql.NewPostgreSQLCollector(cfg, zap.NewNop())
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}
