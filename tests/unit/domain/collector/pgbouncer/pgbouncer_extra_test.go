// Package pgbouncer_test — additional black-box tests that drive Collect
// through an injected ConnectorFactory (no real network) to cover the factory
// override, the per-instance collect path, and the row-label helper.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package pgbouncer_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/pgbouncer"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// twoInstanceCfg returns a config with a single instance so Collect exercises
// the per-instance loop body.
func oneInstanceCfg() config.PgBouncerCollectorConfig {
	return config.PgBouncerCollectorConfig{
		Enabled:   true,
		Instances: []config.PgBouncerInstance{{Name: "pb1", Host: "h", Port: 6432, Database: "pgbouncer", User: "u"}},
	}
}

func TestSetConnectorFactory_CollectHappyPath(t *testing.T) {
	// Inject a fake factory that returns canned STATS + POOLS rows.
	pgbouncer.SetConnectorFactoryExported(func(_ context.Context, _ config.PgBouncerInstance) (pgbouncer.Querier, error) {
		return &fakeQuerier{
			statsRows: &fakeRows{
				cols: []string{"database", "total_xact_count", "total_query_count", "total_received", "total_sent", "avg_query_time", "avg_wait_time"},
				rows: [][]interface{}{{"db1", int64(1), int64(2), int64(3), int64(4), int64(5), int64(6)}},
			},
			poolsRows: &fakeRows{
				cols: []string{"database", "user", "cl_active", "cl_waiting", "sv_active", "sv_idle", "sv_used", "maxwait"},
				rows: [][]interface{}{{"db1", "app", int64(5), int64(0), int64(2), int64(3), int64(1), int64(0)}},
			},
		}, nil
	})
	defer pgbouncer.SetConnectorFactoryExported(nil) // restore default

	coll := pgbouncer.NewPgBouncerCollector(oneInstanceCfg(), zap.NewNop())
	metrics, err := coll.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics from injected factory, got 0")
	}
}

func TestSetConnectorFactory_ConnectError(t *testing.T) {
	// Factory returns an error → collectInstance returns wrapped error →
	// Collect logs + continues → zero metrics, no error.
	pgbouncer.SetConnectorFactoryExported(func(_ context.Context, _ config.PgBouncerInstance) (pgbouncer.Querier, error) {
		return nil, errors.New("refused")
	})
	defer pgbouncer.SetConnectorFactoryExported(nil)

	coll := pgbouncer.NewPgBouncerCollector(oneInstanceCfg(), zap.NewNop())
	metrics, err := coll.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not surface per-instance error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics on connect error, got %d", len(metrics))
	}
}

func TestSetConnectorFactory_NilRestoresDefault(t *testing.T) {
	// Override then restore; restoring with nil must not panic and leaves a
	// usable default factory (exercised indirectly by later tests).
	pgbouncer.SetConnectorFactoryExported(func(_ context.Context, _ config.PgBouncerInstance) (pgbouncer.Querier, error) {
		return &fakeQuerier{}, nil
	})
	pgbouncer.SetConnectorFactoryExported(nil)
}

func TestWithRowLabelsExported(t *testing.T) {
	base := map[string]string{"pgbouncer_instance": "pb1"}
	out := pgbouncer.WithRowLabelsExported(base, "mydb", "myuser")

	if out["database"] != "mydb" || out["user"] != "myuser" {
		t.Errorf("expected database/user labels, got %v", out)
	}
	if out["pgbouncer_instance"] != "pb1" {
		t.Errorf("base labels must be preserved, got %v", out)
	}
	// Must not mutate the caller's base map.
	if _, leaked := base["database"]; leaked {
		t.Error("withRowLabels must not mutate the base map")
	}
}
