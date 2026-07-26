// Package pgbouncer_test contains black-box unit tests for the PgBouncer
// collector. Tests inject a fake Querier so no real DB is required.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package pgbouncer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/pgbouncer"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// fakeRows iterates over canned row data.
type fakeRows struct {
	cols []string
	rows [][]interface{}
	idx  int
}

func (r *fakeRows) Next() bool {
	r.idx++
	return r.idx <= len(r.rows)
}
func (r *fakeRows) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	for i := range dest {
		if i >= len(row) {
			continue
		}
		// dest[i] is `any` containing a pointer; use reflection-free assignment
		// by type-switching on the known pointer types we use in our rows.
		switch dst := dest[i].(type) {
		case *interface{}:
			*dst = row[i]
		case *int64:
			if v, ok := row[i].(int64); ok {
				*dst = v
			}
		case *string:
			if v, ok := row[i].(string); ok {
				*dst = v
			}
		default:
			// For any other pointer type, fall back to assignment via fmt.
		}
	}
	return nil
}
func (r *fakeRows) Close() {}

// fakeQuerier dispatches SQL to the right canned response based on the query
// substring. PgBouncer's collectInstance issues "SHOW STATS" and "SHOW POOLS".
type fakeQuerier struct {
	statsRows *fakeRows
	poolsRows *fakeRows
	statsErr  error
	poolsErr  error
}

func (q *fakeQuerier) Query(_ context.Context, sql string, _ ...any) (pgbouncer.Rows, error) {
	switch {
	case sql == "STATS" || contains(sql, "SHOW STATS"):
		if q.statsErr != nil {
			return nil, q.statsErr
		}
		return q.statsRows, nil
	case sql == "POOLS" || contains(sql, "SHOW POOLS"):
		if q.poolsErr != nil {
			return nil, q.poolsErr
		}
		return q.poolsRows, nil
	default:
		return nil, errors.New("unknown query: " + sql)
	}
}
func (q *fakeQuerier) Close() {}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestPgBouncerCollector_Name(t *testing.T) {
	coll := pgbouncer.NewPgBouncerCollector(config.PgBouncerCollectorConfig{}, zap.NewNop())
	if coll.Name() != "pgbouncer" {
		t.Errorf("expected 'pgbouncer', got %q", coll.Name())
	}
}

func TestPgBouncerCollector_Lifecycle(t *testing.T) {
	coll := pgbouncer.NewPgBouncerCollector(config.PgBouncerCollectorConfig{}, zap.NewNop())
	if coll.IsRunning() {
		t.Error("should not be running before Start")
	}
	if err := coll.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !coll.IsRunning() {
		t.Error("should be running after Start")
	}
	if err := coll.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if coll.IsRunning() {
		t.Error("should not be running after Stop")
	}
}

func TestPgBouncerCollector_NoInstances(t *testing.T) {
	coll := pgbouncer.NewPgBouncerCollector(config.PgBouncerCollectorConfig{}, zap.NewNop())
	metrics, err := coll.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics with no instances, got %d", len(metrics))
	}
}

func TestPgBouncerCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*pgbouncer.PgBouncerCollector)(nil)
}

func TestPgBouncerCollector_ConnectionFailureGraceful(t *testing.T) {
	cfg := config.PgBouncerCollectorConfig{
		Enabled: true,
		Instances: []config.PgBouncerInstance{{
			Name:     "dead",
			Host:     "127.0.0.1",
			Port:     1, // privileged port, will refuse
			Database: "pgbouncer",
			User:     "test",
			Password: "test",
			Timeout:  100 * time.Millisecond,
		}},
	}
	coll := pgbouncer.NewPgBouncerCollector(cfg, zap.NewNop())
	if err := coll.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = coll.Stop() }()

	// Collect should not panic and should not return an error; the failed
	// instance is logged and skipped. Zero metrics is acceptable.
	metrics, err := coll.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error on connection failure: %v", err)
	}
	// Either 0 metrics (skip) or a state=0 metric — both are acceptable.
	for _, m := range metrics {
		if m.Name == "db.pgbouncer.state" && m.Value == 0 {
			return // OK
		}
	}
}

func TestCollectStatsExported_HappyPath(t *testing.T) {
	labels := map[string]string{"pgbouncer_instance": "test"}
	q := &fakeQuerier{
		statsRows: &fakeRows{
			cols: []string{"database", "total_xact_count", "total_query_count", "total_received", "total_sent",
				"avg_query_time", "avg_wait_time"},
			rows: [][]interface{}{
				{"db1", int64(100), int64(200), int64(300), int64(400), int64(50), int64(10)},
			},
		},
	}
	metrics, err := pgbouncer.CollectStatsExported(context.Background(), q, labels)
	if err != nil {
		t.Fatalf("CollectStatsExported: %v", err)
	}
	if len(metrics) < 6 {
		t.Errorf("expected >=6 stats metrics, got %d", len(metrics))
	}
}

func TestCollectStatsExported_QueryError(t *testing.T) {
	q := &fakeQuerier{statsErr: errors.New("connection lost")}
	metrics, err := pgbouncer.CollectStatsExported(context.Background(), q, nil)
	if err == nil {
		t.Error("expected error from stats query failure")
	}
	if metrics != nil {
		t.Errorf("expected nil metrics on error, got %d", len(metrics))
	}
}

func TestCollectPoolsExported_HappyPath(t *testing.T) {
	labels := map[string]string{"pgbouncer_instance": "test"}
	q := &fakeQuerier{
		poolsRows: &fakeRows{
			cols: []string{"database", "user", "cl_active", "cl_waiting", "sv_active", "sv_idle", "sv_used", "maxwait"},
			rows: [][]interface{}{
				{"db1", "app", int64(5), int64(0), int64(2), int64(3), int64(1), int64(0)},
			},
		},
	}
	metrics, err := pgbouncer.CollectPoolsExported(context.Background(), q, labels)
	if err != nil {
		t.Fatalf("CollectPoolsExported: %v", err)
	}
	if len(metrics) < 6 {
		t.Errorf("expected >=6 pool metrics, got %d", len(metrics))
	}
}

func TestInstanceLabelsExported(t *testing.T) {
	cfg := config.PgBouncerCollectorConfig{Tags: map[string]string{"env": "prod"}}
	inst := config.PgBouncerInstance{Name: "test", Host: "h", Port: 6432}
	labels := pgbouncer.InstanceLabelsExported(cfg, inst)
	if labels["pgbouncer_instance"] != "test" {
		t.Errorf("expected pgbouncer_instance=test, got %q", labels["pgbouncer_instance"])
	}
	if labels["env"] != "prod" {
		t.Errorf("expected env=prod, got %q", labels["env"])
	}
}

func TestApplyInstanceDefaultsExported(t *testing.T) {
	inst := &config.PgBouncerInstance{Name: "x"}
	pgbouncer.ApplyInstanceDefaultsExported(inst)
	if inst.Database != "pgbouncer" {
		t.Errorf("expected default Database=pgbouncer, got %q", inst.Database)
	}
	if inst.Timeout == 0 {
		t.Error("expected default Timeout > 0")
	}
}
