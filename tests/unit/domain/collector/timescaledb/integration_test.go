// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package timescaledb_test

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	tsdb "github.com/telemetryflow/telemetryflow-agent/internal/collector/timescaledb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- detect* ---

func TestDetectPGVersion_Success(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i"}, "", "")
	mock.ExpectQuery("server_version_num").WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow(int(150004)))
	mock.ExpectQuery("server_version").WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow("15.4"))

	if err := tsdb.DetectPGVersionExport(context.Background(), mock, inst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetectPGVersion_Error(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i"}, "", "")
	mock.ExpectQuery("server_version_num").WillReturnError(errBoom)
	if err := tsdb.DetectPGVersionExport(context.Background(), mock, inst); err == nil {
		t.Fatal("expected error")
	}
}

func TestDetectPGVersion_VersionStrFallback(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i"}, "", "")
	mock.ExpectQuery("server_version_num").WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow(int(150004)))
	mock.ExpectQuery("server_version").WillReturnError(errBoom)
	if err := tsdb.DetectPGVersionExport(context.Background(), mock, inst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetectTimescaleDB_Success(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i"}, "", "")
	mock.ExpectQuery("pg_extension").WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow("2.15.0"))
	if err := tsdb.DetectTimescaleDBExport(context.Background(), mock, inst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetectTimescaleDB_Error(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i"}, "", "")
	mock.ExpectQuery("pg_extension").WillReturnError(errBoom)
	if err := tsdb.DetectTimescaleDBExport(context.Background(), mock, inst); err == nil {
		t.Fatal("expected error")
	}
}

// --- collectInstanceMetrics ---

func expectInstanceQueries(mock pgxmock.PgxPoolIface) {
	mock.ExpectQuery("server_version_num").WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow(int(150004)))
	mock.ExpectQuery("server_version").WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow("15.4"))
	mock.ExpectQuery("pg_extension").WillReturnRows(pgxmock.NewRows([]string{"v"}).AddRow("2.15.0"))
	mock.ExpectQuery("backend_type").WillReturnRows(
		pgxmock.NewRows([]string{"active", "idle", "idle_in_transaction", "total"}).
			AddRow(float64(5), float64(3), float64(1), float64(9)))
	mock.ExpectQuery("pg_stat_database").WillReturnRows(
		pgxmock.NewRows([]string{"commits", "rollbacks", "blocks_read", "blocks_hit", "tup_returned", "tup_fetched"}).
			AddRow(float64(100), float64(2), float64(10), float64(90), float64(500), float64(400)))
	mock.ExpectQuery("wait_event_type").WillReturnRows(
		pgxmock.NewRows([]string{"waiting_locks", "waiting_lwlocks"}).AddRow(float64(2), float64(1)))
	mock.ExpectQuery("timescaledb_information.hypertables").WillReturnRows(
		pgxmock.NewRows([]string{"schema", "name", "num_dim", "num_chunks", "compression", "total", "index", "toast", "interval"}).
			AddRow("public", "metrics", int(2), int(10), true, float64(5000), float64(1000), float64(200), "7 days"))
	mock.ExpectQuery("compressed_hypertable_stats").WillReturnRows(
		pgxmock.NewRows([]string{"schema", "name", "before", "after", "compressed", "uncompressed"}).
			AddRow("public", "metrics", float64(4000), float64(1000), int(8), int(2)))
	mock.ExpectQuery("continuous_aggregates").WillReturnRows(
		pgxmock.NewRows([]string{"view_name", "materialized_only", "source_schema", "source_hypertable"}).
			AddRow("daily_view", true, "public", "metrics"))
	mock.ExpectQuery("policy_retention").WillReturnRows(
		pgxmock.NewRows([]string{"proc_name", "last_run_status", "total_failures"}).
			AddRow("policy_retention", "Success", float64(0)))
}

func TestCollectInstanceMetrics_FullSuccess(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "prod"}, "", "")
	expectInstanceQueries(mock)

	metrics := tsdb.CollectInstanceMetricsExport(context.Background(), mock, inst, zap.NewNop())
	// 11 pg base + 7 hypertables + 7 compression + 2 cagg + 3 retention = 30
	if len(metrics) != 30 {
		t.Fatalf("expected 30 metrics, got %d", len(metrics))
	}
}

func TestCollectInstanceMetrics_AllQueriesFail(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "prod"}, "", "")
	// detection errors then every collection errors — everything is logged and skipped.
	mock.ExpectQuery("server_version_num").WillReturnError(errBoom)
	mock.ExpectQuery("pg_extension").WillReturnError(errBoom)
	mock.ExpectQuery("backend_type").WillReturnError(errBoom)
	mock.ExpectQuery("pg_stat_database").WillReturnError(errBoom)
	mock.ExpectQuery("wait_event_type").WillReturnError(errBoom)
	mock.ExpectQuery("timescaledb_information.hypertables").WillReturnError(errBoom)
	mock.ExpectQuery("compressed_hypertable_stats").WillReturnError(errBoom)
	mock.ExpectQuery("continuous_aggregates").WillReturnError(errBoom)
	mock.ExpectQuery("policy_retention").WillReturnError(errBoom)

	metrics := tsdb.CollectInstanceMetricsExport(context.Background(), mock, inst, zap.NewNop())
	// every query errors, so no collection yields metrics.
	if len(metrics) != 0 {
		t.Fatalf("expected 0 metrics, got %d", len(metrics))
	}
}

func TestCollectInstanceMetrics_SkipDetectionWhenKnown(t *testing.T) {
	mock := newMock(t)
	// pgVersionS + tsdbVer already set -> detection skipped, so no version queries expected.
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "prod"}, "15.4", "2.15.0")
	mock.ExpectQuery("backend_type").WillReturnError(errBoom)
	mock.ExpectQuery("pg_stat_database").WillReturnError(errBoom)
	mock.ExpectQuery("wait_event_type").WillReturnError(errBoom)
	mock.ExpectQuery("timescaledb_information.hypertables").WillReturnError(errBoom)
	mock.ExpectQuery("compressed_hypertable_stats").WillReturnError(errBoom)
	mock.ExpectQuery("continuous_aggregates").WillReturnError(errBoom)
	mock.ExpectQuery("policy_retention").WillReturnError(errBoom)

	metrics := tsdb.CollectInstanceMetricsExport(context.Background(), mock, inst, zap.NewNop())
	if len(metrics) != 0 {
		t.Fatalf("expected 0 metrics, got %d", len(metrics))
	}
}

// --- QAN buckets ---

func qanStatementRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{"queryid", "query", "calls", "total_exec_time", "min_exec_time", "max_exec_time", "rows", "shared_blks_hit", "shared_blks_read"})
}

func TestCollectQANBuckets_ExtMissing(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q"})
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))

	buckets, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buckets != nil {
		t.Fatalf("expected nil buckets when extension missing, got %d", len(buckets))
	}
}

func TestCollectQANBuckets_FirstRunNoDelta(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q", DBName: "db", User: "u"})
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(30).WillReturnRows(
		qanStatementRows().AddRow(uint64(1), "SELECT 1", uint64(100), float64(500), float64(1), float64(9), uint64(100), uint64(50), uint64(5)))

	buckets, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(buckets) != 0 {
		t.Fatalf("expected 0 buckets on first run, got %d", len(buckets))
	}
}

func TestCollectQANBuckets_DeltaSecondRun(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q", DBName: "db", User: "u"})

	// First run establishes the snapshot.
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(30).WillReturnRows(
		qanStatementRows().AddRow(uint64(1), "SELECT 1", uint64(100), float64(500), float64(1), float64(9), uint64(100), uint64(50), uint64(5)))
	if _, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, nil); err != nil {
		t.Fatalf("first run error: %v", err)
	}

	// Second run produces a delta bucket.
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WithArgs(30).WillReturnRows(
		qanStatementRows().AddRow(uint64(1), "SELECT 1", uint64(150), float64(800), float64(1), float64(12), uint64(160), uint64(70), uint64(9)))

	buckets, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, map[string]string{"env": "prod"})
	if err != nil {
		t.Fatalf("second run error: %v", err)
	}
	if len(buckets) != 1 {
		t.Fatalf("expected 1 delta bucket, got %d", len(buckets))
	}
	if buckets[0].NumQueries != 50 {
		t.Errorf("expected delta calls 50, got %v", buckets[0].NumQueries)
	}
	if buckets[0].Labels["env"] != "prod" {
		t.Error("expected global label propagated")
	}
}

func TestCollectQANBuckets_QueryError(t *testing.T) {
	mock := newMock(t)
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q"})
	mock.ExpectQuery("pg_stat_statements").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("FROM pg_stat_statements").WillReturnError(errBoom)

	if _, err := tsdb.CollectQANBucketsExport(context.Background(), mock, inst, 10, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestQANInstanceLabels(t *testing.T) {
	inst := tsdb.NewQANTsInstanceExport(config.TimescaleDBInstanceConfig{Name: "q", Host: "h"})
	labels := tsdb.QANInstanceLabelsExport(inst, map[string]string{"team": "obs"})
	if labels["timescaledb_instance"] != "q" || labels["timescaledb_host"] != "h" || labels["db_system"] != "timescaledb" || labels["team"] != "obs" {
		t.Errorf("unexpected labels: %+v", labels)
	}
}

// --- connection helpers ---

func TestBuildConnString(t *testing.T) {
	dsn := tsdb.BuildConnStringExport(config.TimescaleDBInstanceConfig{
		User: "postgres", Password: "secret", Host: "localhost", Port: 5432, DBName: "tsdb", SSLMode: "require",
		SSLRootCert: "/root.crt", SSLCert: "/c.crt", SSLKey: "/k.key",
	})
	for _, want := range []string{"postgres://postgres:secret@localhost:5432/tsdb", "sslmode=require", "sslrootcert=/root.crt", "sslcert=/c.crt", "sslkey=/k.key"} {
		if !contains(dsn, want) {
			t.Errorf("expected dsn to contain %q, got %s", want, dsn)
		}
	}
}

func TestBackoffAndClose(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i"}, "", "")

	// advanceBackoff twice: 0 -> 1s -> 2s.
	c.AdvanceBackoffExport(inst)
	c.AdvanceBackoffExport(inst)
	// closeConnection with a nil pool must be safe.
	c.CloseConnectionExport(inst)
}

func TestEnsureConnection_BackoffReturn(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{}, zap.NewNop())
	inst := tsdb.NewTsdbInstanceExport(config.TimescaleDBInstanceConfig{Name: "i", Host: "localhost", Port: 5432}, "", "")
	if err := c.EnsureConnectionExport(context.Background(), inst); err == nil {
		t.Fatal("expected back-off error")
	}
}

func TestCollect_AllInstancesInBackoff(t *testing.T) {
	c := tsdb.NewTimescaleDBCollector(config.TimescaleDBCollectorConfig{
		Instances: []config.TimescaleDBInstanceConfig{{Name: "a"}, {Name: "b"}},
	}, zap.NewNop())
	c.ForceBackoffAllExport()

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(metrics) != 0 {
		t.Fatalf("expected 0 metrics when all instances are in back-off, got %d", len(metrics))
	}
}

func TestQANCollect_ConnectionError(t *testing.T) {
	// An invalid host makes pgxpool.ParseConfig fail before any network I/O,
	// exercising CollectQAN's loop error handling and ensureConnection's
	// parse-error path deterministically.
	c := tsdb.NewQANTimescaleDBCollector(tsdb.QANTimescaleDBConfig{
		Instances: []config.TimescaleDBInstanceConfig{{Name: "q", Host: "%zz", Port: 5432, User: "u", DBName: "d"}},
	}, zap.NewNop())

	buckets, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("CollectQAN should swallow per-instance errors, got %v", err)
	}
	if buckets != nil {
		t.Fatalf("expected nil buckets, got %d", len(buckets))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
