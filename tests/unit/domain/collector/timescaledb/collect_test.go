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
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	tsdb "github.com/telemetryflow/telemetryflow-agent/internal/collector/timescaledb"
)

var errBoom = errors.New("boom")

func newMock(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	t.Cleanup(func() { mock.Close() })
	return mock
}

func baseLabels() map[string]string {
	return map[string]string{"timescaledb_instance": "test", "timescaledb_host": "localhost"}
}

// --- Connection stats ---

func TestCollectConnectionStats_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"active", "idle", "idle_in_transaction", "total"}).
		AddRow(float64(5), float64(3), float64(1), float64(9))
	mock.ExpectQuery("backend_type").WillReturnRows(rows)

	metrics, err := tsdb.CollectConnectionStatsExport(context.Background(), mock, baseLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metrics, got %d", len(metrics))
	}
	if metrics[0].Value != 5 {
		t.Errorf("expected active=5, got %v", metrics[0].Value)
	}
}

func TestCollectConnectionStats_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("backend_type").WillReturnError(errBoom)
	if _, err := tsdb.CollectConnectionStatsExport(context.Background(), mock, baseLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectConnectionStats_NullScan(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"active", "idle", "idle_in_transaction", "total"}).
		AddRow("bad", float64(3), float64(1), float64(9))
	mock.ExpectQuery("backend_type").WillReturnRows(rows)
	if _, err := tsdb.CollectConnectionStatsExport(context.Background(), mock, baseLabels()); err == nil {
		t.Fatal("expected scan error on NULL")
	}
}

// --- Database stats ---

func TestCollectDatabaseStats_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"commits", "rollbacks", "blocks_read", "blocks_hit", "tup_returned", "tup_fetched"}).
		AddRow(float64(100), float64(2), float64(10), float64(90), float64(500), float64(400))
	mock.ExpectQuery("pg_stat_database").WillReturnRows(rows)

	metrics, err := tsdb.CollectDatabaseStatsExport(context.Background(), mock, baseLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 5 {
		t.Fatalf("expected 5 metrics, got %d", len(metrics))
	}
}

func TestCollectDatabaseStats_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("pg_stat_database").WillReturnError(errBoom)
	if _, err := tsdb.CollectDatabaseStatsExport(context.Background(), mock, baseLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectDatabaseStats_NullScan(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"commits", "rollbacks", "blocks_read", "blocks_hit", "tup_returned", "tup_fetched"}).
		AddRow("bad", float64(2), float64(10), float64(90), float64(500), float64(400))
	mock.ExpectQuery("pg_stat_database").WillReturnRows(rows)
	if _, err := tsdb.CollectDatabaseStatsExport(context.Background(), mock, baseLabels()); err == nil {
		t.Fatal("expected scan error")
	}
}

// --- Activity stats ---

func TestCollectActivityStats_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"waiting_locks", "waiting_lwlocks"}).
		AddRow(float64(2), float64(1))
	mock.ExpectQuery("wait_event_type").WillReturnRows(rows)

	metrics, err := tsdb.CollectActivityStatsExport(context.Background(), mock, baseLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
}

func TestCollectActivityStats_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("wait_event_type").WillReturnError(errBoom)
	if _, err := tsdb.CollectActivityStatsExport(context.Background(), mock, baseLabels()); err == nil {
		t.Fatal("expected error")
	}
}

// --- PG base aggregate ---

func TestCollectPGBaseMetrics_AllSucceed(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("backend_type").WillReturnRows(
		pgxmock.NewRows([]string{"active", "idle", "idle_in_transaction", "total"}).
			AddRow(float64(5), float64(3), float64(1), float64(9)))
	mock.ExpectQuery("pg_stat_database").WillReturnRows(
		pgxmock.NewRows([]string{"commits", "rollbacks", "blocks_read", "blocks_hit", "tup_returned", "tup_fetched"}).
			AddRow(float64(100), float64(2), float64(10), float64(90), float64(500), float64(400)))
	mock.ExpectQuery("wait_event_type").WillReturnRows(
		pgxmock.NewRows([]string{"waiting_locks", "waiting_lwlocks"}).
			AddRow(float64(2), float64(1)))

	metrics, err := tsdb.CollectPGBaseMetricsExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 11 { // 4 + 5 + 2
		t.Fatalf("expected 11 metrics, got %d", len(metrics))
	}
}

func TestCollectPGBaseMetrics_AllFail(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("backend_type").WillReturnError(errBoom)
	mock.ExpectQuery("pg_stat_database").WillReturnError(errBoom)
	mock.ExpectQuery("wait_event_type").WillReturnError(errBoom)

	metrics, err := tsdb.CollectPGBaseMetricsExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("aggregate should not return error, got %v", err)
	}
	if len(metrics) != 0 {
		t.Fatalf("expected 0 metrics on all-fail, got %d", len(metrics))
	}
}

// --- Chunks ---

func TestCollectChunks_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"schema", "name", "total", "compressed", "uncompressed", "size"}).
		AddRow("public", "metrics", int(10), int(6), int(4), float64(2048)).
		AddRow("public", "logs", int(5), int(2), int(3), float64(1024))
	mock.ExpectQuery("timescaledb_information.chunks").WillReturnRows(rows)

	metrics, err := tsdb.CollectChunksExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 5 per hypertable * 2 + 3 totals = 13
	if len(metrics) != 13 {
		t.Fatalf("expected 13 metrics, got %d", len(metrics))
	}
}

func TestCollectChunks_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("timescaledb_information.chunks").WillReturnError(errBoom)
	if _, err := tsdb.CollectChunksExport(context.Background(), mock, baseLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectChunks_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"schema", "name", "total", "compressed", "uncompressed", "size"}).
		AddRow("public", "metrics", "bad", int(6), int(4), float64(2048))
	mock.ExpectQuery("timescaledb_information.chunks").WillReturnRows(rows)

	metrics, err := tsdb.CollectChunksExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// bad row skipped; only 3 total metrics remain
	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics, got %d", len(metrics))
	}
}

// --- Compression ---

func TestCollectCompression_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"schema", "name", "before", "after", "compressed", "uncompressed"}).
		AddRow("public", "metrics", float64(4000), float64(1000), int(8), int(2))
	mock.ExpectQuery("compressed_hypertable_stats").WillReturnRows(rows)

	metrics, err := tsdb.CollectCompressionExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 7 {
		t.Fatalf("expected 7 metrics, got %d", len(metrics))
	}
}

func TestCollectCompression_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("compressed_hypertable_stats").WillReturnError(errBoom)
	if _, err := tsdb.CollectCompressionExport(context.Background(), mock, baseLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectCompression_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"schema", "name", "before", "after", "compressed", "uncompressed"}).
		AddRow("public", "metrics", "bad", float64(1000), int(8), int(2))
	mock.ExpectQuery("compressed_hypertable_stats").WillReturnRows(rows)

	metrics, err := tsdb.CollectCompressionExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Fatalf("expected 0 metrics, got %d", len(metrics))
	}
}

// --- Continuous aggregates ---

func TestCollectContinuousAggregates_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"view_name", "materialized_only", "source_schema", "source_hypertable"}).
		AddRow("daily_view", true, "public", "metrics").
		AddRow("hourly_view", false, "public", "metrics")
	mock.ExpectQuery("continuous_aggregates").WillReturnRows(rows)

	metrics, err := tsdb.CollectContinuousAggregatesExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 per cagg * 2 + 1 count = 3
	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics, got %d", len(metrics))
	}
}

func TestCollectContinuousAggregates_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("continuous_aggregates").WillReturnError(errBoom)
	if _, err := tsdb.CollectContinuousAggregatesExport(context.Background(), mock, baseLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectContinuousAggregates_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"view_name", "materialized_only", "source_schema", "source_hypertable"}).
		AddRow(float64(1), true, "public", "metrics")
	mock.ExpectQuery("continuous_aggregates").WillReturnRows(rows)

	metrics, err := tsdb.CollectContinuousAggregatesExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 { // only count metric
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
}

// --- Data nodes ---

func TestCollectDataNodes_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"node_name"}).
		AddRow("dn1").
		AddRow("dn2")
	mock.ExpectQuery("data_nodes").WillReturnRows(rows)

	metrics, err := tsdb.CollectDataNodesExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 per node * 2 + 2 totals = 4
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metrics, got %d", len(metrics))
	}
}

func TestCollectDataNodes_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("data_nodes").WillReturnError(errBoom)
	if _, err := tsdb.CollectDataNodesExport(context.Background(), mock, baseLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectDataNodes_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"node_name"}).AddRow(float64(1))
	mock.ExpectQuery("data_nodes").WillReturnRows(rows)

	metrics, err := tsdb.CollectDataNodesExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 { // totals only
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
}

// --- Hypertables ---

func TestCollectHypertables_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"schema", "name", "num_dim", "num_chunks", "compression", "total", "index", "toast", "interval"}).
		AddRow("public", "metrics", int(2), int(10), true, float64(5000), float64(1000), float64(200), "7 days")
	mock.ExpectQuery("timescaledb_information.hypertables").WillReturnRows(rows)

	metrics, err := tsdb.CollectHypertablesExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 6 per hypertable + 1 count = 7
	if len(metrics) != 7 {
		t.Fatalf("expected 7 metrics, got %d", len(metrics))
	}
}

func TestCollectHypertables_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("timescaledb_information.hypertables").WillReturnError(errBoom)
	if _, err := tsdb.CollectHypertablesExport(context.Background(), mock, baseLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectHypertables_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"schema", "name", "num_dim", "num_chunks", "compression", "total", "index", "toast", "interval"}).
		AddRow("public", "metrics", "bad", int(10), true, float64(5000), float64(1000), float64(200), "7 days")
	mock.ExpectQuery("timescaledb_information.hypertables").WillReturnRows(rows)

	metrics, err := tsdb.CollectHypertablesExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 { // count only
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
}

// --- Jobs ---

func TestCollectJobs_Success(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"job_id", "proc_name", "schedule_interval", "max_runtime", "last_run_status", "last_run_duration_s", "total_successes", "total_failures", "total_crashes", "next_start"}).
		AddRow(int(1000), "compression", "1h0m0s", "0", "Success", float64(2.5), float64(100), float64(0), float64(0), time.Now().Add(time.Hour)).
		AddRow(int(1001), "retention", "24h0m0s", "0", "Failed", float64(0.5), float64(50), float64(3), float64(1), time.Now().Add(-time.Hour))
	mock.ExpectQuery("timescaledb_information.jobs").WillReturnRows(rows)

	metrics, err := tsdb.CollectJobsExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 5 per job * 2 + 5 totals = 15
	if len(metrics) != 15 {
		t.Fatalf("expected 15 metrics, got %d", len(metrics))
	}
}

func TestCollectJobs_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("timescaledb_information.jobs").WillReturnError(errBoom)
	if _, err := tsdb.CollectJobsExport(context.Background(), mock, baseLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectJobs_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"job_id", "proc_name", "schedule_interval", "max_runtime", "last_run_status", "last_run_duration_s", "total_successes", "total_failures", "total_crashes", "next_start"}).
		AddRow("bad", "compression", "1h0m0s", "0", "Success", float64(2.5), float64(100), float64(0), float64(0), time.Now())
	mock.ExpectQuery("timescaledb_information.jobs").WillReturnRows(rows)

	metrics, err := tsdb.CollectJobsExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 5 { // totals only
		t.Fatalf("expected 5 metrics, got %d", len(metrics))
	}
}

// --- Retention ---

func TestCollectRetention_PolicyPresent(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"proc_name", "last_run_status", "total_failures"}).
		AddRow("policy_retention", "Success", float64(0))
	mock.ExpectQuery("policy_retention").WillReturnRows(rows)

	metrics, err := tsdb.CollectRetentionExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 per row + 1 policy_missing = 3
	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics, got %d", len(metrics))
	}
}

func TestCollectRetention_PolicyMissing(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"proc_name", "last_run_status", "total_failures"})
	mock.ExpectQuery("policy_retention").WillReturnRows(rows)

	metrics, err := tsdb.CollectRetentionExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].Value != 1.0 {
		t.Errorf("expected policy_missing=1, got %v", metrics[0].Value)
	}
}

func TestCollectRetention_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("policy_retention").WillReturnError(errBoom)
	if _, err := tsdb.CollectRetentionExport(context.Background(), mock, baseLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectRetention_RowScanErrorSkipped(t *testing.T) {
	mock := newMock(t)
	rows := pgxmock.NewRows([]string{"proc_name", "last_run_status", "total_failures"}).
		AddRow("policy_retention", "Success", "bad")
	mock.ExpectQuery("policy_retention").WillReturnRows(rows)

	metrics, err := tsdb.CollectRetentionExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// scan error -> policyMissing stays 1, only the missing metric emitted
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
}

// --- Tiering ---

func TestCollectTiering_Enabled(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("timescaledb_osm").WillReturnRows(
		pgxmock.NewRows([]string{"exists"}).AddRow(true))

	metrics, err := tsdb.CollectTieringExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 || metrics[0].Value != 1 {
		t.Fatalf("expected enabled=1, got %+v", metrics)
	}
}

func TestCollectTiering_Disabled(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("timescaledb_osm").WillReturnRows(
		pgxmock.NewRows([]string{"exists"}).AddRow(false))

	metrics, err := tsdb.CollectTieringExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 || metrics[0].Value != 0 {
		t.Fatalf("expected enabled=0, got %+v", metrics)
	}
}

func TestCollectTiering_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("timescaledb_osm").WillReturnError(errBoom)

	metrics, err := tsdb.CollectTieringExport(context.Background(), mock, baseLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// error path returns enabled=0 metric
	if len(metrics) != 1 || metrics[0].Value != 0 {
		t.Fatalf("expected enabled=0 on error, got %+v", metrics)
	}
}
