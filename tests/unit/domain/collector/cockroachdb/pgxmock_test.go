// Package cockroachdb_test drives the CockroachDB collector query-scanning
// paths deterministically with pgxmock, covering success, query-error and
// NULL/scan-error branches without a live database.
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
package cockroachdb_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cockroachdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

var errBoom = errors.New("boom")

func newMockPool(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	pool, err := pgxmock.NewPool()
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })
	return pool
}

func testLabels() map[string]string {
	return map[string]string{"cockroachdb_instance": "n1"}
}

// --- node metrics ---

func TestCollectNodeMetrics_Success(t *testing.T) {
	pool := newMockPool(t)
	rows := pgxmock.NewRows([]string{"is_live", "total_ranges", "leaseholders", "replicas", "live_bytes"}).
		AddRow(true, 10, 5, 30, int64(1024))
	pool.ExpectQuery("n.is_live").WillReturnRows(rows)

	metrics, err := cockroachdb.CollectNodeMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 5)
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestCollectNodeMetrics_FallbackOnError(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("n.is_live").WillReturnError(errBoom)
	pool.ExpectQuery("gossip_liveness").
		WillReturnRows(pgxmock.NewRows([]string{"is_live"}).AddRow(false))

	metrics, err := cockroachdb.CollectNodeMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 1)
	assert.Equal(t, float64(0), metrics[0].Value) // is_live=false exercises boolToFloat false branch
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestScalarHelpers(t *testing.T) {
	assert.Equal(t, 3.14, cockroachdb.ParseFloatExported("3.14"))
	assert.Equal(t, float64(0), cockroachdb.ParseFloatExported("not-a-number"))
	assert.Equal(t, float64(1), cockroachdb.BoolToFloatExported(true))
	assert.Equal(t, float64(0), cockroachdb.BoolToFloatExported(false))
}

func TestCollectNodeMetrics_FallbackAlsoErrors(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("n.is_live").WillReturnError(errBoom)
	pool.ExpectQuery("gossip_liveness").WillReturnError(errBoom)

	metrics, err := cockroachdb.CollectNodeMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, metrics)
}

// --- sql metrics ---

func expectSQLRows(pool pgxmock.PgxPoolIface) {
	pool.ExpectQuery("node_sql_sessions").
		WillReturnRows(pgxmock.NewRows([]string{"conns", "idle", "active"}).AddRow(8, 3, 5))
	pool.ExpectQuery("node_transaction_metrics").
		WillReturnRows(pgxmock.NewRows([]string{"total", "commits", "rollbacks", "restarts"}).
			AddRow(100, 90, 10, 2))
}

func TestCollectSQLMetrics_SuccessAndRate(t *testing.T) {
	pool := newMockPool(t)
	expectSQLRows(pool)
	expectSQLRows(pool)

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})

	// First call establishes previous counters => no rate metrics yet.
	first, err := cockroachdb.CollectSQLMetricsExported(context.Background(), pool, inst, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, first, 7)

	// Second call: counters unchanged (>= prev) => rate metrics emitted.
	second, err := cockroachdb.CollectSQLMetricsExported(context.Background(), pool, inst, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, second, 10) // 7 base + 3 rate
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestCollectSQLMetrics_QueryErrorsZeroed(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("node_sql_sessions").WillReturnError(errBoom)
	pool.ExpectQuery("node_transaction_metrics").WillReturnError(errBoom)

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})
	metrics, err := cockroachdb.CollectSQLMetricsExported(context.Background(), pool, inst, testLabels(), zap.NewNop())
	require.NoError(t, err) // errors are swallowed and zeroed
	assert.Len(t, metrics, 7)
	require.NoError(t, pool.ExpectationsWereMet())
}

// --- store metrics ---

func TestCollectStoreMetrics_Success(t *testing.T) {
	pool := newMockPool(t)
	cols := []string{"store_id", "capacity", "available", "used", "lease_count", "range_count", "read_amp"}
	rows := pgxmock.NewRows(cols).
		AddRow(1, int64(1000), int64(400), int64(600), 12, 34, 2).
		AddRow(2, int64(2000), int64(1000), int64(1000), 5, 6, 1)
	pool.ExpectQuery("kv_store_status").WillReturnRows(rows)

	metrics, err := cockroachdb.CollectStoreMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 14) // 7 metrics per store row
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestCollectStoreMetrics_ScanErrorSkipsRow(t *testing.T) {
	pool := newMockPool(t)
	cols := []string{"store_id", "capacity", "available", "used", "lease_count", "range_count", "read_amp"}
	// A NULL in a non-pointer int64 column makes Scan fail => row skipped.
	rows := pgxmock.NewRows(cols).
		AddRow(1, "bad", int64(400), int64(600), 12, 34, 2).
		AddRow(2, int64(2000), int64(1000), int64(1000), 5, 6, 1)
	pool.ExpectQuery("kv_store_status").WillReturnRows(rows)

	metrics, err := cockroachdb.CollectStoreMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 7) // first row skipped, only the valid row emitted
}

func TestCollectStoreMetrics_QueryError(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("kv_store_status").WillReturnError(errBoom)

	metrics, err := cockroachdb.CollectStoreMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, metrics)
}

// --- statement stats ---

func TestCollectStatementStats_Success(t *testing.T) {
	pool := newMockPool(t)
	cols := []string{
		"fingerprint_id", "app_name", "count", "first_attempt_count", "max_retries",
		"avg_latency", "rows_read", "rows_written", "bytes_read", "network_bytes",
	}
	rows := pgxmock.NewRows(cols).
		AddRow("fp1", "app1", int64(10), int64(9), int64(1), 12.5, int64(100), int64(50), int64(2048), int64(512)).
		AddRow("fp2", "", int64(5), int64(5), int64(0), 3.0, int64(10), int64(0), int64(64), int64(16))
	pool.ExpectQuery("node_statement_statistics").WithArgs(pgxmock.AnyArg()).WillReturnRows(rows)

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})
	metrics, err := cockroachdb.CollectStatementStatsExported(context.Background(), pool, inst, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 16) // 8 metrics per statement row
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestCollectStatementStats_ScanErrorSkipsRow(t *testing.T) {
	pool := newMockPool(t)
	cols := []string{
		"fingerprint_id", "app_name", "count", "first_attempt_count", "max_retries",
		"avg_latency", "rows_read", "rows_written", "bytes_read", "network_bytes",
	}
	rows := pgxmock.NewRows(cols).
		AddRow("fp1", "app1", "bad", int64(9), int64(1), 12.5, int64(100), int64(50), int64(2048), int64(512))
	pool.ExpectQuery("node_statement_statistics").WithArgs(pgxmock.AnyArg()).WillReturnRows(rows)

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})
	metrics, err := cockroachdb.CollectStatementStatsExported(context.Background(), pool, inst, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

func TestCollectStatementStats_QueryError(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("node_statement_statistics").WithArgs(pgxmock.AnyArg()).WillReturnError(errBoom)

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})
	metrics, err := cockroachdb.CollectStatementStatsExported(context.Background(), pool, inst, testLabels(), zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, metrics)
}

func TestCollectStatementStats_CustomLimit(t *testing.T) {
	pool := newMockPool(t)
	cols := []string{
		"fingerprint_id", "app_name", "count", "first_attempt_count", "max_retries",
		"avg_latency", "rows_read", "rows_written", "bytes_read", "network_bytes",
	}
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(cols))

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})
	inst.TopStmtsLimit = 50
	metrics, err := cockroachdb.CollectStatementStatsExported(context.Background(), pool, inst, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// --- range metrics ---

func TestCollectRangeMetrics_Success(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("ranges_no_leases").
		WillReturnRows(pgxmock.NewRows([]string{"total", "replicas", "under"}).AddRow(20, 60, 1))
	pool.ExpectQuery("GROUP BY lease_holder").
		WillReturnRows(pgxmock.NewRows([]string{"lease_holder", "count"}).AddRow(1, 12).AddRow(2, 8))

	metrics, err := cockroachdb.CollectRangeMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 6) // 4 base range metrics + 2 leaseholder metrics
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestCollectRangeMetrics_LeaseholderErrorTolerated(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("ranges_no_leases").
		WillReturnRows(pgxmock.NewRows([]string{"total", "replicas", "under"}).AddRow(20, 60, 1))
	pool.ExpectQuery("GROUP BY lease_holder").WillReturnError(errBoom)

	metrics, err := cockroachdb.CollectRangeMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 4) // leaseholder error logged, base metrics returned
}

func TestCollectRangeMetrics_QueryError(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("ranges_no_leases").WillReturnError(errBoom)

	metrics, err := cockroachdb.CollectRangeMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, metrics)
}

func TestCollectRangeMetrics_LeaseholderScanErrorSkipsRow(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("ranges_no_leases").
		WillReturnRows(pgxmock.NewRows([]string{"total", "replicas", "under"}).AddRow(20, 60, 1))
	pool.ExpectQuery("GROUP BY lease_holder").
		WillReturnRows(pgxmock.NewRows([]string{"lease_holder", "count"}).AddRow("notanint", 8).AddRow(2, 8))

	metrics, err := cockroachdb.CollectRangeMetricsExported(context.Background(), pool, testLabels(), zap.NewNop())
	require.NoError(t, err)
	assert.Len(t, metrics, 5) // 4 base + 1 valid leaseholder (bad row skipped)
}

// --- version detection ---

func TestDetectVersion_Success(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("node_executable_version").
		WillReturnRows(pgxmock.NewRows([]string{"version", "cluster_id", "node_id"}).
			AddRow("v23.1.0", "abc-123", 7))

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})
	err := cockroachdb.DetectVersionExported(context.Background(), pool, inst, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, "v23.1.0", inst.Version)
	assert.Equal(t, "abc-123", inst.ClusterID)
	assert.Equal(t, 7, inst.NodeID)
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestDetectVersion_Error(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("node_executable_version").WillReturnError(errBoom)

	inst := cockroachdb.NewCRDBTestInstance(config.CockroachDBInstanceConfig{Name: "n1"})
	err := cockroachdb.DetectVersionExported(context.Background(), pool, inst, zap.NewNop())
	require.Error(t, err)
	assert.Empty(t, inst.Version)
}

// --- QAN statement statistics scanning ---

func qanCols() []string {
	return []string{
		"fingerprint_id", "anonymized_query", "count", "first_attempt_count",
		"max_retries", "avg_latency", "max_latency", "rows_read", "rows_written",
		"bytes_read", "network_bytes", "app_name",
	}
}

func newQANCollector() *cockroachdb.QANCockroachDBCollector {
	return cockroachdb.NewQANCockroachDBCollector(cockroachdb.QANCockroachDBConfig{
		Instances:       []config.CockroachDBInstanceConfig{{Name: "n1", Database: "system"}},
		TopQueriesLimit: 100,
		Logger:          zap.NewNop(),
	}, zap.NewNop())
}

func TestQAN_CollectInstanceRows_Delta(t *testing.T) {
	pool := newMockPool(t)
	// First snapshot (no previous state => no buckets).
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(qanCols()).
			AddRow("fp1", "SELECT 1", 10.0, 8.0, 1.0, 1e9, 2e9, 100.0, 50.0, 2048.0, 512.0, "app1"))
	// Second snapshot with higher counts => one delta bucket.
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(qanCols()).
			AddRow("fp1", "SELECT 1", 25.0, 20.0, 2.0, 1e9, 2e9, 300.0, 120.0, 4096.0, 1024.0, "app1"))

	c := newQANCollector()

	first, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.NoError(t, err)
	assert.Empty(t, first)

	second, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, "fp1", second[0].QueryID)
	assert.Equal(t, 15.0, second[0].NumQueries) // 25 - 10
	require.NoError(t, pool.ExpectationsWereMet())
}

func TestQAN_CollectInstanceRows_NoDeltaWhenCountNotIncreasing(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(qanCols()).
			AddRow("fp1", "SELECT 1", 10.0, 8.0, 1.0, 1e9, 2e9, 100.0, 50.0, 2048.0, 512.0, "app1"))
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(qanCols()).
			AddRow("fp1", "SELECT 1", 10.0, 8.0, 1.0, 1e9, 2e9, 100.0, 50.0, 2048.0, 512.0, "app1"))

	c := newQANCollector()
	_, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.NoError(t, err)
	buckets, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.NoError(t, err)
	assert.Empty(t, buckets) // deltaCount <= 0 => skipped
}

func TestQAN_CollectInstanceRows_QueryError(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("node_statement_statistics").WithArgs(pgxmock.AnyArg()).WillReturnError(errBoom)

	c := newQANCollector()
	buckets, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.Error(t, err)
	assert.Nil(t, buckets)
}

func TestQAN_CollectInstanceRows_ScanErrorSkipsRow(t *testing.T) {
	pool := newMockPool(t)
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(qanCols()).
			AddRow("fp1", "SELECT 1", "bad", 8.0, 1.0, 1e9, 2e9, 100.0, 50.0, 2048.0, 512.0, "app1"))

	c := newQANCollector()
	buckets, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestQAN_CollectInstanceRows_LongExampleTruncated(t *testing.T) {
	long := make([]byte, 2500)
	for i := range long {
		long[i] = 'x'
	}
	pool := newMockPool(t)
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(qanCols()).
			AddRow("fp1", string(long), 10.0, 8.0, 1.0, 1e9, 2e9, 100.0, 50.0, 2048.0, 512.0, "app1"))
	pool.ExpectQuery("node_statement_statistics").
		WithArgs(pgxmock.AnyArg()).
		WillReturnRows(pgxmock.NewRows(qanCols()).
			AddRow("fp1", string(long), 25.0, 20.0, 2.0, 1e9, 2e9, 300.0, 120.0, 4096.0, 1024.0, "app1"))

	c := newQANCollector()
	_, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.NoError(t, err)
	buckets, err := c.CollectInstanceRowsExported(context.Background(), pool)
	require.NoError(t, err)
	require.Len(t, buckets, 1)
	assert.True(t, buckets[0].ExampleTruncated)
	assert.Len(t, buckets[0].Example, 2000)
}
