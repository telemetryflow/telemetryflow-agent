// Package rds_postgresql_test contains unit tests for the RDS PostgreSQL collector module.
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

package rds_postgresql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func newMockPool(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("new mock pool: %v", err)
	}
	t.Cleanup(mock.Close)
	return mock
}

func rdsLabels() map[string]string {
	return map[string]string{"postgresql_instance": "rds-test", "cloud_provider": "aws"}
}

func TestDetectRDSVersion(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewRDSPGTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "rds"})
	mock.ExpectQuery("version").
		WillReturnRows(pgxmock.NewRows([]string{"version"}).
			AddRow("PostgreSQL 14.9 on x86_64-pc-linux-gnu (rds)"))
	ver, verStr, err := postgresql.DetectRDSVersionExported(context.Background(), mock, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != 140900 {
		t.Errorf("version = %d, want 140900", ver)
	}
	if verStr == "" {
		t.Error("expected version string")
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("version").WillReturnError(errors.New("boom"))
	if _, _, err := postgresql.DetectRDSVersionExported(context.Background(), mock2, inst); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectRDSConnectionMetrics(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewRDSPGTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "rds"})
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).
			AddRow("mydb", "active", int64(4)).
			AddRow("", "idle", int64(2)))
	mock.ExpectQuery("max_connections").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(200)))
	metrics, err := postgresql.CollectRDSConnectionMetricsExported(context.Background(), mock, inst, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_activity").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectRDSConnectionMetricsExported(context.Background(), mock2, inst, rdsLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectRDSTransactionMetrics(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewRDSPGTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "rds"})
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)
	inst.PrevCounters = map[string]uint64{
		"rds_xact_commit:mydb":   uint64(1000),
		"rds_xact_rollback:mydb": uint64(0),
		"rds_deadlocks:mydb":     uint64(0),
		"rds_tup_returned:mydb":  uint64(0),
		"rds_tup_fetched:mydb":   uint64(0),
		"rds_blks_hit:mydb":      uint64(0),
		"rds_blks_read:mydb":     uint64(0),
	}
	cols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"deadlocks", "temp_files", "temp_bytes", "conflicts",
	}
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			"mydb", int64(2000), int64(5), int64(100), int64(50),
			int64(10), int64(5), int64(2), int64(9000), int64(1000),
			int64(1), int64(1), int64(2048), int64(0),
		))
	metrics, err := postgresql.CollectRDSTransactionMetricsExported(context.Background(), mock, inst, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_database").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectRDSTransactionMetricsExported(context.Background(), mock2, inst, rdsLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectRDSBgWriterMetrics(t *testing.T) {
	mock := newMockPool(t)
	cols := []string{
		"checkpoints_timed", "checkpoints_req", "checkpoint_write_time", "checkpoint_sync_time",
		"buffers_checkpoint", "buffers_clean", "buffers_backend", "maxwritten_clean",
		"buffers_backend_fsync", "buffers_alloc",
	}
	mock.ExpectQuery("pg_stat_bgwriter").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			int64(1), int64(2), float64(3), float64(4), int64(5), int64(6), int64(7), int64(8), int64(9), int64(10)))
	metrics, err := postgresql.CollectRDSBgWriterMetricsExported(context.Background(), mock, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 10 {
		t.Errorf("expected 10 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_bgwriter").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectRDSBgWriterMetricsExported(context.Background(), mock2, rdsLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectRDSWALMetrics(t *testing.T) {
	mock := newMockPool(t)
	cols := []string{
		"wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full",
		"wal_write", "wal_sync", "wal_write_time", "wal_sync_time",
	}
	mock.ExpectQuery("pg_stat_wal").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			int64(1), int64(2), int64(3), int64(4), int64(5), int64(6), float64(7), float64(8)))
	metrics, err := postgresql.CollectRDSWALMetricsExported(context.Background(), mock, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 8 {
		t.Errorf("expected 8 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_wal").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectRDSWALMetricsExported(context.Background(), mock2, rdsLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectRDSLockMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"lock_type", "cnt"}).AddRow("relation", int64(5)))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("AccessShareLock", int64(3)))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(8)))
	metrics, err := postgresql.CollectRDSLockMetricsExported(context.Background(), mock, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 3 {
		t.Errorf("expected 3 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_locks").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectRDSLockMetricsExported(context.Background(), mock2, rdsLabels()); err == nil {
		t.Fatal("expected error on type query")
	}

	mock3 := newMockPool(t)
	mock3.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"lock_type", "cnt"}).AddRow("relation", int64(1)))
	mock3.ExpectQuery("pg_locks").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectRDSLockMetricsExported(context.Background(), mock3, rdsLabels()); err == nil {
		t.Fatal("expected error on mode query")
	}
}

func TestCollectRDSDatabaseSizeMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).
			AddRow("db1", int64(1024)))
	metrics, err := postgresql.CollectRDSDatabaseSizeMetricsExported(context.Background(), mock, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_database_size").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectRDSDatabaseSizeMetricsExported(context.Background(), mock2, rdsLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectRDSActivityMetrics_Umbrella(t *testing.T) {
	cfg := config.RDSPostgreSQLCollectorConfig{
		Instances:      []config.RDSPostgreSQLInstanceConfig{{Name: "rds", Host: "h"}},
		MaxConnections: 2,
	}
	c := postgresql.NewRDSPostgreSQLCollector(cfg, zap.NewNop())
	inst := postgresql.NewRDSPGTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "rds"})
	inst.Version = 140000 // WAL path enabled
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)

	mock := newMockPool(t)
	// connection metrics
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).AddRow("mydb", "active", int64(2)))
	mock.ExpectQuery("max_connections").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(100)))
	// transaction metrics
	txCols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"deadlocks", "temp_files", "temp_bytes", "conflicts",
	}
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(txCols).AddRow(
			"mydb", int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1),
			int64(1), int64(1), int64(1), int64(1), int64(1), int64(1)))
	// bgwriter
	bgCols := []string{
		"checkpoints_timed", "checkpoints_req", "checkpoint_write_time", "checkpoint_sync_time",
		"buffers_checkpoint", "buffers_clean", "buffers_backend", "maxwritten_clean",
		"buffers_backend_fsync", "buffers_alloc",
	}
	mock.ExpectQuery("pg_stat_bgwriter").
		WillReturnRows(pgxmock.NewRows(bgCols).AddRow(
			int64(1), int64(2), float64(3), float64(4), int64(5), int64(6), int64(7), int64(8), int64(9), int64(10)))
	// wal (version 14)
	walCols := []string{
		"wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full",
		"wal_write", "wal_sync", "wal_write_time", "wal_sync_time",
	}
	mock.ExpectQuery("pg_stat_wal").
		WillReturnRows(pgxmock.NewRows(walCols).AddRow(
			int64(1), int64(2), int64(3), int64(4), int64(5), int64(6), float64(7), float64(8)))
	// locks: by type, by mode, total
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"lock_type", "cnt"}).AddRow("relation", int64(1)))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("AccessShareLock", int64(1)))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(2)))
	// database sizes (replication disabled by default cfg)
	mock.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).AddRow("db1", int64(100)))

	metrics := c.CollectRDSActivityMetricsExported(context.Background(), mock, inst)
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}

func TestCollectRDSReplicationMetrics_Standby(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_is_in_recovery").
		WillReturnRows(pgxmock.NewRows([]string{"r"}).AddRow(true))
	metrics, err := postgresql.CollectRDSReplicationMetricsExported(context.Background(), mock, rdsLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics != nil {
		t.Errorf("expected nil metrics on standby, got %d", len(metrics))
	}
}
