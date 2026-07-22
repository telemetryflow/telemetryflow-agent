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

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

var errRDSBoom = errors.New("boom")

// NewRDSPostgresReporter with a nil logger falls back to a no-op logger.
func TestReporter_NilLoggerFallback(t *testing.T) {
	r := postgresql.NewRDSPostgresReporter("", "", "", nil)
	if r == nil {
		t.Fatal("expected reporter")
	}
	if err := r.Submit(context.Background(), nil); err != nil {
		t.Errorf("no-op submit should not error: %v", err)
	}
}

func TestCollectRDSConnectionMetrics_ScanErrorAndRowsErr(t *testing.T) {
	inst := postgresql.NewRDSPGTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "rds"})

	// Scan error: count is a string -> row skipped.
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).AddRow("mydb", "active", "bad"))
	mock.ExpectQuery("max_connections").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(100)))
	metrics, err := postgresql.CollectRDSConnectionMetricsExported(context.Background(), mock, inst, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// max_connections>0 still emits the max metric even with no scanned rows.
	if len(metrics) != 1 {
		t.Errorf("expected only the max metric, got %d", len(metrics))
	}

	// rows.Err path.
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).
			AddRow("mydb", "active", int64(1)).CloseError(errRDSBoom))
	if _, err := postgresql.CollectRDSConnectionMetricsExported(context.Background(), mock2, inst, rdsLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectRDSTransactionMetrics_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"deadlocks", "temp_files", "temp_bytes", "conflicts",
	}
	inst := postgresql.NewRDSPGTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "rds"})

	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			"mydb", "bad", int64(0), int64(0), int64(0), int64(0), int64(0), int64(0),
			int64(0), int64(0), int64(0), int64(0), int64(0), int64(0)))
	metrics, err := postgresql.CollectRDSTransactionMetricsExported(context.Background(), mock, inst, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			"mydb", int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1),
			int64(1), int64(1), int64(1), int64(1), int64(1), int64(1)).CloseError(errRDSBoom))
	if _, err := postgresql.CollectRDSTransactionMetricsExported(context.Background(), mock2, inst, rdsLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectRDSLockMetrics_ScanAndRowsErrBranches(t *testing.T) {
	// a) type scan error -> skipped; mode + total still run.
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"lock_type", "cnt"}).AddRow("relation", "bad"))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("AccessShareLock", int64(1)))
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))
	metrics, err := postgresql.CollectRDSLockMetricsExported(context.Background(), mock, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected by_mode + total = 2 metrics, got %d", len(metrics))
	}

	// b) type rows.Err.
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"lock_type", "cnt"}).AddRow("relation", int64(1)).CloseError(errRDSBoom))
	if _, err := postgresql.CollectRDSLockMetricsExported(context.Background(), mock2, rdsLabels()); err == nil {
		t.Fatal("expected type iterate error")
	}

	// c) mode scan error -> skipped; total still runs.
	mock3 := newMockPool(t)
	mock3.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"lock_type", "cnt"}).AddRow("relation", int64(1)))
	mock3.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("AccessShareLock", "bad"))
	mock3.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(int64(1)))
	metrics3, err := postgresql.CollectRDSLockMetricsExported(context.Background(), mock3, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics3) != 2 {
		t.Errorf("expected by_type + total = 2 metrics, got %d", len(metrics3))
	}

	// d) mode rows.Err.
	mock4 := newMockPool(t)
	mock4.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"lock_type", "cnt"}).AddRow("relation", int64(1)))
	mock4.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("AccessShareLock", int64(1)).CloseError(errRDSBoom))
	if _, err := postgresql.CollectRDSLockMetricsExported(context.Background(), mock4, rdsLabels()); err == nil {
		t.Fatal("expected mode iterate error")
	}
}

func TestCollectRDSDatabaseSizeMetrics_ScanErrorAndRowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).AddRow("db1", "bad"))
	metrics, err := postgresql.CollectRDSDatabaseSizeMetricsExported(context.Background(), mock, rdsLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).AddRow("db1", int64(1)).CloseError(errRDSBoom))
	if _, err := postgresql.CollectRDSDatabaseSizeMetricsExported(context.Background(), mock2, rdsLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectRDSActivityMetrics_AllSubCollectorsFail(t *testing.T) {
	cfg := config.RDSPostgreSQLCollectorConfig{
		Instances:          []config.RDSPostgreSQLInstanceConfig{{Name: "rds", Host: "h"}},
		MaxConnections:     2,
		CollectReplication: true,
	}
	c := postgresql.NewRDSPostgreSQLCollector(cfg, zap.NewNop())
	inst := postgresql.NewRDSPGTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "rds"})
	inst.Version = 140000 // WAL path enabled

	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_activity").WillReturnError(errRDSBoom)  // connection
	mock.ExpectQuery("pg_stat_database").WillReturnError(errRDSBoom)  // transaction
	mock.ExpectQuery("pg_stat_bgwriter").WillReturnError(errRDSBoom)  // bgwriter
	mock.ExpectQuery("pg_stat_wal").WillReturnError(errRDSBoom)       // wal
	mock.ExpectQuery("pg_locks").WillReturnError(errRDSBoom)          // locks (by type)
	mock.ExpectQuery("pg_is_in_recovery").WillReturnError(errRDSBoom) // replication
	mock.ExpectQuery("pg_database_size").WillReturnError(errRDSBoom)  // db size

	metrics := c.CollectRDSActivityMetricsExported(context.Background(), mock, inst)
	if len(metrics) != 0 {
		t.Errorf("expected no metrics when every sub-collector fails, got %d", len(metrics))
	}
}
