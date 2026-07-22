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
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// errBoom is a reusable sentinel error for iteration-failure branches.
var errBoom = errors.New("boom")

// ---------------------------------------------------------------------------
// instance_metrics.go — scan-error + rows.Err branches
// ---------------------------------------------------------------------------

func TestCollectConnectionMetrics_ScanErrorSkipsRow(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	// Third column (count) is a string where int64 is expected -> scan fails, row skipped.
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).
			AddRow("mydb", "active", "not-an-int"))
	mock.ExpectQuery("max_connections").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(100)))

	metrics, err := postgresql.CollectConnectionMetricsExported(context.Background(), mock, inst, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics when the only row fails to scan, got %d", len(metrics))
	}
}

func TestCollectConnectionMetrics_RowsErr(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	rows := pgxmock.NewRows([]string{"dbname", "state", "cnt"}).
		AddRow("mydb", "active", int64(1)).CloseError(errBoom)
	mock.ExpectQuery("pg_stat_activity").WillReturnRows(rows)

	if _, err := postgresql.CollectConnectionMetricsExported(context.Background(), mock, inst, testLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectTransactionMetrics_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"temp_files", "temp_bytes",
	}

	// Scan error: xact_commit is a string.
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			"mydb", "bad", int64(0), int64(0), int64(0),
			int64(0), int64(0), int64(0), int64(0), int64(0), int64(0), int64(0)))
	metrics, err := postgresql.CollectTransactionMetricsExported(context.Background(), mock, inst, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	// rows.Err path.
	mock2 := newMockPool(t)
	rows := pgxmock.NewRows(cols).AddRow(
		"mydb", int64(1), int64(1), int64(1), int64(1),
		int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1)).CloseError(errBoom)
	mock2.ExpectQuery("pg_stat_database").WillReturnRows(rows)
	if _, err := postgresql.CollectTransactionMetricsExported(context.Background(), mock2, inst, testLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectDatabaseSizeMetrics_ScanErrorAndRowsErr(t *testing.T) {
	// Scan error: size is a string.
	mock := newMockPool(t)
	mock.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).AddRow("db1", "bad"))
	metrics, err := postgresql.CollectDatabaseSizeMetricsExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	// rows.Err path.
	mock2 := newMockPool(t)
	rows := pgxmock.NewRows([]string{"datname", "size"}).AddRow("db1", int64(1)).CloseError(errBoom)
	mock2.ExpectQuery("pg_database_size").WillReturnRows(rows)
	if _, err := postgresql.CollectDatabaseSizeMetricsExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectInstanceMetrics_AllSubCollectorsFail(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 140000 // enables WAL path

	mock.ExpectQuery("pg_stat_activity").WillReturnError(errBoom)
	mock.ExpectQuery("pg_stat_database").WillReturnError(errBoom)
	mock.ExpectQuery("pg_stat_bgwriter").WillReturnError(errBoom)
	mock.ExpectQuery("pg_stat_wal").WillReturnError(errBoom)
	mock.ExpectQuery("pg_database_size").WillReturnError(errBoom)

	metrics, err := postgresql.CollectInstanceMetricsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("umbrella should swallow sub-collector errors, got %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics when every sub-collector fails, got %d", len(metrics))
	}
}

// ---------------------------------------------------------------------------
// lock_metrics.go — scan-error + rows.Err branches
// ---------------------------------------------------------------------------

func TestCollectLocksByType_ScanErrorAndRowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"locktype", "cnt"}).AddRow("relation", "bad"))
	metrics, err := postgresql.CollectLocksByTypeExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	rows := pgxmock.NewRows([]string{"locktype", "cnt"}).AddRow("relation", int64(1)).CloseError(errBoom)
	mock2.ExpectQuery("pg_locks").WillReturnRows(rows)
	if _, err := postgresql.CollectLocksByTypeExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectLocksByMode_ScanErrorAndRowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").
		WillReturnRows(pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("AccessShareLock", "bad"))
	metrics, err := postgresql.CollectLocksByModeExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	rows := pgxmock.NewRows([]string{"mode", "cnt"}).AddRow("AccessShareLock", int64(1)).CloseError(errBoom)
	mock2.ExpectQuery("pg_locks").WillReturnRows(rows)
	if _, err := postgresql.CollectLocksByModeExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectLockMetrics_AllSubCollectorsFail(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_locks").WillReturnError(errBoom) // by type
	mock.ExpectQuery("pg_locks").WillReturnError(errBoom) // by mode
	mock.ExpectQuery("pg_locks").WillReturnError(errBoom) // blocked (QueryRow)
	metrics, err := postgresql.CollectLockMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("umbrella should swallow errors, got %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

// ---------------------------------------------------------------------------
// query_metrics.go — scan-error, rows.Err, and version-detect fallback
// ---------------------------------------------------------------------------

func TestCollectWaitEvents_ScanErrorAndRowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"wait_event_type", "wait_event", "count"}).
			AddRow("Lock", "relation", "bad"))
	metrics, err := postgresql.CollectWaitEventsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	rows := pgxmock.NewRows([]string{"wait_event_type", "wait_event", "count"}).
		AddRow("Lock", "relation", uint64(1)).CloseError(errBoom)
	mock2.ExpectQuery("pg_stat_activity").WillReturnRows(rows)
	if _, err := postgresql.CollectWaitEventsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectQueryAnalytics_ScanErrorAndRowsErr(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 140000

	// Scan error on the statements row -> skipped, then wait events succeed.
	mock := newMockPool(t)
	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	badRow := pgxmock.NewRows(stmtCols).AddRow(
		"not-an-int", "SELECT 1", uint64(1), float64(1), float64(1), float64(1), float64(1),
		uint64(1), uint64(1), uint64(1), uint64(1), uint64(1),
		uint64(1), uint64(1), float64(1), float64(1))
	mock.ExpectQuery("pg_stat_statements").WithArgs(200).WillReturnRows(badRow)
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"wait_event_type", "wait_event", "count"}).
			AddRow("Lock", "relation", uint64(1)))
	metrics, err := postgresql.CollectQueryAnalyticsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected only the wait-event metric, got %d", len(metrics))
	}

	// rows.Err on the statements query.
	mock2 := newMockPool(t)
	inst2 := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst2.Version = 140000
	mock2.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	errRow := addStmtRow(pgxmock.NewRows(stmtCols), int64(1), 1, 1, 1).CloseError(errBoom)
	mock2.ExpectQuery("pg_stat_statements").WithArgs(200).WillReturnRows(errRow)
	if _, err := postgresql.CollectQueryAnalyticsExported(context.Background(), mock2, inst2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectQueryAnalytics_VersionDetectFallback(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	// Version 0 forces the in-function detectVersion call; make it fail (logged, not fatal).
	mock.ExpectQuery("server_version_num").WillReturnError(errBoom)
	// Extension check then reports not installed -> wait events fallback.
	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"wait_event_type", "wait_event", "count"}).
			AddRow("Lock", "relation", uint64(1)))

	metrics, err := postgresql.CollectQueryAnalyticsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 wait-event metric, got %d", len(metrics))
	}
}

// ---------------------------------------------------------------------------
// replication_metrics.go — non-nil lag durations, scan-error, rows.Err
// ---------------------------------------------------------------------------

func TestCollectReplicationLag_WithDurationsAndScanError(t *testing.T) {
	mock := newMockPool(t)
	wl := 2 * time.Second
	fl := 3 * time.Second
	rl := 4 * time.Second
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows(replLagCols).AddRow(
			int32(1), "repl", "s1", "10.0.0.2", "streaming",
			"0/1", "0/1", "0/1", "0/1",
			&wl, &fl, &rl))
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
			AddRow("s1", "10.0.0.2", "streaming", int64(10)))
	metrics, err := postgresql.CollectReplicationLagExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// write/flush/replay lag + backend_pid + lag_bytes = 5
	if len(metrics) != 5 {
		t.Errorf("expected 5 metrics with all lag durations set, got %d", len(metrics))
	}

	// Scan error on the primary lag query -> row skipped, byte query still runs.
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows(replLagCols).AddRow(
			"bad-pid", "repl", "s1", "10.0.0.2", "streaming",
			"0/1", "0/1", "0/1", "0/1", nil, nil, nil))
	mock2.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
			AddRow("s1", "10.0.0.2", "streaming", int64(10)))
	metrics2, err := postgresql.CollectReplicationLagExported(context.Background(), mock2, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics2) != 1 {
		t.Errorf("expected only the lag_bytes metric after scan skip, got %d", len(metrics2))
	}
}

func TestCollectReplicationLag_RowsErr(t *testing.T) {
	mock := newMockPool(t)
	rows := pgxmock.NewRows(replLagCols).AddRow(
		int32(1), "repl", "s1", "10.0.0.2", "streaming",
		"0/1", "0/1", "0/1", "0/1", nil, nil, nil).CloseError(errBoom)
	mock.ExpectQuery("pg_stat_replication").WillReturnRows(rows)
	if _, err := postgresql.CollectReplicationLagExported(context.Background(), mock, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectReplicationLagBytes_ScanErrorAndRowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
			AddRow("s1", "10.0.0.2", "streaming", "bad"))
	metrics, err := postgresql.CollectReplicationLagBytesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	rows := pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
		AddRow("s1", "10.0.0.2", "streaming", int64(1)).CloseError(errBoom)
	mock2.ExpectQuery("pg_stat_replication").WillReturnRows(rows)
	if _, err := postgresql.CollectReplicationLagBytesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectReplicationSlots_ScanErrorAndRowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_replication_slots").
		WillReturnRows(pgxmock.NewRows([]string{"slot_name", "slot_type", "active", "retained_bytes"}).
			AddRow("slot1", "physical", true, "bad"))
	metrics, err := postgresql.CollectReplicationSlotsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	rows := pgxmock.NewRows([]string{"slot_name", "slot_type", "active", "retained_bytes"}).
		AddRow("slot1", "physical", true, int64(1)).CloseError(errBoom)
	mock2.ExpectQuery("pg_replication_slots").WillReturnRows(rows)
	if _, err := postgresql.CollectReplicationSlotsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectReplicationMetrics_AllSubCollectorsFail(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_is_in_recovery").
		WillReturnRows(pgxmock.NewRows([]string{"r"}).AddRow(false))
	mock.ExpectQuery("pg_stat_replication").WillReturnError(errBoom)  // lag
	mock.ExpectQuery("pg_replication_slots").WillReturnError(errBoom) // slots
	metrics, err := postgresql.CollectReplicationMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("umbrella should swallow sub errors, got %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}
