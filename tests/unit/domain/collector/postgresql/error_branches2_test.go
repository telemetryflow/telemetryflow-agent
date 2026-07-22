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
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ---------------------------------------------------------------------------
// vacuum_metrics.go — scan-error + rows.Err branches
// ---------------------------------------------------------------------------

func TestCollectVacuumProgress_ScanErrorAndRowsErr(t *testing.T) {
	progCols := []string{
		"table_name", "phase", "heap_blks_total", "heap_blks_scanned",
		"heap_blks_vacuumed", "index_vacuum_count", "max_dead_tuples", "num_dead_tuples",
	}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_progress_vacuum").
		WillReturnRows(pgxmock.NewRows(progCols).
			AddRow("public.t", "scanning heap", "bad", int64(1), int64(1), int64(1), int64(1), int64(1)))
	metrics, err := postgresql.CollectVacuumProgressExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_progress_vacuum").
		WillReturnRows(pgxmock.NewRows(progCols).
			AddRow("public.t", "scanning heap", int64(1), int64(1), int64(1), int64(1), int64(1), int64(1)).
			CloseError(errBoom))
	if _, err := postgresql.CollectVacuumProgressExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectXIDAge_ScanErrorAndRowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "xid_age", "freeze_max"}).
			AddRow("mydb", "bad", int64(1)))
	metrics, err := postgresql.CollectXIDAgeExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_database").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "xid_age", "freeze_max"}).
			AddRow("mydb", int64(1), int64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectXIDAgeExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectDeadTuples_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"schemaname", "relname", "n_dead_tup", "n_live_tup"}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "bad", int64(1)))
	metrics, err := postgresql.CollectDeadTuplesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", int64(1), int64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectDeadTuplesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectVacuumConfig_RowsErr(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_settings").
		WillReturnRows(pgxmock.NewRows([]string{"name", "setting"}).
			AddRow("autovacuum", "on").CloseError(errBoom))
	if _, err := postgresql.CollectVacuumConfigExported(context.Background(), mock, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectTableXIDAge_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"schemaname", "relname", "xid_age"}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_class").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "bad"))
	metrics, err := postgresql.CollectTableXIDAgeExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_class").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", int64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectTableXIDAgeExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectVacuumNeeded_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"schemaname", "relname", "n_dead_tup", "n_live_tup"}
	mock := newMockPool(t)
	mock.ExpectQuery("autovacuum_vacuum_threshold").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(50)))
	mock.ExpectQuery("autovacuum_vacuum_scale_factor").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(float64(0.2)))
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "bad", int64(1)))
	metrics, err := postgresql.CollectVacuumNeededExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("autovacuum_vacuum_threshold").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(50)))
	mock2.ExpectQuery("autovacuum_vacuum_scale_factor").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(float64(0.2)))
	mock2.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", int64(1), int64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectVacuumNeededExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectSubscriptionMetrics_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"subname", "lsn", "lag_interval"}
	mock := newMockPool(t)
	mock.ExpectQuery("information_schema.views").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_subscription").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("sub1", "0/1", "bad"))
	metrics, err := postgresql.CollectSubscriptionMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("information_schema.views").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock2.ExpectQuery("pg_stat_subscription").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("sub1", "0/1", float64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectSubscriptionMetricsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectVacuumMetrics_AllSubCollectorsFail(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	mock.ExpectQuery("pg_stat_activity").WillReturnError(errBoom)        // workers
	mock.ExpectQuery("pg_stat_progress_vacuum").WillReturnError(errBoom) // progress
	mock.ExpectQuery("pg_database").WillReturnError(errBoom)             // xid age
	mock.ExpectQuery("pg_stat_user_tables").WillReturnError(errBoom)     // dead tuples
	mock.ExpectQuery("pg_settings").WillReturnError(errBoom)             // config
	mock.ExpectQuery("pg_class").WillReturnError(errBoom)                // table xid age
	// vacuum needed: two settings (fall back to defaults) then tables query errors
	mock.ExpectQuery("autovacuum_vacuum_threshold").WillReturnError(errBoom)
	mock.ExpectQuery("autovacuum_vacuum_scale_factor").WillReturnError(errBoom)
	mock.ExpectQuery("pg_stat_user_tables").WillReturnError(errBoom)
	// dead tuple rate
	mock.ExpectQuery("pg_stat_user_tables").WillReturnError(errBoom)
	// subscription view check errors -> nil
	mock.ExpectQuery("information_schema.views").WillReturnError(errBoom)

	metrics, err := postgresql.CollectVacuumMetricsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("umbrella should swallow sub errors, got %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}

// ---------------------------------------------------------------------------
// table_metrics.go — scan-error + rows.Err branches
// ---------------------------------------------------------------------------

func TestCollectTableStatMetrics_ScanErrorAndRowsErr(t *testing.T) {
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	badVals := []any{
		"public", "orders",
		"bad", uint64(0), uint64(0), uint64(0),
		uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0),
		uint64(0), nil, nil, nil, nil,
		uint64(0), uint64(0), uint64(0), uint64(0),
	}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows(tableStatCols).AddRow(badVals...))
	metrics, err := postgresql.CollectTableStatMetricsExported(context.Background(), mock, inst, testLabels(), 500, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	goodVals := []any{
		"public", "orders",
		uint64(1), uint64(1), uint64(1), uint64(1),
		uint64(1), uint64(1), uint64(1), uint64(1), uint64(1), uint64(1),
		uint64(1), nil, nil, nil, nil,
		uint64(1), uint64(1), uint64(1), uint64(1),
	}
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows(tableStatCols).AddRow(goodVals...).CloseError(errBoom))
	if _, err := postgresql.CollectTableStatMetricsExported(context.Background(), mock2, inst, testLabels(), 500, zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectTableIOMetrics_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{
		"schemaname", "relname", "heap_blks_read", "heap_blks_hit",
		"idx_blks_read", "idx_blks_hit", "toast_blks_read", "toast_blks_hit",
	}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_statio_user_tables").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "bad", uint64(1), uint64(1), uint64(1), uint64(1), uint64(1)))
	metrics, err := postgresql.CollectTableIOMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_statio_user_tables").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", uint64(1), uint64(1), uint64(1), uint64(1), uint64(1), uint64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectTableIOMetricsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectIndexMetrics_ScanAndRowsErrBranches(t *testing.T) {
	statCols := []string{"schemaname", "relname", "indexrelname", "idx_scan", "idx_tup_read", "idx_tup_fetch"}
	ioCols := []string{"schemaname", "relname", "indexrelname", "idx_blks_read", "idx_blks_hit"}

	// a) stat scan error -> row skipped; io query still runs (empty).
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(statCols).AddRow("public", "orders", "idx", "bad", uint64(1), uint64(1)))
	mock.ExpectQuery("pg_statio_user_indexes").
		WillReturnRows(pgxmock.NewRows(ioCols))
	metrics, err := postgresql.CollectIndexMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	// b) stat rows.Err.
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(statCols).AddRow("public", "orders", "idx", uint64(1), uint64(1), uint64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectIndexMetricsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected stat iterate error")
	}

	// c) io scan error -> io row skipped; merge emits stat-only metrics.
	mock3 := newMockPool(t)
	mock3.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(statCols).AddRow("public", "orders", "idx", uint64(1), uint64(1), uint64(1)))
	mock3.ExpectQuery("pg_statio_user_indexes").
		WillReturnRows(pgxmock.NewRows(ioCols).AddRow("public", "orders", "idx", "bad", uint64(1)))
	metrics3, err := postgresql.CollectIndexMetricsExported(context.Background(), mock3, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics3) != 3 {
		t.Errorf("expected 3 stat-only metrics, got %d", len(metrics3))
	}

	// d) io rows.Err.
	mock4 := newMockPool(t)
	mock4.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(statCols).AddRow("public", "orders", "idx", uint64(1), uint64(1), uint64(1)))
	mock4.ExpectQuery("pg_statio_user_indexes").
		WillReturnRows(pgxmock.NewRows(ioCols).AddRow("public", "orders", "idx", uint64(1), uint64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectIndexMetricsExported(context.Background(), mock4, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected io iterate error")
	}
}

func TestCollectTableSizeMetrics_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"schemaname", "relname", "table_size", "index_size", "total_size"}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "bad", uint64(1), uint64(1)))
	metrics, err := postgresql.CollectTableSizeMetricsExported(context.Background(), mock, testLabels(), 500, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", uint64(1), uint64(1), uint64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectTableSizeMetricsExported(context.Background(), mock2, testLabels(), 500, zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectBloatEstimates_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"schemaname", "relname", "total_size", "n_dead_tup", "relpages", "reltuples"}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "bad", float64(1), int64(1), float64(1)))
	metrics, err := postgresql.CollectBloatEstimatesExported(context.Background(), mock, testLabels(), 500, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", int64(1), float64(1), int64(1), float64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectBloatEstimatesExported(context.Background(), mock2, testLabels(), 500, zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectIndexBloatEstimates_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"schemaname", "relname", "indexrelname", "index_bytes", "idx_reltuples"}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "idx", "bad", float64(1)))
	metrics, err := postgresql.CollectIndexBloatEstimatesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "idx", int64(1), float64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectIndexBloatEstimatesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectUnusedIndexes_ScanErrorAndRowsErr(t *testing.T) {
	cols := []string{"schemaname", "relname", "indexrelname", "index_bytes"}
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "idx", "bad"))
	metrics, err := postgresql.CollectUnusedIndexesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows(cols).AddRow("public", "orders", "idx", int64(1)).CloseError(errBoom))
	if _, err := postgresql.CollectUnusedIndexesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected iterate error")
	}
}

func TestCollectTableStats_AllSubCollectorsFail(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).WillReturnError(errBoom) // table stat
	mock.ExpectQuery("pg_statio_user_tables").WillReturnError(errBoom)             // table io
	mock.ExpectQuery("pg_stat_user_indexes").WillReturnError(errBoom)              // index metrics
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).WillReturnError(errBoom) // table size
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).WillReturnError(errBoom) // bloat
	mock.ExpectQuery("pg_stat_user_indexes").WillReturnError(errBoom)              // index bloat
	mock.ExpectQuery("pg_stat_user_indexes").WillReturnError(errBoom)              // unused indexes

	metrics, err := postgresql.CollectTableStatsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("umbrella should swallow sub errors, got %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics, got %d", len(metrics))
	}
}
