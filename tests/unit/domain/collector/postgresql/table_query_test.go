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

var tableStatCols = []string{
	"schemaname", "relname", "seq_scan", "seq_tup_read", "idx_scan", "idx_tup_fetch",
	"n_tup_ins", "n_tup_upd", "n_tup_del", "n_tup_hot_upd", "n_live_tup", "n_dead_tup",
	"n_mod_since_analyze", "last_vacuum", "last_autovacuum", "last_analyze", "last_autoanalyze",
	"vacuum_count", "autovacuum_count", "analyze_count", "autoanalyze_count",
}

func TestCollectTableStatMetrics(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	ts := time.Now().Add(-time.Hour)

	rows := pgxmock.NewRows(tableStatCols).
		AddRow(
			"public", "orders",
			uint64(10), uint64(100), uint64(50), uint64(40),
			uint64(5), uint64(3), uint64(1), uint64(2), uint64(1000), uint64(200),
			uint64(20), &ts, &ts, &ts, &ts,
			uint64(1), uint64(2), uint64(3), uint64(4),
		).
		AddRow(
			"public", "empty",
			uint64(0), uint64(0), uint64(0), uint64(0),
			uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0),
			uint64(0), nil, nil, nil, nil,
			uint64(0), uint64(0), uint64(0), uint64(0),
		)
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).WillReturnRows(rows)

	metrics, err := postgresql.CollectTableStatMetricsExported(context.Background(), mock, inst, testLabels(), 500, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").WithArgs(500).WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectTableStatMetricsExported(context.Background(), mock2, inst, testLabels(), 500, zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectTableIOMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_statio_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{
			"schemaname", "relname", "heap_blks_read", "heap_blks_hit",
			"idx_blks_read", "idx_blks_hit", "toast_blks_read", "toast_blks_hit",
		}).AddRow("public", "orders", uint64(5), uint64(500), uint64(2), uint64(200), uint64(0), uint64(0)))
	metrics, err := postgresql.CollectTableIOMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 6 {
		t.Errorf("expected 6 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_statio_user_tables").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectTableIOMetricsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectIndexMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "idx_scan", "idx_tup_read", "idx_tup_fetch"}).
			AddRow("public", "orders", "orders_pkey", uint64(100), uint64(200), uint64(150)))
	mock.ExpectQuery("pg_statio_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "idx_blks_read", "idx_blks_hit"}).
			AddRow("public", "orders", "orders_pkey", uint64(3), uint64(300)))
	metrics, err := postgresql.CollectIndexMetricsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 5 {
		t.Errorf("expected 5 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_indexes").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectIndexMetricsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}

	mock3 := newMockPool(t)
	mock3.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "idx_scan", "idx_tup_read", "idx_tup_fetch"}).
			AddRow("public", "orders", "orders_pkey", uint64(1), uint64(2), uint64(3)))
	mock3.ExpectQuery("pg_statio_user_indexes").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectIndexMetricsExported(context.Background(), mock3, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error on io query")
	}
}

func TestCollectTableSizeMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "table_size", "index_size", "total_size"}).
			AddRow("public", "orders", uint64(1024), uint64(512), uint64(1536)))
	metrics, err := postgresql.CollectTableSizeMetricsExported(context.Background(), mock, testLabels(), 500, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 3 {
		t.Errorf("expected 3 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").WithArgs(500).WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectTableSizeMetricsExported(context.Background(), mock2, testLabels(), 500, zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectBloatEstimates(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "total_size", "n_dead_tup", "relpages", "reltuples"}).
			AddRow("public", "orders", int64(1000000), float64(1000), int64(100), float64(10000)))
	metrics, err := postgresql.CollectBloatEstimatesExported(context.Background(), mock, testLabels(), 500, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_tables").WithArgs(500).WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectBloatEstimatesExported(context.Background(), mock2, testLabels(), 500, zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectIndexBloatEstimates(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "index_bytes", "idx_reltuples"}).
			AddRow("public", "orders", "orders_idx", int64(10000000), float64(1000)))
	metrics, err := postgresql.CollectIndexBloatEstimatesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_indexes").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectIndexBloatEstimatesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectUnusedIndexes(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "index_bytes"}).
			AddRow("public", "orders", "orders_unused", int64(4096)))
	metrics, err := postgresql.CollectUnusedIndexesExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_user_indexes").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectUnusedIndexesExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectTableStats_Umbrella(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows(tableStatCols).AddRow(
			"public", "orders",
			uint64(1), uint64(1), uint64(1), uint64(1),
			uint64(1), uint64(1), uint64(1), uint64(1), uint64(1), uint64(1),
			uint64(1), nil, nil, nil, nil,
			uint64(1), uint64(1), uint64(1), uint64(1)))
	mock.ExpectQuery("pg_statio_user_tables").
		WillReturnRows(pgxmock.NewRows([]string{
			"schemaname", "relname", "heap_blks_read", "heap_blks_hit",
			"idx_blks_read", "idx_blks_hit", "toast_blks_read", "toast_blks_hit",
		}).AddRow("public", "orders", uint64(1), uint64(1), uint64(1), uint64(1), uint64(1), uint64(1)))
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "idx_scan", "idx_tup_read", "idx_tup_fetch"}).
			AddRow("public", "orders", "idx", uint64(1), uint64(1), uint64(1)))
	mock.ExpectQuery("pg_statio_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "idx_blks_read", "idx_blks_hit"}).
			AddRow("public", "orders", "idx", uint64(1), uint64(1)))
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "table_size", "index_size", "total_size"}).
			AddRow("public", "orders", uint64(1), uint64(1), uint64(1)))
	mock.ExpectQuery("pg_stat_user_tables").WithArgs(500).
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "total_size", "n_dead_tup", "relpages", "reltuples"}).
			AddRow("public", "orders", int64(100), float64(1), int64(1), float64(1)))
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "index_bytes", "idx_reltuples"}).
			AddRow("public", "orders", "idx", int64(1), float64(1)))
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(pgxmock.NewRows([]string{"schemaname", "relname", "indexrelname", "index_bytes"}).
			AddRow("public", "orders", "idx", int64(1)))

	metrics, err := postgresql.CollectTableStatsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}
