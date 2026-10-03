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

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
)

// PostgreSQL version_num constants used across the compatibility tests.
const (
	pg16 = 160000
	pg17 = 170000
	pg18 = 180000
)

// --- Background writer / checkpointer --------------------------------------

// PG16 keeps every checkpoint column in pg_stat_bgwriter.
func TestBgWriter_PG16_UsesBgwriterView(t *testing.T) {
	mock := newMockPool(t)
	cols := []string{
		"checkpoints_timed", "checkpoints_req", "checkpoint_write_time", "checkpoint_sync_time",
		"buffers_checkpoint", "buffers_clean", "buffers_backend", "maxwritten_clean",
		"buffers_backend_fsync", "buffers_alloc",
	}
	mock.ExpectQuery("pg_stat_bgwriter").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			int64(10), int64(2), float64(1.5), float64(0.5),
			int64(100), int64(50), int64(20), int64(3), int64(1), int64(500),
		))
	metrics, err := postgresql.CollectBgWriterMetricsVersionExported(context.Background(), mock, pg16, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 10 {
		t.Errorf("expected 10 metrics, got %d", len(metrics))
	}
}

// PG17+ sources checkpoint stats from pg_stat_checkpointer (joined to
// pg_stat_bgwriter for the retained buffer counters). PG18 behaves the same.
func TestBgWriter_PG17AndPG18_UseCheckpointerView(t *testing.T) {
	for _, ver := range []int{pg17, pg18} {
		mock := newMockPool(t)
		// Output shape is fixed (10 cols) regardless of the underlying views.
		cols := []string{
			"checkpoints_timed", "checkpoints_req", "checkpoint_write_time", "checkpoint_sync_time",
			"buffers_checkpoint", "buffers_clean", "buffers_backend", "maxwritten_clean",
			"buffers_backend_fsync", "buffers_alloc",
		}
		mock.ExpectQuery("pg_stat_checkpointer").
			WillReturnRows(pgxmock.NewRows(cols).AddRow(
				int64(10), int64(2), float64(1.5), float64(0.5),
				int64(100), int64(50), int64(0), int64(3), int64(0), int64(500),
			))
		metrics, err := postgresql.CollectBgWriterMetricsVersionExported(context.Background(), mock, ver, testLabels())
		if err != nil {
			t.Fatalf("pg%d: unexpected error: %v", ver, err)
		}
		if len(metrics) != 10 {
			t.Errorf("pg%d: expected 10 metrics, got %d", ver, len(metrics))
		}
	}
}

// --- WAL -------------------------------------------------------------------

// PG16/PG17 read the write/sync timing columns straight from pg_stat_wal.
func TestWAL_PG16AndPG17_UsePgStatWalColumns(t *testing.T) {
	for _, ver := range []int{pg16, pg17} {
		mock := newMockPool(t)
		cols := []string{
			"wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full",
			"wal_write", "wal_sync", "wal_write_time", "wal_sync_time",
		}
		mock.ExpectQuery("pg_stat_wal").
			WillReturnRows(pgxmock.NewRows(cols).AddRow(
				int64(1000), int64(50), int64(1048576), int64(2),
				int64(200), int64(100), float64(1.2), float64(0.4),
			))
		metrics, err := postgresql.CollectWALMetricsVersionExported(context.Background(), mock, ver, testLabels())
		if err != nil {
			t.Fatalf("pg%d: unexpected error: %v", ver, err)
		}
		if len(metrics) != 8 {
			t.Errorf("pg%d: expected 8 metrics, got %d", ver, len(metrics))
		}
	}
}

// PG18 removed write/sync from pg_stat_wal; the query joins pg_stat_io.
func TestWAL_PG18_JoinsPgStatIO(t *testing.T) {
	mock := newMockPool(t)
	cols := []string{
		"wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full",
		"wal_write", "wal_sync", "wal_write_time", "wal_sync_time",
	}
	// Matches the PG18 query which references pg_stat_io for WAL I/O.
	mock.ExpectQuery("pg_stat_io").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			int64(1000), int64(50), int64(1048576), int64(2),
			int64(200), int64(100), float64(1.2), float64(0.4),
		))
	metrics, err := postgresql.CollectWALMetricsVersionExported(context.Background(), mock, pg18, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 8 {
		t.Errorf("expected 8 metrics, got %d", len(metrics))
	}
}

// --- Vacuum progress -------------------------------------------------------

// PG16 emits the tuple-count dead-tuple metrics (num/max_dead_tuples).
func TestVacuumProgress_PG16_EmitsTupleCounts(t *testing.T) {
	mock := newMockPool(t)
	cols := []string{
		"table_name", "phase", "heap_blks_total", "heap_blks_scanned",
		"heap_blks_vacuumed", "index_vacuum_count", "max_dead_tuples", "num_dead_tuples",
	}
	mock.ExpectQuery("max_dead_tuples").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			"public.orders", "scanning heap", int64(1000), int64(400),
			int64(100), int64(1), int64(5000), int64(1200),
		))
	metrics, err := postgresql.CollectVacuumProgressVersionExported(context.Background(), mock, pg16, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasMetric(metrics, "db.postgresql.vacuum.max_dead_tuples") {
		t.Error("PG16 should emit max_dead_tuples (count)")
	}
	if hasMetric(metrics, "db.postgresql.vacuum.max_dead_tuple_bytes") {
		t.Error("PG16 must not emit the byte-based metric")
	}
}

// PG17+ emits the byte-based budget (max_dead_tuple_bytes) and keeps the
// num_dead_tuples count sourced from num_dead_item_ids.
func TestVacuumProgress_PG17AndPG18_EmitByteBudget(t *testing.T) {
	for _, ver := range []int{pg17, pg18} {
		mock := newMockPool(t)
		cols := []string{
			"table_name", "phase", "heap_blks_total", "heap_blks_scanned",
			"heap_blks_vacuumed", "index_vacuum_count", "max_dead_tuple_bytes", "num_dead_item_ids",
		}
		mock.ExpectQuery("num_dead_item_ids").
			WillReturnRows(pgxmock.NewRows(cols).AddRow(
				"public.orders", "scanning heap", int64(1000), int64(400),
				int64(100), int64(1), int64(2097152), int64(1200),
			))
		metrics, err := postgresql.CollectVacuumProgressVersionExported(context.Background(), mock, ver, testLabels(), zap.NewNop())
		if err != nil {
			t.Fatalf("pg%d: unexpected error: %v", ver, err)
		}
		if !hasMetric(metrics, "db.postgresql.vacuum.max_dead_tuple_bytes") {
			t.Errorf("pg%d should emit max_dead_tuple_bytes", ver)
		}
		if !hasMetric(metrics, "db.postgresql.vacuum.num_dead_tuples") {
			t.Errorf("pg%d should still emit num_dead_tuples (from num_dead_item_ids)", ver)
		}
		if hasMetric(metrics, "db.postgresql.vacuum.max_dead_tuples") {
			t.Errorf("pg%d must not emit the legacy count budget metric", ver)
		}
	}
}

func hasMetric(metrics []collector.Metric, name string) bool {
	for _, m := range metrics {
		if m.Name == name {
			return true
		}
	}
	return false
}
