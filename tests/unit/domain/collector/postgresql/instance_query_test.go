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

func newMockPool(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("new mock pool: %v", err)
	}
	t.Cleanup(mock.Close)
	return mock
}

func testLabels() map[string]string {
	return map[string]string{"postgresql_instance": "test", "postgresql_host": "localhost"}
}

func TestCollectConnectionMetrics_Success(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).
			AddRow("mydb", "active", int64(5)).
			AddRow("mydb", "idle", int64(3)).
			AddRow("", "unknown_state", int64(1)))
	mock.ExpectQuery("max_connections").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(100)))

	metrics, err := postgresql.CollectConnectionMetricsExported(context.Background(), mock, inst, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestCollectConnectionMetrics_QueryError(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	mock.ExpectQuery("pg_stat_activity").WillReturnError(errors.New("boom"))

	if _, err := postgresql.CollectConnectionMetricsExported(context.Background(), mock, inst, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectConnectionMetrics_MaxConnsError(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})

	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).
			AddRow("mydb", "active", int64(2)))
	mock.ExpectQuery("max_connections").WillReturnError(errors.New("denied"))

	metrics, err := postgresql.CollectConnectionMetricsExported(context.Background(), mock, inst, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics even without max_connections")
	}
}

func TestCollectTransactionMetrics_WithRates(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)
	inst.PrevCounters = map[string]uint64{
		"xact_commit:mydb":   uint64(1000),
		"xact_rollback:mydb": uint64(10),
		"tup_returned:mydb":  uint64(0),
		"tup_fetched:mydb":   uint64(0),
		"tup_inserted:mydb":  uint64(0),
		"tup_updated:mydb":   uint64(0),
		"tup_deleted:mydb":   uint64(0),
		"blks_hit:mydb":      uint64(0),
		"blks_read:mydb":     uint64(0),
		"temp_files:mydb":    uint64(0),
		"temp_bytes:mydb":    uint64(0),
	}

	cols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"temp_files", "temp_bytes",
	}
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			"mydb", int64(2000), int64(20), int64(100), int64(50),
			int64(10), int64(5), int64(2), int64(9000), int64(1000),
			int64(1), int64(2048),
		))

	metrics, err := postgresql.CollectTransactionMetricsExported(context.Background(), mock, inst, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestCollectTransactionMetrics_QueryError(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	mock.ExpectQuery("pg_stat_database").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectTransactionMetricsExported(context.Background(), mock, inst, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectBgWriterMetrics(t *testing.T) {
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
	metrics, err := postgresql.CollectBgWriterMetricsExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 10 {
		t.Errorf("expected 10 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_bgwriter").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectBgWriterMetricsExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectWALMetrics(t *testing.T) {
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
	metrics, err := postgresql.CollectWALMetricsExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 8 {
		t.Errorf("expected 8 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_wal").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectWALMetricsExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectDatabaseSizeMetrics(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).
			AddRow("db1", int64(1024)).
			AddRow("db2", int64(2048)))
	metrics, err := postgresql.CollectDatabaseSizeMetricsExported(context.Background(), mock, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_database_size").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectDatabaseSizeMetricsExported(context.Background(), mock2, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectInstanceMetrics_Umbrella(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 140000 // triggers WAL path
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)

	// connection metrics
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).AddRow("mydb", "active", int64(3)))
	mock.ExpectQuery("max_connections").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(100)))
	// transaction metrics
	txCols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"temp_files", "temp_bytes",
	}
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(txCols).AddRow(
			"mydb", int64(10), int64(1), int64(2), int64(3),
			int64(4), int64(5), int64(6), int64(7), int64(8), int64(9), int64(10)))
	// bgwriter
	bgCols := []string{
		"checkpoints_timed", "checkpoints_req", "checkpoint_write_time", "checkpoint_sync_time",
		"buffers_checkpoint", "buffers_clean", "buffers_backend", "maxwritten_clean",
		"buffers_backend_fsync", "buffers_alloc",
	}
	mock.ExpectQuery("pg_stat_bgwriter").
		WillReturnRows(pgxmock.NewRows(bgCols).AddRow(
			int64(1), int64(2), float64(3), float64(4), int64(5), int64(6), int64(7), int64(8), int64(9), int64(10)))
	// wal
	walCols := []string{
		"wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full",
		"wal_write", "wal_sync", "wal_write_time", "wal_sync_time",
	}
	mock.ExpectQuery("pg_stat_wal").
		WillReturnRows(pgxmock.NewRows(walCols).AddRow(
			int64(1), int64(2), int64(3), int64(4), int64(5), int64(6), float64(7), float64(8)))
	// database sizes
	mock.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).AddRow("db1", int64(100)))

	metrics, err := postgresql.CollectInstanceMetricsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}
