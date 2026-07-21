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
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// collectInstanceMetrics without the WAL path (version < 14) exercises the
// hasPgStatWal=false branch of the umbrella.
func TestCollectInstanceMetrics_NoWAL(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 120000 // < 14 -> no WAL query expected
	inst.PrevTimestamp = time.Now().Add(-5 * time.Second)

	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"dbname", "state", "cnt"}).AddRow("mydb", "active", int64(1)))
	mock.ExpectQuery("max_connections").
		WillReturnRows(pgxmock.NewRows([]string{"setting"}).AddRow(int64(100)))
	txCols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"temp_files", "temp_bytes",
	}
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(txCols).AddRow(
			"mydb", int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1)))
	bgCols := []string{
		"checkpoints_timed", "checkpoints_req", "checkpoint_write_time", "checkpoint_sync_time",
		"buffers_checkpoint", "buffers_clean", "buffers_backend", "maxwritten_clean",
		"buffers_backend_fsync", "buffers_alloc",
	}
	mock.ExpectQuery("pg_stat_bgwriter").
		WillReturnRows(pgxmock.NewRows(bgCols).AddRow(
			int64(1), int64(2), float64(3), float64(4), int64(5), int64(6), int64(7), int64(8), int64(9), int64(10)))
	mock.ExpectQuery("pg_database_size").
		WillReturnRows(pgxmock.NewRows([]string{"datname", "size"}).AddRow("db1", int64(100)))

	metrics, err := postgresql.CollectInstanceMetricsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
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

// collectReplicationLag with non-nil lag durations exercises the write/flush/replay
// lag emission branches.
func TestCollectReplicationLag_WithDurations(t *testing.T) {
	mock := newMockPool(t)
	wl := 100 * time.Millisecond
	fl := 200 * time.Millisecond
	rl := 300 * time.Millisecond
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows(replLagCols).AddRow(
			int32(9), "repl", "s1", "10.0.0.9", "streaming",
			"0/1", "0/1", "0/1", "0/1", &wl, &fl, &rl))
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows([]string{"application_name", "client_addr", "state", "lag_bytes"}).
			AddRow("s1", "10.0.0.9", "streaming", int64(64)))

	metrics, err := postgresql.CollectReplicationLagExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 3 lag durations + backend pid + 1 lag_bytes = 5
	if len(metrics) < 4 {
		t.Errorf("expected at least 4 metrics, got %d", len(metrics))
	}
}
