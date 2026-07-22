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

var stmtCols = []string{
	"queryid", "query", "calls", "total_exec_time", "mean_exec_time", "min_exec_time", "max_exec_time",
	"rows", "shared_blks_hit", "shared_blks_read", "shared_blks_dirtied", "shared_blks_written",
	"temp_blks_read", "temp_blks_written", "blk_read_time", "blk_write_time",
}

func addStmtRow(rows *pgxmock.Rows, qid int64, calls, totalTime, rowsRet float64) *pgxmock.Rows {
	return rows.AddRow(
		qid, "SELECT * FROM t WHERE id = 1", uint64(calls), totalTime, float64(2), float64(1), float64(5),
		uint64(rowsRet), uint64(10), uint64(2), uint64(0), uint64(0),
		uint64(0), uint64(0), float64(0), float64(0),
	)
}

func TestCollectWaitEvents(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"wait_event_type", "wait_event", "count"}).
			AddRow("Lock", "relation", uint64(3)).
			AddRow("IO", "DataFileRead", uint64(1)))
	metrics, err := postgresql.CollectWaitEventsExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}

	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_stat_activity").WillReturnError(errors.New("boom"))
	if _, err := postgresql.CollectWaitEventsExported(context.Background(), mock2, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectQueryAnalytics_ExtNotInstalled(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 140000

	// pg_extension EXISTS check -> false, falls back to wait events.
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

func TestCollectQueryAnalytics_WithStatements(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 140000 // useExecCols true
	inst.PrevTimestamp = time.Now().Add(-10 * time.Second)
	// Seed prev counters so rate path is exercised.
	inst.PrevCounters = map[string]uint64{
		"query:42:calls":           uint64(100),
		"query:42:total_exec_time": uint64(1000),
		"query:42:rows":            uint64(500),
	}

	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_statements").WithArgs(200).
		WillReturnRows(addStmtRow(pgxmock.NewRows(stmtCols), int64(42), 300, 4000, 2000))
	// wait events after statements
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"wait_event_type", "wait_event", "count"}).
			AddRow("Lock", "relation", uint64(2)))

	metrics, err := postgresql.CollectQueryAnalyticsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}

func TestCollectQueryAnalytics_StatementsQueryError(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 130000

	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_statements").WillReturnError(errors.New("boom"))

	if _, err := postgresql.CollectQueryAnalyticsExported(context.Background(), mock, inst, testLabels(), zap.NewNop()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectQueryAnalytics_LegacyColumns(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 120000 // useExecCols false -> legacy total_time columns
	inst.PrevTimestamp = time.Now().Add(-5 * time.Second)

	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_statements").WithArgs(200).
		WillReturnRows(addStmtRow(pgxmock.NewRows(stmtCols), int64(7), 10, 20, 30))
	mock.ExpectQuery("pg_stat_activity").
		WillReturnRows(pgxmock.NewRows([]string{"wait_event_type", "wait_event", "count"}).
			AddRow("Client", "ClientRead", uint64(1)))

	metrics, err := postgresql.CollectQueryAnalyticsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}
