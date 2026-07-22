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

// collectTransactionMetrics: elapsed <= 0 clamp (prevTimestamp in the future).
func TestCollectTransactionMetrics_NonPositiveElapsed(t *testing.T) {
	cols := []string{
		"datname", "xact_commit", "xact_rollback", "tup_returned", "tup_fetched",
		"tup_inserted", "tup_updated", "tup_deleted", "blks_hit", "blks_read",
		"temp_files", "temp_bytes",
	}
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.PrevTimestamp = time.Now().Add(time.Hour) // future -> elapsed <= 0
	mock.ExpectQuery("pg_stat_database").
		WillReturnRows(pgxmock.NewRows(cols).AddRow(
			"mydb", int64(1), int64(1), int64(1), int64(1),
			int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1)))
	metrics, err := postgresql.CollectTransactionMetricsExported(context.Background(), mock, inst, testLabels())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}
}

// collectQueryAnalytics: elapsed <= 0 clamp + wait-events failure branch.
func TestCollectQueryAnalytics_NonPositiveElapsedAndWaitEventsError(t *testing.T) {
	mock := newMockPool(t)
	inst := postgresql.NewPGTestInstance(config.PostgreSQLInstanceConfig{Name: "test"})
	inst.Version = 140000
	inst.PrevTimestamp = time.Now().Add(time.Hour) // future -> elapsed <= 0

	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_statements").WithArgs(200).
		WillReturnRows(addStmtRow(pgxmock.NewRows(stmtCols), int64(9), 5, 5, 5))
	// wait events query fails -> logged and skipped (not fatal).
	mock.ExpectQuery("pg_stat_activity").WillReturnError(errBoom)

	metrics, err := postgresql.CollectQueryAnalyticsExported(context.Background(), mock, inst, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// snapshot metrics for the one statement, no wait-event metrics.
	if len(metrics) == 0 {
		t.Fatal("expected snapshot metrics despite wait-event failure")
	}
}

// collectReplicationLag: byte-lag follow-up query fails -> logged, primary metrics kept.
func TestCollectReplicationLag_ByteQueryError(t *testing.T) {
	mock := newMockPool(t)
	mock.ExpectQuery("pg_stat_replication").
		WillReturnRows(pgxmock.NewRows(replLagCols).AddRow(
			int32(1), "repl", "s1", "10.0.0.2", "streaming",
			"0/1", "0/1", "0/1", "0/1", nil, nil, nil))
	mock.ExpectQuery("pg_stat_replication").WillReturnError(errBoom)

	metrics, err := postgresql.CollectReplicationLagExported(context.Background(), mock, testLabels(), zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// backend_pid metric from the primary query survives.
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(metrics))
	}
}
