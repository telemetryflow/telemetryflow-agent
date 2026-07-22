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

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

var qanStmtCols = []string{
	"queryid", "query", "calls", "total_exec_time", "min_exec_time", "max_exec_time",
	"rows", "shared_blks_hit", "shared_blks_read", "shared_blks_dirtied", "shared_blks_written",
	"temp_blks_read", "temp_blks_written", "blk_read_time", "blk_write_time",
}

func addQANRow(rows *pgxmock.Rows, qid int64, calls uint64, totalTime float64) *pgxmock.Rows {
	return rows.AddRow(
		qid, "SELECT * FROM users WHERE id = 5", calls, totalTime, float64(1), float64(9),
		uint64(1000), uint64(50), uint64(5), uint64(1), uint64(0),
		uint64(0), uint64(0), float64(0.5), float64(0.2),
	)
}

func newQANBucketCollector() *postgresql.QANPostgreSQLCollector {
	cfg := postgresql.QANConfig{
		Instances:       []config.PostgreSQLInstanceConfig{{Name: "qan", Host: "localhost", DBName: "app", User: "mon"}},
		TopQueriesLimit: 200,
	}
	return postgresql.NewQANPostgreSQLCollector(cfg, zap.NewNop())
}

func TestQANCollectBuckets_ExtNotInstalled(t *testing.T) {
	c := newQANBucketCollector()
	mock := newMockPool(t)
	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
	n, err := c.CollectQANBucketsExported(context.Background(), mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 buckets, got %d", n)
	}
}

func TestQANCollectBuckets_QueryError(t *testing.T) {
	c := newQANBucketCollector()
	mock := newMockPool(t)
	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("pg_stat_statements").WithArgs(600).WillReturnError(errors.New("boom"))
	if _, err := c.CollectQANBucketsExported(context.Background(), mock); err == nil {
		t.Fatal("expected error")
	}
}

func TestQANCollectBuckets_FirstCycleThenDeltas(t *testing.T) {
	c := newQANBucketCollector()

	// First cycle: seeds the previous snapshot, produces no buckets.
	mock1 := newMockPool(t)
	mock1.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock1.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addQANRow(pgxmock.NewRows(qanStmtCols), int64(1), uint64(100), float64(1000)))
	n1, err := c.CollectQANBucketsExported(context.Background(), mock1)
	if err != nil {
		t.Fatalf("first cycle error: %v", err)
	}
	if n1 != 0 {
		t.Errorf("expected 0 buckets on first cycle, got %d", n1)
	}

	// Second cycle: higher counters yield a positive delta -> one bucket.
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock2.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addQANRow(pgxmock.NewRows(qanStmtCols), int64(1), uint64(250), float64(4000)))
	n2, err := c.CollectQANBucketsExported(context.Background(), mock2)
	if err != nil {
		t.Fatalf("second cycle error: %v", err)
	}
	if n2 != 1 {
		t.Errorf("expected 1 bucket on second cycle, got %d", n2)
	}
}
