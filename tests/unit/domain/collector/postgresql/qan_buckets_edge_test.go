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
	"strings"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func newQANBucketCollectorLimit(limit int) *postgresql.QANPostgreSQLCollector {
	cfg := postgresql.QANConfig{
		Instances:       []config.PostgreSQLInstanceConfig{{Name: "qan", Host: "localhost", DBName: "app", User: "mon"}},
		TopQueriesLimit: limit,
	}
	return postgresql.NewQANPostgreSQLCollector(cfg, zap.NewNop())
}

func TestQANCollectBuckets_ScanErrorSkipsRow(t *testing.T) {
	c := newQANBucketCollector()
	mock := newMockPool(t)
	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	// queryid is a string where int64 is expected -> scan fails, row skipped.
	badRow := pgxmock.NewRows(qanStmtCols).AddRow(
		"bad", "SELECT 1", uint64(1), float64(1), float64(1), float64(1),
		uint64(1), uint64(1), uint64(1), uint64(1), uint64(1),
		uint64(1), uint64(1), float64(1), float64(1))
	mock.ExpectQuery("pg_stat_statements").WithArgs(600).WillReturnRows(badRow)
	n, err := c.CollectQANBucketsExported(context.Background(), mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 buckets, got %d", n)
	}
}

func TestQANCollectBuckets_NonPositiveDeltaSkipped(t *testing.T) {
	c := newQANBucketCollector()

	// First cycle seeds prev snapshot with high call count.
	mock1 := newMockPool(t)
	mock1.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock1.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addQANRow(pgxmock.NewRows(qanStmtCols), int64(1), uint64(500), float64(5000)))
	if _, err := c.CollectQANBucketsExported(context.Background(), mock1); err != nil {
		t.Fatalf("first cycle error: %v", err)
	}

	// Second cycle: calls decreased (counter reset) -> deltaCalls <= 0 -> skipped.
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	mock2.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addQANRow(pgxmock.NewRows(qanStmtCols), int64(1), uint64(10), float64(50)))
	n2, err := c.CollectQANBucketsExported(context.Background(), mock2)
	if err != nil {
		t.Fatalf("second cycle error: %v", err)
	}
	if n2 != 0 {
		t.Errorf("expected 0 buckets on non-positive delta, got %d", n2)
	}
}

func TestQANCollectBuckets_ExampleTruncatedAndSortLimit(t *testing.T) {
	// limit 1 -> candidatePool 3; two positive deltas trigger sort + truncation.
	c := newQANBucketCollectorLimit(1)
	longQuery := "SELECT " + strings.Repeat("a", 2100)

	addLong := func(rows *pgxmock.Rows, qid int64, calls uint64, total float64) *pgxmock.Rows {
		return rows.AddRow(
			qid, longQuery, calls, total, float64(1), float64(9),
			uint64(10), uint64(5), uint64(1), uint64(0), uint64(0),
			uint64(0), uint64(0), float64(0.1), float64(0.1))
	}

	// First cycle seeds both queries.
	mock1 := newMockPool(t)
	mock1.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	seed := addLong(pgxmock.NewRows(qanStmtCols), int64(1), uint64(100), float64(1000))
	addLong(seed, int64(2), uint64(100), float64(1000))
	mock1.ExpectQuery("pg_stat_statements").WithArgs(3).WillReturnRows(seed)
	if _, err := c.CollectQANBucketsExported(context.Background(), mock1); err != nil {
		t.Fatalf("first cycle error: %v", err)
	}

	// Second cycle: both have positive deltas; query 2 is slower this period.
	mock2 := newMockPool(t)
	mock2.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	delta := addLong(pgxmock.NewRows(qanStmtCols), int64(1), uint64(150), float64(2000))
	addLong(delta, int64(2), uint64(300), float64(9000))
	mock2.ExpectQuery("pg_stat_statements").WithArgs(3).WillReturnRows(delta)
	n2, err := c.CollectQANBucketsExported(context.Background(), mock2)
	if err != nil {
		t.Fatalf("second cycle error: %v", err)
	}
	if n2 != 1 {
		t.Errorf("expected buckets truncated to limit 1, got %d", n2)
	}
}
