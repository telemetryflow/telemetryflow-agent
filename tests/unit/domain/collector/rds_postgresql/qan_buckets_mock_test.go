// Package rds_postgresql_test contains unit tests for the RDS PostgreSQL QAN collector.
//
// This file drives the collectQANBuckets scan/delta path via pgxmock so the
// pg_stat_statements query body is exercised without a live database.
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

package rds_postgresql_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	rdspg "github.com/telemetryflow/telemetryflow-agent/internal/collector/rds_postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// qanRdsStmtCols mirrors the column order the collector scans from
// pg_stat_statements.
var qanRdsStmtCols = []string{
	"queryid", "query", "calls", "total_exec_time", "min_exec_time", "max_exec_time",
	"rows", "shared_blks_hit", "shared_blks_read", "shared_blks_dirtied", "shared_blks_written",
}

// addRdsQANRow appends one pg_stat_statements row with the given query text.
func addRdsQANRow(rows *pgxmock.Rows, qid int64, query string, calls uint64, totalTime float64) *pgxmock.Rows {
	return rows.AddRow(
		qid, query, calls, totalTime, float64(1), float64(9),
		uint64(1000), uint64(50), uint64(5), uint64(1), uint64(0),
	)
}

func newMockQANCollector(cfg rdspg.QANRDSPostgreSQLConfig) *rdspg.QANRDSPostgreSQLCollector {
	return rdspg.NewQANRDSPostgreSQLCollector(cfg, zap.NewNop())
}

func newMockQANInstance() *rdspg.RDSPgTestInstance {
	return rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{
		Name:   "primary",
		DBName: "postgres",
		User:   "postgres",
	})
}

func expectExtension(mock pgxmock.PgxPoolIface, exists bool) {
	mock.ExpectQuery("pg_extension").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(exists))
}

func TestQANBuckets_ExtensionMissing(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{})
	mock := newMockPool(t)
	expectExtension(mock, false)

	buckets, err := c.CollectQANBucketsExported(context.Background(), mock, newMockQANInstance())
	require.NoError(t, err)
	assert.Nil(t, buckets)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestQANBuckets_ExtensionQueryError(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{})
	mock := newMockPool(t)
	mock.ExpectQuery("pg_extension").WillReturnError(errors.New("boom"))

	buckets, err := c.CollectQANBucketsExported(context.Background(), mock, newMockQANInstance())
	// A query error on the extension check is treated as "not present" -> no buckets.
	require.NoError(t, err)
	assert.Nil(t, buckets)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestQANBuckets_StatementsQueryError(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 200})
	mock := newMockPool(t)
	expectExtension(mock, true)
	mock.ExpectQuery("pg_stat_statements").WithArgs(600).WillReturnError(errors.New("query failed"))

	buckets, err := c.CollectQANBucketsExported(context.Background(), mock, newMockQANInstance())
	require.Error(t, err)
	assert.Nil(t, buckets)
	assert.Contains(t, err.Error(), "query pg_stat_statements")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestQANBuckets_FirstCycleSeedsSnapshotNoBuckets(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 200})
	inst := newMockQANInstance()
	mock := newMockPool(t)
	expectExtension(mock, true)
	mock.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 1, "SELECT 1", 100, 1000))

	buckets, err := c.CollectQANBucketsExported(context.Background(), mock, inst)
	require.NoError(t, err)
	assert.Empty(t, buckets)
	assert.Equal(t, 1, inst.PrevSnapshotLen())
	assert.False(t, inst.PrevTime().IsZero())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestQANBuckets_SecondCycleProducesDeltaBucket(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{
		TopQueriesLimit: 200,
		Labels:          map[string]string{"env": "test"},
	})
	inst := newMockQANInstance()

	// First cycle seeds the snapshot.
	mock1 := newMockPool(t)
	expectExtension(mock1, true)
	mock1.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 1, "SELECT 1", 100, 1000))
	_, err := c.CollectQANBucketsExported(context.Background(), mock1, inst)
	require.NoError(t, err)

	// Force a known previous time so the period length is deterministic.
	inst.SetPrevTime(time.Now().Add(-60 * time.Second))

	// Second cycle: higher counters -> positive delta -> one bucket.
	mock2 := newMockPool(t)
	expectExtension(mock2, true)
	mock2.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 1, "SELECT 1", 250, 4000))
	buckets, err := c.CollectQANBucketsExported(context.Background(), mock2, inst)
	require.NoError(t, err)
	require.Len(t, buckets, 1)

	b := buckets[0]
	assert.Equal(t, qan.AgentTypeRDSPostgreSQLPgStmt, b.AgentType)
	assert.Equal(t, "1", b.QueryID)
	assert.Equal(t, b.QueryID, b.Fingerprint)
	assert.Equal(t, "postgres", b.Database)
	assert.Equal(t, "postgres", b.Username)
	assert.Equal(t, "test", b.Labels["env"])
	assert.Equal(t, "rds_postgresql", b.Labels["db_system"])
	assert.InDelta(t, float64(150), b.NumQueries, 0.001)
	assert.InDelta(t, float64(150), b.QueryTimeCnt, 0.001)
	assert.InDelta(t, float64(3.0), b.QueryTimeSum, 0.001) // (4000-1000)/1000
	require.NotNil(t, b.PostgreSQL)
	require.NoError(t, mock2.ExpectationsWereMet())
}

func TestQANBuckets_NonPositiveDeltaSkipped(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 200})
	inst := newMockQANInstance()

	mock1 := newMockPool(t)
	expectExtension(mock1, true)
	mock1.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 7, "SELECT 2", 500, 5000))
	_, err := c.CollectQANBucketsExported(context.Background(), mock1, inst)
	require.NoError(t, err)

	// Same calls count -> deltaCalls == 0 -> skipped.
	mock2 := newMockPool(t)
	expectExtension(mock2, true)
	mock2.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 7, "SELECT 2", 500, 5000))
	buckets, err := c.CollectQANBucketsExported(context.Background(), mock2, inst)
	require.NoError(t, err)
	assert.Empty(t, buckets)
	require.NoError(t, mock2.ExpectationsWereMet())
}

func TestQANBuckets_ExampleTruncatedAt2000(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 200})
	inst := newMockQANInstance()
	longQuery := "SELECT " + strings.Repeat("a", 2500)

	mock1 := newMockPool(t)
	expectExtension(mock1, true)
	mock1.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 3, longQuery, 10, 100))
	_, err := c.CollectQANBucketsExported(context.Background(), mock1, inst)
	require.NoError(t, err)

	mock2 := newMockPool(t)
	expectExtension(mock2, true)
	mock2.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 3, longQuery, 20, 200))
	buckets, err := c.CollectQANBucketsExported(context.Background(), mock2, inst)
	require.NoError(t, err)
	require.Len(t, buckets, 1)
	assert.True(t, buckets[0].ExampleTruncated)
	assert.Len(t, buckets[0].Example, 2000)
	require.NoError(t, mock2.ExpectationsWereMet())
}

func TestQANBuckets_UnscannableRowSkipped(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 200})
	mock := newMockPool(t)
	expectExtension(mock, true)
	// A non-numeric queryid cannot scan into uint64 -> row skipped, no error.
	mock.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(pgxmock.NewRows(qanRdsStmtCols).AddRow(
			"not-a-number", "SELECT 1", uint64(1), float64(1), float64(1), float64(9),
			uint64(1), uint64(1), uint64(1), uint64(1), uint64(1),
		))

	buckets, err := c.CollectQANBucketsExported(context.Background(), mock, newMockQANInstance())
	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestQANBuckets_SortAndLimitTruncates(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 1})
	inst := newMockQANInstance()

	seed := func(calls uint64, total float64) *pgxmock.Rows {
		rows := pgxmock.NewRows(qanRdsStmtCols)
		addRdsQANRow(rows, 1, "SELECT 1", calls, total)
		addRdsQANRow(rows, 2, "SELECT 2", calls, total)
		addRdsQANRow(rows, 3, "SELECT 3", calls, total)
		return rows
	}

	mock1 := newMockPool(t)
	expectExtension(mock1, true)
	mock1.ExpectQuery("pg_stat_statements").WithArgs(3).WillReturnRows(seed(100, 1000))
	_, err := c.CollectQANBucketsExported(context.Background(), mock1, inst)
	require.NoError(t, err)

	mock2 := newMockPool(t)
	expectExtension(mock2, true)
	mock2.ExpectQuery("pg_stat_statements").WithArgs(3).WillReturnRows(seed(200, 3000))
	buckets, err := c.CollectQANBucketsExported(context.Background(), mock2, inst)
	require.NoError(t, err)
	// Three deltas exist pre-sort; limit of 1 truncates to a single bucket.
	assert.Len(t, buckets, 1)
	require.NoError(t, mock2.ExpectationsWereMet())
}

func TestQANBuckets_CandidatePoolClamping(t *testing.T) {
	// limit*3 > 1000 clamps candidatePool to 1000.
	cHigh := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 400})
	mockHigh := newMockPool(t)
	expectExtension(mockHigh, true)
	mockHigh.ExpectQuery("pg_stat_statements").WithArgs(1000).
		WillReturnRows(pgxmock.NewRows(qanRdsStmtCols))
	_, err := cHigh.CollectQANBucketsExported(context.Background(), mockHigh, newMockQANInstance())
	require.NoError(t, err)
	require.NoError(t, mockHigh.ExpectationsWereMet())

	// limit > 1000: clamped 1000 < limit -> raised back to limit.
	cVeryHigh := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 2000})
	mockVH := newMockPool(t)
	expectExtension(mockVH, true)
	mockVH.ExpectQuery("pg_stat_statements").WithArgs(2000).
		WillReturnRows(pgxmock.NewRows(qanRdsStmtCols))
	_, err = cVeryHigh.CollectQANBucketsExported(context.Background(), mockVH, newMockQANInstance())
	require.NoError(t, err)
	require.NoError(t, mockVH.ExpectationsWereMet())
}

func TestQANBuckets_NegativePeriodFallsBackTo60s(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 200})
	inst := newMockQANInstance()

	mock1 := newMockPool(t)
	expectExtension(mock1, true)
	mock1.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 1, "SELECT 1", 100, 1000))
	_, err := c.CollectQANBucketsExported(context.Background(), mock1, inst)
	require.NoError(t, err)

	// prevTime in the future -> now-prevTime <= 0 -> 60s fallback.
	inst.SetPrevTime(time.Now().Add(1 * time.Hour))

	mock2 := newMockPool(t)
	expectExtension(mock2, true)
	mock2.ExpectQuery("pg_stat_statements").WithArgs(600).
		WillReturnRows(addRdsQANRow(pgxmock.NewRows(qanRdsStmtCols), 1, "SELECT 1", 250, 4000))
	buckets, err := c.CollectQANBucketsExported(context.Background(), mock2, inst)
	require.NoError(t, err)
	require.Len(t, buckets, 1)
	assert.Equal(t, int64(60), buckets[0].PeriodLengthSec)
	require.NoError(t, mock2.ExpectationsWereMet())
}

// --- Real (lazy) pool paths: no live DB required ---
//
// pgxpool.New is lazy: it validates the DSN and returns a usable *pgxpool.Pool
// without dialing. The first query attempt then fails against the unreachable
// host. This lets us exercise the collectInstance success wiring, the export
// SetPool/Pool helpers, and the Stop close loop without a running database.

func newLazyUnreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// Port 1 is unassigned/unreachable; the DSN parses fine.
	pool, err := pgxpool.New(context.Background(),
		"postgres://u:p@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestCollectInstanceExported_WithLazyPool_ExtensionCheckFails(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{TopQueriesLimit: 200})
	inst := newMockQANInstance()
	pool := newLazyUnreachablePool(t)
	inst.SetPool(pool)
	assert.Equal(t, pool, inst.Pool())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// ensureConnection returns the injected pool; the extension QueryRow then
	// fails to connect, so the collector treats the extension as absent.
	buckets, err := c.CollectInstanceExported(ctx, inst)
	require.NoError(t, err)
	assert.Nil(t, buckets)
}

func TestStop_ClosesInstancePool_LazyPool(t *testing.T) {
	c := newMockQANCollector(rdspg.QANRDSPostgreSQLConfig{})
	inst := newMockQANInstance()
	inst.SetPool(newLazyUnreachablePool(t))
	c.SetInstances(inst)

	require.NoError(t, c.Start(context.Background()))
	require.NoError(t, c.Stop())
	assert.Nil(t, inst.Pool())
}
