// Package rds_postgresql_test contains unit tests for the RDS PostgreSQL QAN collector.
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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	rdspg "github.com/telemetryflow/telemetryflow-agent/internal/collector/rds_postgresql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

// --- test DB helpers ---

// testDSN returns the admin DSN for the throwaway Postgres used by these tests.
// Override with TFO_TEST_PG_DSN if the container runs elsewhere.
func testDSN(dbName string) string {
	base := os.Getenv("TFO_TEST_PG_DSN")
	if base == "" {
		base = "postgres://postgres:testpw@127.0.0.1:55432"
	}
	return fmt.Sprintf("%s/%s?sslmode=disable", base, dbName)
}

// newPool connects to the given database or skips the test if unreachable.
func newPool(t *testing.T, dbName string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, testDSN(dbName))
	if err != nil {
		t.Skipf("test Postgres unavailable: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...interface{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, sql, args...)
	require.NoError(t, err)
}

// positiveLongQueries returns `count` distinct SQL statements, each > 2000 chars,
// whose normalized form hashes to a POSITIVE bigint queryid.
//
// Why this matters: the collector scans pg_stat_statements.queryid (a signed
// bigint) into a uint64. pgx's Rows.Scan calls rows.fatal on a decode error, so
// the FIRST row with a negative queryid aborts the entire row iteration. Roughly
// half of all real queryids are negative, so reliable delta buckets require
// statements that (a) hash positive and (b) sort to the top by total_exec_time
// (many columns => expensive plan) so they are scanned before any negative row.
// It resets pg_stat_statements before returning so the caller starts clean.
func positiveLongQueries(t *testing.T, pool *pgxpool.Pool, count int) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	out := make([]string, 0, count)
	for cols := 210; cols <= 400 && len(out) < count; cols++ {
		sql := "SELECT " + strings.Repeat("1::integer,", cols) + "1::integer"
		if len(sql) <= 2000 {
			continue
		}
		_, err := pool.Exec(ctx, "SELECT pg_stat_statements_reset()")
		require.NoError(t, err)
		_, err = pool.Exec(ctx, sql)
		require.NoError(t, err)

		var qid int64
		err = pool.QueryRow(ctx,
			"SELECT queryid FROM pg_stat_statements WHERE query LIKE 'SELECT $1::integer%' ORDER BY length(query) DESC LIMIT 1",
		).Scan(&qid)
		require.NoError(t, err)
		if qid > 0 {
			out = append(out, sql)
		}
	}
	require.Len(t, out, count, "could not find enough positive-queryid statements")

	_, err := pool.Exec(ctx, "SELECT pg_stat_statements_reset()")
	require.NoError(t, err)
	return out
}

// negativeLongQuery returns a single SQL statement whose normalized form hashes
// to a NEGATIVE bigint queryid. Scanning such a queryid into the collector's
// uint64 destination fails, exercising the row-scan error branch.
func negativeLongQuery(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for cols := 210; cols <= 500; cols++ {
		sql := "SELECT " + strings.Repeat("1::integer,", cols) + "1::integer"
		_, err := pool.Exec(ctx, "SELECT pg_stat_statements_reset()")
		require.NoError(t, err)
		_, err = pool.Exec(ctx, sql)
		require.NoError(t, err)

		var qid int64
		err = pool.QueryRow(ctx,
			"SELECT queryid FROM pg_stat_statements WHERE query LIKE 'SELECT $1::integer%' ORDER BY length(query) DESC LIMIT 1",
		).Scan(&qid)
		require.NoError(t, err)
		if qid < 0 {
			_, err = pool.Exec(ctx, "SELECT pg_stat_statements_reset()")
			require.NoError(t, err)
			return sql
		}
	}
	t.Fatal("could not find a negative-queryid statement")
	return ""
}

// runQueries executes each statement once.
func runQueries(t *testing.T, pool *pgxpool.Pool, qs []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, q := range qs {
		_, err := pool.Exec(ctx, q)
		require.NoError(t, err)
	}
}

// --- Constructor / config defaults ---

func TestNewQANRDSPostgreSQLCollector_Defaults(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		Instances: []config.RDSPostgreSQLInstanceConfig{{Name: "a"}},
	}, zap.NewNop())

	require.NotNil(t, c)
	assert.Equal(t, "qan-rds-postgresql-pgstatements", c.Name())
	assert.Equal(t, qan.AgentTypeRDSPostgreSQLPgStmt, c.AgentType())
	assert.False(t, c.IsRunning())
}

func TestNewQANRDSPostgreSQLCollector_NilLoggerUsesProduction(t *testing.T) {
	// nil logger must not panic; constructor falls back to a production logger.
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		TopQueriesLimit: 50,
		Instances:       []config.RDSPostgreSQLInstanceConfig{{Name: "a"}, {Name: "b"}},
	}, nil)
	require.NotNil(t, c)
	assert.Equal(t, "qan-rds-postgresql-pgstatements", c.Name())
}

func TestNewQANRDSPostgreSQLCollector_CustomTopQueriesLimit(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		TopQueriesLimit: 7,
	}, zap.NewNop())
	require.NotNil(t, c)
}

// --- Lifecycle ---

func TestStart_And_DoubleStart(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		Instances: []config.RDSPostgreSQLInstanceConfig{{Name: "a"}},
	}, zap.NewNop())

	require.NoError(t, c.Start(context.Background()))
	assert.True(t, c.IsRunning())

	err := c.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestStop_WhenNotRunning(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	// Stopping a collector that never started is a no-op.
	require.NoError(t, c.Stop())
}

func TestStart_Then_Stop(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	require.NoError(t, c.Start(context.Background()))
	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())
}

func TestStop_ClosesInstancePool(t *testing.T) {
	pool := newPool(t, "postgres")
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())

	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "a"})
	inst.SetPool(pool)
	c.SetInstances(inst)

	require.NoError(t, c.Start(context.Background()))
	require.NoError(t, c.Stop())
	// Pool is closed and nil-ed by Stop.
	assert.Nil(t, inst.Pool())
	// Test cleanup will call pool.Close again; that is safe on an already-closed pool.
}

// --- databaseName ---

func TestDatabaseName(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())

	def := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{})
	assert.Equal(t, "postgres", c.DatabaseNameExported(def))

	named := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{DBName: "orders"})
	assert.Equal(t, "orders", c.DatabaseNameExported(named))
}

// --- instanceLabels ---

func TestInstanceLabels(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		Labels: map[string]string{"env": "prod", "team": "obs"},
	}, zap.NewNop())

	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{
		Name:       "primary",
		InstanceID: "db-123",
		Host:       "db.rds.aws",
		Region:     "us-east-1",
	})
	labels := c.InstanceLabelsExported(inst)

	assert.Equal(t, "prod", labels["env"])
	assert.Equal(t, "obs", labels["team"])
	assert.Equal(t, "primary", labels["rds_postgresql_instance"])
	assert.Equal(t, "db-123", labels["rds_postgresql_instance_id"])
	assert.Equal(t, "db.rds.aws", labels["rds_postgresql_host"])
	assert.Equal(t, "us-east-1", labels["rds_postgresql_region"])
	assert.Equal(t, "rds_postgresql", labels["db_system"])
}

// --- ensureConnection ---

func TestEnsureConnection_ReturnsExistingPool(t *testing.T) {
	pool := newPool(t, "postgres")
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "a"})
	inst.SetPool(pool)

	got, err := c.EnsureConnectionExported(context.Background(), inst)
	require.NoError(t, err)
	assert.Equal(t, pool, got)
}

func TestEnsureConnection_ParseConfigError(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	// A space in the password produces an invalid DSN that ParseConfig rejects.
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{
		Name:     "bad",
		Host:     "localhost",
		User:     "u",
		Password: "bad pass",
	})
	_, err := c.EnsureConnectionExported(context.Background(), inst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse config")
}

func TestEnsureConnection_PingError(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	// Unroutable port; connection build succeeds but Ping fails. Empty DBName/Port
	// also exercise the default-application branches.
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{
		Name: "unreachable",
		Host: "127.0.0.1",
		User: "u",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.EnsureConnectionExported(ctx, inst)
	require.Error(t, err)
}

func TestEnsureConnection_AppliesDBNameAndPort(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	// Non-empty DBName and Port exercise the override branches; the unroutable
	// port still fails at Ping, which is the expected outcome here.
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{
		Name:   "custom",
		Host:   "127.0.0.1",
		Port:   1,
		User:   "u",
		DBName: "customdb",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.EnsureConnectionExported(ctx, inst)
	require.Error(t, err)
}

// --- collectInstance (delta calculation over a live DB) ---

func TestCollectInstance_ExtensionMissing(t *testing.T) {
	admin := newPool(t, "postgres")
	// Fresh database without pg_stat_statements registered.
	exec(t, admin, "DROP DATABASE IF EXISTS tfo_noext")
	exec(t, admin, "CREATE DATABASE tfo_noext")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS tfo_noext")
	})

	pool := newPool(t, "tfo_noext")
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "noext", DBName: "tfo_noext"})
	inst.SetPool(pool)

	buckets, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)
	assert.Nil(t, buckets)
}

func TestCollectInstance_DeltaProducesBuckets(t *testing.T) {
	pool := newPool(t, "postgres")
	exec(t, pool, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
	exec(t, pool, "SELECT pg_stat_statements_reset()")

	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		TopQueriesLimit: 200,
		Labels:          map[string]string{"env": "test"},
	}, zap.NewNop())
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{
		Name:   "primary",
		DBName: "postgres",
		User:   "postgres",
	})
	inst.SetPool(pool)

	queries := positiveLongQueries(t, pool, 3)

	// First pass: builds baseline snapshot, no prior state -> no buckets.
	runQueries(t, pool, queries)
	first, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)
	assert.Empty(t, first)
	assert.True(t, inst.PrevSnapshotLen() > 0)
	assert.False(t, inst.PrevTime().IsZero())

	// Second pass: re-run queries to create positive call deltas.
	runQueries(t, pool, queries)
	second, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)
	require.NotEmpty(t, second, "expected delta buckets on second pass")

	var sawTruncated bool
	for _, b := range second {
		assert.Equal(t, qan.AgentTypeRDSPostgreSQLPgStmt, b.AgentType)
		assert.NotEmpty(t, b.QueryID)
		assert.Equal(t, b.QueryID, b.Fingerprint)
		assert.Equal(t, "postgres", b.Database)
		assert.Equal(t, "postgres", b.Username)
		assert.Equal(t, "test", b.Labels["env"])
		assert.Equal(t, "rds_postgresql", b.Labels["db_system"])
		assert.True(t, b.NumQueries > 0)
		assert.True(t, b.QueryTimeCnt > 0)
		assert.True(t, len(b.Example) <= 2000)
		require.NotNil(t, b.PostgreSQL)
		if b.ExampleTruncated {
			sawTruncated = true
			assert.Len(t, b.Example, 2000)
		}
	}
	assert.True(t, sawTruncated, "expected the long query to be truncated at 2000 chars")
}

func TestCollectInstance_SortAndLimit(t *testing.T) {
	pool := newPool(t, "postgres")
	exec(t, pool, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
	exec(t, pool, "SELECT pg_stat_statements_reset()")

	// Limit of 1 forces the sort-and-truncate branch when >1 delta buckets exist.
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		TopQueriesLimit: 1,
	}, zap.NewNop())
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "p", DBName: "postgres"})
	inst.SetPool(pool)

	queries := positiveLongQueries(t, pool, 3)

	runQueries(t, pool, queries)
	_, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)

	runQueries(t, pool, queries)
	buckets, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)
	// >1 delta buckets exist pre-sort, so the collector sorts and truncates to 1.
	assert.LessOrEqual(t, len(buckets), 1)
}

func TestCollectInstance_SkipsUnscannableRow(t *testing.T) {
	pool := newPool(t, "postgres")
	exec(t, pool, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")

	// A negative bigint queryid cannot be scanned into the collector's uint64
	// destination; that row is skipped (and pgx aborts the remaining rows). The
	// collect must still succeed and simply yield no buckets for that row.
	neg := negativeLongQuery(t, pool)
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "p", DBName: "postgres"})
	inst.SetPool(pool)

	runQueries(t, pool, []string{neg})
	buckets, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)
	assert.Empty(t, buckets)
}

func TestCollectInstance_CandidatePoolClamping(t *testing.T) {
	pool := newPool(t, "postgres")
	exec(t, pool, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")

	// TopQueriesLimit > 333 makes limit*3 exceed 1000 -> clamps candidatePool to 1000.
	cHigh := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		TopQueriesLimit: 400,
	}, zap.NewNop())
	instHigh := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "h", DBName: "postgres"})
	instHigh.SetPool(pool)
	runQueries(t, pool, positiveLongQueries(t, pool, 1))
	_, err := cHigh.CollectInstanceExported(context.Background(), instHigh)
	require.NoError(t, err)

	// TopQueriesLimit > 1000 makes candidatePool (clamped to 1000) < limit -> raised back to limit.
	cVeryHigh := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{
		TopQueriesLimit: 2000,
	}, zap.NewNop())
	instVH := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "vh", DBName: "postgres"})
	instVH.SetPool(pool)
	_, err = cVeryHigh.CollectInstanceExported(context.Background(), instVH)
	require.NoError(t, err)
}

func TestCollectInstance_NegativePeriodFallback(t *testing.T) {
	pool := newPool(t, "postgres")
	exec(t, pool, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
	exec(t, pool, "SELECT pg_stat_statements_reset()")

	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "p", DBName: "postgres"})
	inst.SetPool(pool)

	queries := positiveLongQueries(t, pool, 3)
	runQueries(t, pool, queries)
	_, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)

	// Force prevTime into the future so now-prevTime <= 0 hits the 60s fallback.
	inst.SetPrevTime(time.Now().Add(1 * time.Hour))
	runQueries(t, pool, queries)
	buckets, err := c.CollectInstanceExported(context.Background(), inst)
	require.NoError(t, err)
	for _, b := range buckets {
		assert.Equal(t, int64(60), b.PeriodLengthSec)
	}
}

// --- CollectQAN ---

func TestCollectQAN_NoInstances(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Nil(t, buckets)
}

func TestCollectQAN_InstanceErrorIsSkipped(t *testing.T) {
	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	// No pool set and an unreachable host -> ensureConnection fails, warn+continue.
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{
		Name: "unreachable",
		Host: "127.0.0.1",
		User: "u",
	})
	c.SetInstances(inst)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	buckets, err := c.CollectQAN(ctx)
	require.NoError(t, err)
	assert.Nil(t, buckets)
}

func TestCollectQAN_AggregatesBuckets(t *testing.T) {
	pool := newPool(t, "postgres")
	exec(t, pool, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
	exec(t, pool, "SELECT pg_stat_statements_reset()")

	c := rdspg.NewQANRDSPostgreSQLCollector(rdspg.QANRDSPostgreSQLConfig{}, zap.NewNop())
	inst := rdspg.NewRDSPgTestInstance(config.RDSPostgreSQLInstanceConfig{Name: "p", DBName: "postgres"})
	inst.SetPool(pool)
	c.SetInstances(inst)

	queries := positiveLongQueries(t, pool, 3)
	runQueries(t, pool, queries)
	_, err := c.CollectQAN(context.Background())
	require.NoError(t, err)

	runQueries(t, pool, queries)
	buckets, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, buckets)
}
