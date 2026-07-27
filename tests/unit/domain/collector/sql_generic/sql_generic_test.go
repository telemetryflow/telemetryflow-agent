// Package sql_generic_test contains unit tests for the sql_generic collector.
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

package sql_generic_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/sql_generic"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// setupSQLite creates a temp SQLite database file, runs the given DDL/DML
// statements against it, closes the writer, and returns the file path (which
// doubles as the DSN for the modernc "sqlite" driver).
func setupSQLite(t *testing.T, statements ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	for _, s := range statements {
		_, err = db.Exec(s)
		require.NoError(t, err)
	}
	return path
}

func TestNewCollector_BadDriver(t *testing.T) {
	// An unknown driver is rejected up front (fail-fast).
	_, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name: "bad", Driver: "nonexistent-driver", DSN: "whatever",
		}},
	}, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

func TestNewCollector_EmptyInstanceName(t *testing.T) {
	_, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{Driver: "sqlite", DSN: ":memory:"}},
	}, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty name")
}

func TestCollector_NameAndLifecycle(t *testing.T) {
	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{}, zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, "sql_generic", c.Name())
	assert.False(t, c.IsRunning())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	// Double start must error.
	require.Error(t, c.Start(ctx))

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
	assert.False(t, c.IsRunning())

	// Stop when not running is a no-op.
	assert.NoError(t, c.Stop())
}

func TestCollect_NoInstances(t *testing.T) {
	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{}, zap.NewNop())
	require.NoError(t, err)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, metrics)
}

// Single-row query emits exactly one metric with the value column as the value
// and the configured label column as a label.
func TestCollect_SingleRow(t *testing.T) {
	path := setupSQLite(t,
		`CREATE TABLE subscriptions (id INTEGER, plan TEXT, status TEXT)`,
		`INSERT INTO subscriptions VALUES (1,'pro','active'),(2,'free','active'),(3,'pro','canceled')`,
	)

	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "billing",
			Driver: "sqlite",
			DSN:    path,
			Queries: []config.SQLQuery{{
				Metric:       "billing.active_subscriptions",
				Type:         "gauge",
				SQL:          "SELECT count(*) AS value FROM subscriptions WHERE status='active'",
				ValueColumn:  "value",
				LabelColumns: []string{"plan_tier"},
			}},
		}},
	}, zap.NewNop())
	require.NoError(t, err)

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, metrics, 1)

	m := metrics[0]
	assert.Equal(t, "billing.active_subscriptions", m.Name)
	assert.Equal(t, collector.MetricTypeGauge, m.Type)
	assert.Equal(t, 2.0, m.Value) // 2 active subscriptions
	assert.Equal(t, "billing", m.Labels["sql_instance"])
	assert.False(t, m.Timestamp.IsZero())

	require.NoError(t, c.Stop())
}

// Multi-row query emits one metric per result row.
func TestCollect_MultiRow(t *testing.T) {
	path := setupSQLite(t,
		`CREATE TABLE subscriptions (id INTEGER, plan TEXT, status TEXT)`,
		`INSERT INTO subscriptions VALUES
			(1,'pro','active'),(2,'free','active'),(3,'pro','active'),
			(4,'enterprise','active'),(5,'free','canceled')`,
	)

	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "billing",
			Driver: "sqlite",
			DSN:    path,
			Queries: []config.SQLQuery{{
				Metric: "billing.active_subscriptions",
				Type:   "counter",
				SQL: `SELECT count(*) AS value, plan AS plan_tier
				      FROM subscriptions WHERE status='active' GROUP BY plan`,
				ValueColumn:  "value",
				LabelColumns: []string{"plan_tier"},
			}},
		}},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, metrics, 3) // pro, free, enterprise

	byPlan := map[string]float64{}
	for _, m := range metrics {
		assert.Equal(t, "billing.active_subscriptions", m.Name)
		assert.Equal(t, collector.MetricTypeCounter, m.Type)
		assert.Equal(t, "billing", m.Labels["sql_instance"])
		byPlan[m.Labels["plan_tier"]] = m.Value
	}
	assert.Equal(t, 2.0, byPlan["pro"])
	assert.Equal(t, 1.0, byPlan["free"])
	assert.Equal(t, 1.0, byPlan["enterprise"])
}

// An empty result set emits zero metrics and no error.
func TestCollect_EmptyResult(t *testing.T) {
	path := setupSQLite(t,
		`CREATE TABLE subscriptions (id INTEGER, status TEXT)`,
		// No rows inserted, so the filtered query below returns no rows.
	)

	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "billing",
			Driver: "sqlite",
			DSN:    path,
			Queries: []config.SQLQuery{{
				Metric:      "billing.row",
				SQL:         "SELECT id AS value FROM subscriptions WHERE status='active'",
				ValueColumn: "value",
			}},
		}},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// A bad query is skipped; other queries in the same instance still emit.
func TestCollect_BadSQLOthersContinue(t *testing.T) {
	path := setupSQLite(t,
		`CREATE TABLE subscriptions (id INTEGER, status TEXT)`,
		`INSERT INTO subscriptions VALUES (1,'active'),(2,'active')`,
	)

	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "billing",
			Driver: "sqlite",
			DSN:    path,
			Queries: []config.SQLQuery{
				{
					Metric:      "billing.bad",
					SQL:         "SELECT count(*) AS value FROM nonexistent_table",
					ValueColumn: "value",
				},
				{
					Metric:      "billing.good",
					SQL:         "SELECT count(*) AS value FROM subscriptions WHERE status='active'",
					ValueColumn: "value",
				},
			},
		}},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	require.Len(t, metrics, 1)
	assert.Equal(t, "billing.good", metrics[0].Name)
	assert.Equal(t, 2.0, metrics[0].Value)
}

// A connection that cannot be established yields zero metrics for that
// instance, surfaced via the SetDBFactory test seam.
func TestCollect_ConnectionFailure_ClosedDB(t *testing.T) {
	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "dead",
			Driver: "sqlite",
			DSN:    ":memory:",
			Queries: []config.SQLQuery{{
				Metric:      "billing.dead",
				SQL:         "SELECT 1 AS value",
				ValueColumn: "value",
			}},
		}},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	// Inject a closed pool: sql.Open succeeds but the pool is already closed,
	// so QueryContext fails with "sql: database is closed".
	deadDB, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	require.NoError(t, deadDB.Close())

	c.SetDBFactory(func(_, _ string) (*sql.DB, error) {
		return deadDB, nil
	})

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err) // per-instance failures are swallowed
	assert.Empty(t, metrics)
}

// A bad DSN (unreachable file path) drives the connection-failure path
// without the test seam: sql.Open succeeds, the query fails at exec time.
func TestCollect_ConnectionFailure_BadPath(t *testing.T) {
	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "missing",
			Driver: "sqlite",
			DSN:    filepath.Join(t.TempDir(), "nested", "missing.db"),
			Queries: []config.SQLQuery{{
				Metric:      "billing.missing",
				SQL:         "SELECT 1 AS value",
				ValueColumn: "value",
			}},
		}},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// SetDBFactory injects a pre-populated in-memory database so the collector
// reads from the test-controlled connection instead of the configured DSN.
func TestCollect_SetDBFactory_InjectsDB(t *testing.T) {
	// Shared in-memory DB: open once, populate, keep the writer open so the
	// cache survives for the collector's read connection.
	writer, err := sql.Open("sqlite", "file:injected?mode=memory&cache=shared")
	require.NoError(t, err)
	defer func() { _ = writer.Close() }()
	_, err = writer.Exec(`CREATE TABLE t (n INTEGER); INSERT INTO t VALUES (10),(20);`)
	require.NoError(t, err)

	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "injected",
			Driver: "sqlite",
			DSN:    "file:injected?mode=memory&cache=shared",
			Queries: []config.SQLQuery{{
				Metric:      "test.injected",
				SQL:         "SELECT n AS value FROM t",
				ValueColumn: "value",
			}},
		}},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	// Re-open via the factory to prove the seam overrides the constructor's pool.
	c.SetDBFactory(func(_, dsn string) (*sql.DB, error) {
		return sql.Open("sqlite", dsn)
	})

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, metrics, 2)

	vals := map[float64]bool{}
	for _, m := range metrics {
		vals[m.Value] = true
		assert.Equal(t, "injected", m.Labels["sql_instance"])
	}
	assert.True(t, vals[10.0])
	assert.True(t, vals[20.0])
}

// Two instances are collected independently and their metrics merged.
func TestCollect_MultipleInstances(t *testing.T) {
	pathA := setupSQLite(t, `CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (5);`)
	pathB := setupSQLite(t, `CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (7);`)

	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{
			{
				Name: "a", Driver: "sqlite", DSN: pathA,
				Queries: []config.SQLQuery{{
					Metric: "test.v", SQL: "SELECT v AS value FROM t", ValueColumn: "value",
				}},
			},
			{
				Name: "b", Driver: "sqlite", DSN: pathB,
				Queries: []config.SQLQuery{{
					Metric: "test.v", SQL: "SELECT v AS value FROM t", ValueColumn: "value",
				}},
			},
		},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, metrics, 2)

	byInstance := map[string]float64{}
	for _, m := range metrics {
		byInstance[m.Labels["sql_instance"]] = m.Value
	}
	assert.Equal(t, 5.0, byInstance["a"])
	assert.Equal(t, 7.0, byInstance["b"])
}

// The unit field is propagated onto emitted metrics.
func TestCollect_UnitPropagated(t *testing.T) {
	path := setupSQLite(t, `CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (42);`)

	c, err := sql_generic.NewSQLGenericCollector(config.SQLGenericCollectorConfig{
		Instances: []config.SQLGenericInstance{{
			Name:   "u",
			Driver: "sqlite",
			DSN:    path,
			Queries: []config.SQLQuery{{
				Metric:      "test.unit",
				SQL:         "SELECT v AS value FROM t",
				ValueColumn: "value",
				Unit:        "bytes",
			}},
		}},
	}, zap.NewNop())
	require.NoError(t, err)
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	assert.Equal(t, "bytes", metrics[0].Unit)
}
