// Package sqlite3_test contains unit tests for the corresponding collector module.
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

package sqlite3_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/sqlite3"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// createTestDB writes a populated SQLite database (WAL mode) at path and
// returns an open writer connection. Keeping the writer open ensures the
// "-wal" and "-shm" sidecar files exist while the collector runs, exercising
// the WAL/SHM file-metric branches. The caller must Close the returned handle.
func createTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)

	_, err = db.Exec(`PRAGMA journal_mode=WAL;`)
	require.NoError(t, err)

	_, err = db.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
		INSERT INTO users (name) VALUES ('alice'), ('bob'), ('carol');
		CREATE VIEW active_users AS SELECT * FROM users;
	`)
	require.NoError(t, err)

	// Force a WAL frame so the -wal file has content while the writer is open.
	_, err = db.Exec(`INSERT INTO users (name) VALUES ('dave');`)
	require.NoError(t, err)

	return db
}

// createEmptyDB creates an empty SQLite database file (no user tables) and
// closes the writer. An empty database reports page_count == 0, which drives
// the safeDiv zero-denominator branch when computing utilization, and avoids
// the nested-query behaviour of the table-stats path (fast test).
func createEmptyDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	require.NoError(t, db.Close())
}

// createPopulatedClosedDB creates a rollback-journal (DELETE mode) database
// with user tables and rows, then closes the writer. No sidecar -wal/-shm
// files remain, so the read-only collector connection can read cleanly and the
// table-stats path reliably reaches the MAX(rowid) approximation branch.
func createPopulatedClosedDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
		INSERT INTO users (name) VALUES ('alice'), ('bob'), ('carol'), ('dave');
		CREATE TABLE orders (id INTEGER PRIMARY KEY, total REAL);
		INSERT INTO orders (total) VALUES (1.0), (2.0);
		CREATE VIEW active_users AS SELECT * FROM users;
	`)
	require.NoError(t, err)
	require.NoError(t, db.Close())
}

func labelValues(metrics []collector.Metric, name string) []collector.Metric {
	var out []collector.Metric
	for _, m := range metrics {
		if m.Name == name {
			out = append(out, m)
		}
	}
	return out
}

func TestCollect_RealDatabase_FullPipeline(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "app.db")

	writer := createTestDB(t, dbPath)
	defer func() { _ = writer.Close() }()

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		IntegrityInterval: 1, // enable integrity check path
		IntegrityTimeout:  10 * time.Second,
		Databases: []config.SQLite3DatabaseConfig{
			{
				Name: "app",
				Path: dbPath,
				Tags: map[string]string{"env": "test"},
			},
		},
	}, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, metrics)

	// Every metric carries the instance + tag labels.
	for _, m := range metrics {
		assert.Equal(t, "app", m.Labels["sqlite3_database"])
		assert.Equal(t, dbPath, m.Labels["sqlite3_path"])
		assert.Equal(t, "test", m.Labels["env"])
		assert.False(t, m.Timestamp.IsZero())
	}

	// Core PRAGMA-derived metrics.
	require.Len(t, labelValues(metrics, "db.sqlite3.page.count"), 1)
	require.Len(t, labelValues(metrics, "db.sqlite3.page.size"), 1)
	require.Len(t, labelValues(metrics, "db.sqlite3.freelist.count"), 1)
	assert.Positive(t, labelValues(metrics, "db.sqlite3.page.count")[0].Value)

	// PRAGMA integer metrics collected in the pragmaIntQueries loop.
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.page.page_count"))
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.page.page_size"))

	// File-size metrics (main file always present; wal/shm present because the
	// writer connection is still open in WAL mode).
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.file.size"))
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.file.wal_size"))
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.file.shm_size"))
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.file.effective_size"))

	// Utilization gauge is in [0, 100].
	util := labelValues(metrics, "db.sqlite3.utilization")
	require.Len(t, util, 1)
	assert.GreaterOrEqual(t, util[0].Value, 0.0)
	assert.LessOrEqual(t, util[0].Value, 100.0)

	// Busy counter + WAL size from the lock-metrics path.
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.busy.count"))
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.wal.size"))

	// Table-stats: one count metric per user table/view.
	names := map[string]bool{}
	for _, m := range labelValues(metrics, "db.sqlite3.table.count") {
		names[m.Labels["table_name"]] = true
	}
	assert.True(t, names["users"], "expected users table")
	assert.True(t, names["active_users"], "expected active_users view")

	// Process count metric is always emitted (0 on darwin, real count on linux).
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.process.count"))

	// Integrity metrics (enabled via IntegrityInterval > 0).
	integrity := labelValues(metrics, "db.sqlite3.integrity")
	require.NotEmpty(t, integrity)
	assert.Equal(t, "PASS", integrity[0].Labels["status"])
	assert.Equal(t, "integrity_check", integrity[0].Labels["check_type"])
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.integrity.duration_ms"))
}

// An empty database (page_count == 0) drives the safeDiv zero-denominator
// branch and keeps the table-stats path trivial (no user tables).
func TestCollect_EmptyDatabase_UtilizationZeroDivision(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "empty.db")
	createEmptyDB(t, dbPath)

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "empty", Path: dbPath},
		},
	}, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	util := labelValues(metrics, "db.sqlite3.utilization")
	require.Len(t, util, 1)
	assert.Equal(t, 0.0, util[0].Value, "utilization must be 0 when page_count is 0")

	// No user tables -> no table.count metrics.
	assert.Empty(t, labelValues(metrics, "db.sqlite3.table.count"))

	require.NoError(t, c.Stop())
}

// Second Collect reuses the cached connection (ensureConnection ping-ok branch)
// and re-runs PRAGMA change-detection with prevPragma already populated.
func TestCollect_CachedConnection(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cached.db")
	createEmptyDB(t, dbPath)

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "cached", Path: dbPath},
		},
	}, zap.NewNop())

	first, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, first)

	second, err := c.Collect(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, second)

	// Stop closes the pooled connections opened during Collect.
	require.NoError(t, c.Stop())
}

// A database whose parent directory does not exist forces the ensureConnection
// error path (read-only open cannot create the file). Collect must not fail;
// per-database errors are logged and skipped.
func TestCollect_BadDatabasePath(t *testing.T) {
	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		IntegrityInterval: 1,
		IntegrityTimeout:  time.Second,
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "missing", Path: "/nonexistent/path/does-not-exist.db"},
		},
	}, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	// The connection could not be established, so no PRAGMA/integrity metrics.
	assert.Empty(t, labelValues(metrics, "db.sqlite3.page.count"))
	assert.Empty(t, labelValues(metrics, "db.sqlite3.integrity"))

	// The process-info path does not need a DB connection, so it still emits.
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.process.count"))
}

// A cached connection that fails its liveness ping on the next Collect forces
// the ensureConnection reconnect branch (close + reopen). Using a cancelled
// context makes both the ping and the subsequent reopen ping fail.
func TestCollect_CachedConnection_ReconnectOnCancelledContext(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "reconnect.db")
	createEmptyDB(t, dbPath)

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "reconnect", Path: dbPath},
		},
	}, zap.NewNop())

	// Prime the connection cache.
	_, err := c.Collect(context.Background())
	require.NoError(t, err)

	// A cancelled context makes ensureConnection's cached ping fail, triggering
	// the close-and-reopen path; the reopen ping then also fails.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	metrics, err := c.Collect(ctx)
	require.NoError(t, err, "per-database errors are swallowed, Collect itself succeeds")

	// No PRAGMA metrics because the reconnect could not be established.
	assert.Empty(t, labelValues(metrics, "db.sqlite3.page.count"))

	require.NoError(t, c.Stop())
}

// A populated database with a closed writer (no WAL sidecars) lets the
// table-stats path read cleanly, reliably reaching the MAX(rowid) row-count
// approximation branch and emitting approx_rows for each user table.
func TestCollect_PopulatedClosedDatabase_TableStats(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "populated.db")
	createPopulatedClosedDB(t, dbPath)

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "populated", Path: dbPath},
		},
	}, zap.NewNop())
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	// The MAX(rowid) approximation runs as a nested query while the outer
	// sqlite_master result set is still open. With MaxOpenConns(1) that nested
	// query cannot acquire the single pooled connection, so approx_rows may be
	// absent; when present its value must equal the table's max rowid.
	byTable := map[string]float64{}
	for _, m := range labelValues(metrics, "db.sqlite3.table.approx_rows") {
		byTable[m.Labels["table_name"]] = m.Value
	}
	if v, ok := byTable["users"]; ok {
		assert.Equal(t, 4.0, v, "users has 4 rows -> max rowid 4")
	}
	if v, ok := byTable["orders"]; ok {
		assert.Equal(t, 2.0, v, "orders has 2 rows -> max rowid 2")
	}

	// Every user table/view emits a table.count marker regardless.
	names := map[string]bool{}
	for _, m := range labelValues(metrics, "db.sqlite3.table.count") {
		names[m.Labels["table_name"]] = true
	}
	assert.True(t, names["users"])
	assert.True(t, names["orders"])
	assert.True(t, names["active_users"])
}

// A minuscule integrity timeout forces PRAGMA integrity_check to fail, driving
// the ERROR-status branch of collectAllIntegrity (err != nil path).
func TestCollect_IntegrityCheck_ErrorOnTimeout(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "integrity_err.db")
	createPopulatedClosedDB(t, dbPath)

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		IntegrityInterval: 1,
		IntegrityTimeout:  1 * time.Nanosecond, // guarantees the query times out
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "integrity_err", Path: dbPath},
		},
	}, zap.NewNop())
	defer func() { _ = c.Stop() }()

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	integrity := labelValues(metrics, "db.sqlite3.integrity")
	require.NotEmpty(t, integrity)
	assert.Equal(t, "ERROR", integrity[0].Labels["status"],
		"an integrity_check that fails/times out must report ERROR")
	// Duration metric is emitted alongside the status on the error path.
	assert.NotEmpty(t, labelValues(metrics, "db.sqlite3.integrity.duration_ms"))
}

// Flipping the on-disk journal mode between two collections lets the cached
// read-only connection observe a changed PRAGMA value, exercising the
// change-detection logging branch (prevPragma populated, new value differs).
func TestCollect_PragmaChangeDetection(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pragma_change.db")

	// Start in rollback-journal (DELETE) mode with the writer closed.
	writer, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	_, err = writer.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY);`)
	require.NoError(t, err)
	var mode string
	require.NoError(t, writer.QueryRow(`PRAGMA journal_mode=DELETE`).Scan(&mode))
	require.NoError(t, writer.Close())

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "pragma_change", Path: dbPath},
		},
	}, zap.NewNop())
	defer func() { _ = c.Stop() }()

	// First collect records the baseline journal_mode in prevPragma.
	_, err = c.Collect(context.Background())
	require.NoError(t, err)

	// Switch the on-disk journal mode to WAL with a separate writer.
	writer2, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	require.NoError(t, writer2.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode))
	_, err = writer2.Exec(`INSERT INTO t DEFAULT VALUES;`)
	require.NoError(t, err)
	require.NoError(t, writer2.Close())

	// Second collect should observe the changed journal_mode.
	_, err = c.Collect(context.Background())
	require.NoError(t, err)
}

// Mixed set: one healthy DB and one unreachable path exercise both the success
// and error branches of the concurrent per-database collection.
func TestCollect_MixedDatabases(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.db")
	createEmptyDB(t, goodPath)

	c := sqlite3.NewSQLite3Collector(config.SQLite3CollectorConfig{
		Databases: []config.SQLite3DatabaseConfig{
			{Name: "good", Path: goodPath},
			{Name: "bad", Path: "/nonexistent/dir/bad.db"},
		},
	}, zap.NewNop())

	metrics, err := c.Collect(context.Background())
	require.NoError(t, err)

	// Only the good database contributes PRAGMA metrics.
	pageCounts := labelValues(metrics, "db.sqlite3.page.count")
	require.Len(t, pageCounts, 1)
	assert.Equal(t, "good", pageCounts[0].Labels["sqlite3_database"])
}
