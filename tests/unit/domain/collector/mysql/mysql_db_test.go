// Package mysql_test contains sqlmock-driven unit tests for the MySQL collector.
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
//
// These tests use github.com/DATA-DOG/go-sqlmock exclusively. No live database,
// Docker, or network is used, so they are deterministic and hermetic.

package mysql_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	mysql "github.com/telemetryflow/telemetryflow-agent/internal/collector/mysql"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

var errBoom = errors.New("boom")

func newMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

// hasMetric returns true if a metric with the given name exists.
func hasMetric(metrics []collector.Metric, name string) bool {
	return findMetric(metrics, name) != nil
}

func testLabels() map[string]string { return map[string]string{"mysql_instance": "test"} }

// --- Global status ---------------------------------------------------------

func TestCollectGlobalStatus_Success(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Threads_connected", "42").
			AddRow("Queries", "1000").
			AddRow("Uptime", "notanumber"))

	rows, raw, err := mysql.CollectGlobalStatusExport(context.Background(), db)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if raw["Threads_connected"] != 42 || raw["Queries"] != 1000 {
		t.Errorf("raw parse wrong: %+v", raw)
	}
	if raw["Uptime"] != 0 {
		t.Errorf("non-numeric should parse to 0, got %d", raw["Uptime"])
	}
}

func TestCollectGlobalStatus_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS").WillReturnError(errBoom)
	if _, _, err := mysql.CollectGlobalStatusExport(context.Background(), db); err == nil {
		t.Fatal("expected error")
	}
}

// --- Global variables ------------------------------------------------------

func TestCollectGlobalVariables_Success(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL VARIABLES").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("max_connections", "500").
			AddRow("version", "8.0.35"))
	vars, err := mysql.CollectGlobalVariablesExport(context.Background(), db)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if vars["max_connections"] != "500" {
		t.Errorf("max_connections = %q", vars["max_connections"])
	}
}

func TestCollectGlobalVariables_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL VARIABLES").WillReturnError(errBoom)
	if _, err := mysql.CollectGlobalVariablesExport(context.Background(), db); err == nil {
		t.Fatal("expected error")
	}
}

// --- InnoDB status ---------------------------------------------------------

// The in-package parseInnoDBStatus treats lines ending in "===" as section
// boundaries and derives the section name from that same line, so section
// headers are written inline with the "===" suffix.
const innodbStatusText = `
BUFFER POOL===========================
Buffer pool size   8192
Free buffers       1024
Database pages     7000
Modified db pages  12
Number of read views 3
ROW OPERATIONS=======================
0 queries inside InnoDB, 5 queries in queue
END==================================
`

func TestCollectInnoDBStatus_Success(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ENGINE INNODB STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Type", "Name", "Status"}).
			AddRow("InnoDB", "", innodbStatusText))

	metrics, err := mysql.CollectInnoDBStatusExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.innodb.buffer_pool.pages.total") {
		t.Error("expected buffer_pool.pages.total")
	}
	if !hasMetric(metrics, "db.mysql.innodb.queries_in_queue") {
		t.Error("expected queries_in_queue")
	}
}

func TestCollectInnoDBStatus_NullStatus(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ENGINE INNODB STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Type", "Name", "Status"}).
			AddRow("InnoDB", "", nil))
	metrics, err := mysql.CollectInnoDBStatusExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if metrics != nil {
		t.Errorf("expected nil metrics on null status, got %d", len(metrics))
	}
}

func TestCollectInnoDBStatus_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ENGINE INNODB STATUS").WillReturnError(errBoom)
	if _, err := mysql.CollectInnoDBStatusExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseInnoDBPureHelpers(t *testing.T) {
	sections := mysql.ParseInnoDBStatusSectionsExport(innodbStatusText)
	if _, ok := sections["BUFFER POOL"]; !ok {
		t.Error("expected BUFFER POOL section")
	}
	bp := mysql.ParseBufferPoolSectionExport("Free buffers 1024\nDatabase pages 7000\nModified db pages 12\nNumber of read views 3\nbuffer pool size 100", testLabels())
	if len(bp) == 0 {
		t.Error("expected buffer pool metrics")
	}
	ro := mysql.ParseRowOperationsSectionExport("0 queries inside InnoDB, 5 queries in queue", testLabels())
	if len(ro) == 0 {
		t.Error("expected row op metrics")
	}
	if mysql.ExtractNumberExport("no numbers here") != -1 {
		t.Error("expected -1 for no numbers")
	}
	if mysql.ExtractNumberExport("value 55") != 55 {
		t.Error("expected 55")
	}
}

// --- Replication -----------------------------------------------------------

func TestCollectReplicationStatus_Success(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"Seconds_Behind_Master", "Slave_IO_Running", "Slave_SQL_Running", "Relay_Log_Space", "Retried_Transactions", "Last_Error", "Channel_Name"}
	mock.ExpectQuery("SHOW SLAVE STATUS").WillReturnRows(
		sqlmock.NewRows(cols).AddRow("5", "Yes", "Yes", "1024", "2", "some error", "chan1"))

	metrics, err := mysql.CollectReplicationStatusExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	lag := findMetric(metrics, "db.mysql.replication.lag_seconds")
	if lag == nil || lag.Value != 5 {
		t.Error("lag wrong")
	}
	io := findMetric(metrics, "db.mysql.replication.io_running")
	if io == nil || io.Value != 1 {
		t.Error("io_running wrong")
	}
	if !hasMetric(metrics, "db.mysql.replication.last_error") {
		t.Error("expected last_error metric")
	}
	if lag.Labels["replication_channel"] != "chan1" {
		t.Error("channel label missing")
	}
}

func TestCollectReplicationStatus_FallbackToReplica(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW SLAVE STATUS").WillReturnError(errBoom)
	mock.ExpectQuery("SHOW REPLICA STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Slave_IO_Running", "Slave_SQL_Running"}).AddRow("No", "No"))
	metrics, err := mysql.CollectReplicationStatusExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	io := findMetric(metrics, "db.mysql.replication.io_running")
	if io == nil || io.Value != 0 {
		t.Error("io_running should be 0")
	}
}

func TestCollectReplicationStatus_BothFail(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW SLAVE STATUS").WillReturnError(errBoom)
	mock.ExpectQuery("SHOW REPLICA STATUS").WillReturnError(errBoom)
	if _, err := mysql.CollectReplicationStatusExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestToStrExport(t *testing.T) {
	if mysql.ToStrExport(nil) != "" {
		t.Error("nil -> empty")
	}
	if mysql.ToStrExport("x") != "x" {
		t.Error("string")
	}
	if mysql.ToStrExport([]byte("y")) != "y" {
		t.Error("bytes")
	}
	if mysql.ToStrExport(42) != "" {
		t.Error("other -> empty")
	}
}

// --- Galera ----------------------------------------------------------------

func TestCollectGaleraStatus_Enabled(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("wsrep_on").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).AddRow("wsrep_on", "ON"))
	// 7 galera vars queried in map order (nondeterministic) + cluster status.
	for i := 0; i < 7; i++ {
		mock.ExpectQuery("SHOW GLOBAL STATUS LIKE").WillReturnRows(
			sqlmock.NewRows([]string{"Variable_name", "Value"}).AddRow("x", "3"))
	}
	mock.ExpectQuery("wsrep_cluster_status").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).AddRow("wsrep_cluster_status", "Primary"))

	metrics, err := mysql.CollectGaleraStatusExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(metrics) == 0 {
		t.Error("expected galera metrics")
	}
}

func TestCollectGaleraStatus_Disabled(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("wsrep_on").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).AddRow("wsrep_on", "OFF"))
	metrics, err := mysql.CollectGaleraStatusExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if metrics != nil {
		t.Error("expected nil when wsrep off")
	}
}

func TestCollectGaleraStatus_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("wsrep_on").WillReturnError(errBoom)
	if _, err := mysql.CollectGaleraStatusExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

// --- Schema ----------------------------------------------------------------

func TestCollectSchema_Success(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"TABLE_SCHEMA", "TABLE_NAME", "ENGINE", "TABLE_ROWS", "DATA_LENGTH", "INDEX_LENGTH", "DATA_FREE", "AUTO_INCREMENT"}
	mock.ExpectQuery("information_schema.TABLES").WillReturnRows(
		sqlmock.NewRows(cols).
			AddRow("appdb", "users", "InnoDB", 1000, 8192, 4096, 512, 42).
			AddRow(nil, "skip", "InnoDB", 1, 1, 1, 1, 1))

	metrics, err := mysql.CollectSchemaExport(context.Background(), db, config.MySQLInstanceConfig{}, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.schema.data_size") {
		t.Error("expected data_size")
	}
	if !hasMetric(metrics, "db.mysql.schema.auto_increment_usage") {
		t.Error("expected auto_increment_usage")
	}
}

func TestCollectSchema_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("information_schema.TABLES").WillReturnError(errBoom)
	if _, err := mysql.CollectSchemaExport(context.Background(), db, config.MySQLInstanceConfig{}, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestGetAutoIncrMax(t *testing.T) {
	if mysql.GetAutoIncrMaxExport("InnoDB") != 1<<63-1 {
		t.Error("innodb max wrong")
	}
	if mysql.GetAutoIncrMaxExport("MyISAM") != 1<<31-1 {
		t.Error("myisam max wrong")
	}
}

// --- Query analytics -------------------------------------------------------

func qanCols() []string {
	return []string{"DIGEST", "DIGEST_TEXT", "SCHEMA_NAME", "COUNT_STAR", "total_time_us",
		"SUM_ROWS_SENT", "SUM_ROWS_EXAMINED", "SUM_ROWS_AFFECTED", "SUM_CREATED_TMP_TABLES",
		"SUM_CREATED_TMP_DISK_TABLES", "SUM_NO_INDEX_USED", "SUM_SORT_ROWS", "FIRST_SEEN", "LAST_SEEN"}
}

func TestCollectQueryAnalytics_WithDelta(t *testing.T) {
	db, mock := newMock(t)
	inst := mysql.NewMySQLInstanceExport(config.MySQLInstanceConfig{Name: "i"}, "mysql", "8.0")
	mysql.SetPrevDigestExport(inst, "abc", 10, 1000, 5, 20)

	mock.ExpectQuery("setup_instruments").WillReturnRows(sqlmock.NewRows([]string{"c"}).AddRow(3))
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnRows(
		sqlmock.NewRows(qanCols()).
			AddRow("abc", "SELECT 1", "appdb", 20, 3000, 15, 40, 2, 1, 0, 0, 3, "t1", "t2").
			AddRow("noprev", "SELECT 2", "NULL", 5, 100, 1, 1, 0, 0, 0, 0, 0, "t1", "t2"))

	metrics, err := mysql.CollectQueryAnalyticsExport(context.Background(), db, inst, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.query.calls") {
		t.Error("expected query.calls for delta digest")
	}
}

func TestCollectQueryAnalytics_PerfSchemaDisabled(t *testing.T) {
	db, mock := newMock(t)
	inst := mysql.NewMySQLInstanceExport(config.MySQLInstanceConfig{Name: "i"}, "mysql", "8.0")
	mock.ExpectQuery("setup_instruments").WillReturnRows(sqlmock.NewRows([]string{"c"}).AddRow(0))
	metrics, err := mysql.CollectQueryAnalyticsExport(context.Background(), db, inst, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if metrics != nil {
		t.Error("expected nil when perf_schema disabled")
	}
}

func TestCollectQueryAnalytics_QueryError(t *testing.T) {
	db, mock := newMock(t)
	inst := mysql.NewMySQLInstanceExport(config.MySQLInstanceConfig{Name: "i"}, "mysql", "8.0")
	mock.ExpectQuery("setup_instruments").WillReturnRows(sqlmock.NewRows([]string{"c"}).AddRow(1))
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnError(errBoom)
	if _, err := mysql.CollectQueryAnalyticsExport(context.Background(), db, inst, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

// --- MariaDB ---------------------------------------------------------------

func TestDetectMariaDBEngines(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("information_schema.ENGINES").WillReturnRows(
		sqlmock.NewRows([]string{"ENGINE", "SUPPORT"}).
			AddRow("Aria", "YES").
			AddRow("Spider", "DEFAULT").
			AddRow("ColumnStore", "NO"))
	ext, err := mysql.DetectMariaDBEnginesExport(context.Background(), db)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ext.DetectedEngines()["Aria"] || !ext.DetectedEngines()["Spider"] {
		t.Error("expected Aria and Spider detected")
	}
	if ext.DetectedEngines()["ColumnStore"] {
		t.Error("ColumnStore should not be detected")
	}
}

func TestDetectMariaDBEngines_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("information_schema.ENGINES").WillReturnError(errBoom)
	if _, err := mysql.DetectMariaDBEnginesExport(context.Background(), db); err == nil {
		t.Fatal("expected error")
	}
}

func TestDetectMariaDBPlugins(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("information_schema.PLUGINS").WillReturnRows(
		sqlmock.NewRows([]string{"PLUGIN_NAME", "PLUGIN_STATUS"}).
			AddRow("userstat", "ACTIVE"))
	vars := map[string]string{"have_query_cache": "YES", "thread_handling": "pool-of-threads"}
	ext, err := mysql.DetectMariaDBPluginsExport(context.Background(), db, vars)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ext.QueryCacheEnabled() {
		t.Error("expected query cache enabled")
	}
	if !ext.DetectedPlugins()["userstat"] {
		t.Error("expected userstat plugin")
	}
}

func TestDetectMariaDBPlugins_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("information_schema.PLUGINS").WillReturnError(errBoom)
	if _, err := mysql.DetectMariaDBPluginsExport(context.Background(), db, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectMariaDBQueryCache(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Qcache_hits", "800").
			AddRow("Qcache_inserts", "200").
			AddRow("Qcache_free_blocks", "10").
			AddRow("Qcache_total_blocks", "100").
			AddRow("Qcache_free_memory", "1024").
			AddRow("Qcache_queries_in_cache", "50").
			AddRow("Qcache_lowmem_prunes", "1").
			AddRow("Qcache_not_cached", "5"))
	metrics, err := mysql.CollectMariaDBQueryCacheExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	hr := findMetric(metrics, "db.mysql.qcache.hit_ratio")
	if hr == nil || hr.Value != 0.8 {
		t.Errorf("hit_ratio wrong: %+v", hr)
	}
}

func TestCollectMariaDBQueryCache_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnError(errBoom)
	if _, err := mysql.CollectMariaDBQueryCacheExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectMariaDBAria(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ENGINE ARIA STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Type", "Name", "Status"}).
			AddRow("Aria", "Aria_pagecache_read_requests", "1000").
			AddRow("Aria", "Aria_pagecache_reads", "10").
			AddRow("Aria", "Aria_pagecache_blocks_used", "50").
			AddRow("Aria", "Aria_pagecache_blocks_unused", "5").
			AddRow("Aria", "Aria_pagecache_blocks_not_flushed", "2").
			AddRow("Aria", "Aria_pagecache_write_requests", "3").
			AddRow("Aria", "Aria_pagecache_writes", "1"))
	metrics, err := mysql.CollectMariaDBAriaExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.aria.pagecache.hit_ratio") {
		t.Error("expected aria hit_ratio")
	}
}

func TestCollectMariaDBAria_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ENGINE ARIA STATUS").WillReturnError(errBoom)
	if _, err := mysql.CollectMariaDBAriaExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectMariaDBColumnStore(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("columnstore_pm_cache_used").WillReturnRows(
		sqlmock.NewRows([]string{"variable_value"}).AddRow("123"))
	mock.ExpectQuery("columnstore_extents").WillReturnRows(
		sqlmock.NewRows([]string{"used", "total"}).AddRow(10.0, 20.0))
	metrics, err := mysql.CollectMariaDBColumnStoreExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.columnstore.extent.used") {
		t.Error("expected extent.used")
	}
}

func TestCollectMariaDBColumnStore_QueriesError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("columnstore_pm_cache_used").WillReturnError(errBoom)
	mock.ExpectQuery("columnstore_extents").WillReturnError(errBoom)
	metrics, err := mysql.CollectMariaDBColumnStoreExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err should be nil (soft-fail): %v", err)
	}
	if metrics != nil {
		t.Error("expected nil metrics")
	}
}

func TestCollectMariaDBSpider(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ENGINE SPIDER STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"spider_pool_conns", "spider_pool_total_conns", "spider_link_error_count", "spider_link_threads_running"}).
			AddRow("3", "10", "1", "2"))
	metrics, err := mysql.CollectMariaDBSpiderExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	used := findMetric(metrics, "db.mysql.spider.conn_pool.used")
	if used == nil || used.Value != 3 {
		t.Error("spider pool used wrong")
	}
}

func TestCollectMariaDBSpider_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ENGINE SPIDER STATUS").WillReturnError(errBoom)
	if _, err := mysql.CollectMariaDBSpiderExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectMariaDBThreadPool(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Threadpool_threads", "8").
			AddRow("Threadpool_active_threads", "4").
			AddRow("Threadpool_idle_threads", "4").
			AddRow("Threadpool_overflows", "1").
			AddRow("Threadpool_waits", "2").
			AddRow("Threadpool_queues", "3"))
	metrics, err := mysql.CollectMariaDBThreadPoolExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.threadpool.utilization") {
		t.Error("expected utilization")
	}
}

func TestCollectMariaDBThreadPool_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnError(errBoom)
	if _, err := mysql.CollectMariaDBThreadPoolExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectMariaDBMultiSourceReplication_AllSlaves(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"Connection_name", "Seconds_Behind_Master", "Slave_IO_Running", "Slave_SQL_Running"}
	mock.ExpectQuery("SHOW ALL SLAVES STATUS").WillReturnRows(
		sqlmock.NewRows(cols).AddRow("conn1", "3", "Yes", "Yes"))
	metrics, err := mysql.CollectMariaDBMultiSourceReplicationExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	lag := findMetric(metrics, "db.mysql.replication.lag_seconds")
	if lag == nil || lag.Labels["channel"] != "conn1" {
		t.Error("expected channel label conn1")
	}
}

func TestCollectMariaDBMultiSourceReplication_FallbackToStd(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW ALL SLAVES STATUS").WillReturnError(errBoom)
	mock.ExpectQuery("SHOW SLAVE STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Slave_IO_Running"}).AddRow("Yes"))
	metrics, err := mysql.CollectMariaDBMultiSourceReplicationExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.replication.io_running") {
		t.Error("expected fallback replication metrics")
	}
}

func TestCollectMariaDBUserStats(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"USER", "TOTAL_CONNECTIONS", "CONCURRENT_CONNECTIONS", "CPU_TIME", "ROWS_READ", "ROWS_SENT", "ROWS_INSERTED", "ROWS_UPDATED", "ROWS_DELETED", "BUSY_TIME", "SELECT_COMMANDS", "UPDATE_COMMANDS", "OTHER_COMMANDS"}
	mock.ExpectQuery("USER_STATISTICS").WillReturnRows(
		sqlmock.NewRows(cols).AddRow("root", 5.0, 1.0, 2.0, 100.0, 90.0, 3.0, 2.0, 1.0, 4.0, 50.0, 10.0, 5.0))
	metrics, err := mysql.CollectMariaDBUserStatsExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	w := findMetric(metrics, "db.mysql.userstats.rows_written")
	if w == nil || w.Value != 6 {
		t.Errorf("rows_written = %+v, want 6", w)
	}
}

func TestCollectMariaDBUserStats_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("USER_STATISTICS").WillReturnError(errBoom)
	if _, err := mysql.CollectMariaDBUserStatsExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

// --- Percona ---------------------------------------------------------------

func TestDetectPerconaPlugins(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("information_schema.PLUGINS").WillReturnRows(
		sqlmock.NewRows([]string{"PLUGIN_NAME", "PLUGIN_STATUS"}).
			AddRow("QUERY_RESPONSE_TIME", "ACTIVE").
			AddRow("USERSTAT", "ACTIVE").
			AddRow("audit_log", "DISABLED"))
	ext, err := mysql.DetectPerconaPluginsExport(context.Background(), db)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ext.QueryResponseTimeEnabled() {
		t.Error("expected QRT enabled")
	}
	if ext.DetectedPlugins()["audit_log"] {
		t.Error("audit_log should not be active")
	}
}

func TestDetectPerconaPlugins_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("information_schema.PLUGINS").WillReturnError(errBoom)
	if _, err := mysql.DetectPerconaPluginsExport(context.Background(), db); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectPerconaQueryResponseTime(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("query_response_time_appliers").WillReturnRows(
		sqlmock.NewRows([]string{"time", "count", "total"}).
			AddRow("0.000010", 100, 0.5).
			AddRow("0.001000", 50, 0.4).
			AddRow("1.000000", 10, 5.0))
	metrics, err := mysql.CollectPerconaQueryResponseTimeExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.query_response_time.p50") {
		t.Error("expected p50")
	}
}

func TestCollectPerconaQueryResponseTime_Fallback(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("query_response_time_appliers").WillReturnError(errBoom)
	mock.ExpectQuery("QUERY_RESPONSE_TIME").WillReturnRows(
		sqlmock.NewRows([]string{"time", "count", "total"}).AddRow("0.001", 5, 0.1))
	metrics, err := mysql.CollectPerconaQueryResponseTimeExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(metrics) == 0 {
		t.Error("expected metrics from fallback")
	}
}

func TestCollectPerconaQueryResponseTime_BothFail(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("query_response_time_appliers").WillReturnError(errBoom)
	mock.ExpectQuery("QUERY_RESPONSE_TIME").WillReturnError(errBoom)
	if _, err := mysql.CollectPerconaQueryResponseTimeExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectPerconaUserStats(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"USER", "TOTAL_CONNECTIONS", "CONCURRENT_CONNECTIONS", "CPU_TIME", "ROWS_READ", "ROWS_SENT", "ROWS_INSERTED", "ROWS_UPDATED", "ROWS_DELETED", "BUSY_TIME", "SELECT_COMMANDS", "UPDATE_COMMANDS", "OTHER_COMMANDS"}
	mock.ExpectQuery("USER_STATISTICS").WillReturnRows(
		sqlmock.NewRows(cols).AddRow("app", 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0))
	metrics, err := mysql.CollectPerconaUserStatsExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.userstats.total_connections") {
		t.Error("expected userstats metric")
	}
}

func TestCollectPerconaUserStats_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("USER_STATISTICS").WillReturnError(errBoom)
	if _, err := mysql.CollectPerconaUserStatsExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectPerconaThreadPool(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Threadpool_threads", "8").
			AddRow("Threadpool_active_threads", "4").
			AddRow("Threadpool_idle_threads", "4").
			AddRow("Threadpool_overflows", "1").
			AddRow("Threadpool_waits", "2").
			AddRow("Threadpool_queues", "3").
			AddRow("Threadpool_high_prio_threads", "1").
			AddRow("Threadpool_high_prio_overflows", "0"))
	metrics, err := mysql.CollectPerconaThreadPoolExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.threadpool.high_prio_threads") {
		t.Error("expected high_prio_threads")
	}
}

func TestCollectPerconaThreadPool_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnError(errBoom)
	if _, err := mysql.CollectPerconaThreadPoolExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectPerconaPXC_Enabled(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("wsrep_local_state", "4").
			AddRow("wsrep_cluster_status", "0").
			AddRow("wsrep_flow_control_paused", "0.1").
			AddRow("wsrep_local_commits", "100").
			AddRow("wsrep_local_cert_failures", "2").
			AddRow("wsrep_replicated_bytes", "5000").
			AddRow("wsrep_received_bytes", "6000"))
	vars := map[string]string{"wsrep_on": "ON"}
	metrics, err := mysql.CollectPerconaPXCExport(context.Background(), db, nil, vars, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	h := findMetric(metrics, "db.mysql.pxc.cluster_health")
	if h == nil || h.Value != 1 {
		t.Error("expected cluster_health 1")
	}
}

func TestCollectPerconaPXC_Disabled(t *testing.T) {
	db, _ := newMock(t)
	metrics, err := mysql.CollectPerconaPXCExport(context.Background(), db, nil, map[string]string{"wsrep_on": "OFF"}, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if metrics != nil {
		t.Error("expected nil when wsrep off")
	}
}

func TestCollectPerconaPXC_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnError(errBoom)
	if _, err := mysql.CollectPerconaPXCExport(context.Background(), db, nil, map[string]string{"wsrep_on": "ON"}, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectPerconaXtraBackup(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("COUNT.*INNODB_CHANGED_PAGES").WillReturnRows(
		sqlmock.NewRows([]string{"c"}).AddRow(42.0))
	mock.ExpectQuery("MIN.LAST_LSN").WillReturnRows(
		sqlmock.NewRows([]string{"lsn"}).AddRow(1000.0))
	metrics, err := mysql.CollectPerconaXtraBackupExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.xtrabackup.changed_pages") {
		t.Error("expected changed_pages")
	}
	if !hasMetric(metrics, "db.mysql.xtrabackup.oldest_lsn") {
		t.Error("expected oldest_lsn")
	}
}

func TestCollectPerconaXtraBackup_QueriesError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("INNODB_CHANGED_PAGES").WillReturnError(errBoom)
	mock.ExpectQuery("INNODB_CHANGED_PAGES").WillReturnError(errBoom)
	metrics, err := mysql.CollectPerconaXtraBackupExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err should be nil: %v", err)
	}
	if metrics != nil {
		t.Error("expected nil metrics")
	}
}

func TestCollectPerconaAudit(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Audit_log_events", "10").
			AddRow("Audit_log_events_filtered", "2").
			AddRow("Audit_log_events_lost", "0").
			AddRow("Audit_log_events_written", "8").
			AddRow("Audit_log_size", "1024"))
	metrics, err := mysql.CollectPerconaAuditExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.audit.log_size") {
		t.Error("expected audit log_size")
	}
}

func TestCollectPerconaAudit_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnError(errBoom)
	if _, err := mysql.CollectPerconaAuditExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectPerconaEnhancedSlowQuery(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"DIGEST", "SCHEMA_NAME", "SUM_ROWS_SENT", "SUM_ROWS_EXAMINED", "SUM_ROWS_AFFECTED", "SUM_CREATED_TMP_TABLES", "SUM_CREATED_TMP_DISK_TABLES", "SUM_NO_INDEX_USED", "SUM_SORT_ROWS", "COUNT_STAR"}
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnRows(
		sqlmock.NewRows(cols).
			AddRow("d1", "appdb", 10, 100, 5, 2, 3, 1, 4, 20).
			AddRow("d2", "NULL", 0, 0, 0, 0, 0, 0, 0, 0))
	metrics, err := mysql.CollectPerconaEnhancedSlowQueryExport(context.Background(), db, testLabels())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.query.full_scan") {
		t.Error("expected full_scan indicator")
	}
	if !hasMetric(metrics, "db.mysql.query.full_join") {
		t.Error("expected full_join indicator")
	}
}

func TestCollectPerconaEnhancedSlowQuery_QueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnError(errBoom)
	if _, err := mysql.CollectPerconaEnhancedSlowQueryExport(context.Background(), db, testLabels()); err == nil {
		t.Fatal("expected error")
	}
}

// --- Flavor detection ------------------------------------------------------

func newSingleInstanceCollector() *mysql.MySQLCollector {
	return mysql.NewMySQLCollector(config.MySQLCollectorConfig{
		Instances: []config.MySQLInstanceConfig{{Name: "i", Host: "h"}},
	}, zap.NewNop())
}

func TestDetectFlavor(t *testing.T) {
	tests := []struct {
		version string
		flavor  string
	}{
		{"8.0.35", "mysql"},
		{"10.6.12-MariaDB", "mariadb"},
		{"8.0.34-26 Percona Server", "percona"},
	}
	for _, tc := range tests {
		t.Run(tc.flavor, func(t *testing.T) {
			c := newSingleInstanceCollector()
			db, mock := newMock(t)
			mock.ExpectQuery("VERSION").WillReturnRows(
				sqlmock.NewRows([]string{"v"}).AddRow(tc.version))
			flavor, version, err := mysql.DetectFlavorExport(c, context.Background(), db)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if flavor != tc.flavor {
				t.Errorf("flavor = %q, want %q", flavor, tc.flavor)
			}
			if version != tc.version {
				t.Errorf("version = %q", version)
			}
		})
	}
}

func TestDetectFlavor_QueryError(t *testing.T) {
	c := newSingleInstanceCollector()
	db, mock := newMock(t)
	mock.ExpectQuery("VERSION").WillReturnError(errBoom)
	if _, _, err := mysql.DetectFlavorExport(c, context.Background(), db); err == nil {
		t.Fatal("expected error")
	}
}

// --- ensureConnection / backoff -------------------------------------------

func TestEnsureConnection_BackoffAfterFailure(t *testing.T) {
	c := newSingleInstanceCollector()
	// First call: no db injected -> sql.Open("mysql", ...) with unregistered
	// driver or ping failure triggers advanceBackoff and returns an error.
	if err := mysql.EnsureConnectionErrExport(c, context.Background()); err == nil {
		t.Fatal("expected connection error")
	}
	// Second call immediately: should be short-circuited by backoff window.
	if err := mysql.EnsureConnectionErrExport(c, context.Background()); err == nil {
		t.Fatal("expected backoff error")
	}
}

func TestAdvanceBackoff(t *testing.T) {
	c := newSingleInstanceCollector()
	// Multiple advances should not panic and should cap at 60s internally.
	for i := 0; i < 10; i++ {
		mysql.AdvanceBackoffExport(c)
	}
}

// --- collectInstance / Collect integration ---------------------------------

func TestCollectInstance_MariaDBFlavor(t *testing.T) {
	c := newSingleInstanceCollector()
	db, mock := newMock(t)
	mysql.SetInstanceDBExport(c, db)
	mysql.SetInstanceFlavorExport(c, "mariadb")
	mysql.PrimeMariaDBExport(c)

	// detectFlavor consumes SELECT VERSION(); remaining queries return errors
	// which the collector tolerates as warnings while still executing all paths.
	mock.ExpectQuery("VERSION").WillReturnRows(
		sqlmock.NewRows([]string{"v"}).AddRow("10.6-MariaDB"))
	mock.MatchExpectationsInOrder(false)

	metrics, err := mysql.CollectInstanceExport(c, context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Derived metrics are always emitted regardless of query failures.
	if !hasMetric(metrics, "db.mysql.innodb.buffer_pool.hit_ratio") {
		t.Error("expected derived hit_ratio metric")
	}
}

func TestCollectInstance_MySQLSuccessPaths(t *testing.T) {
	c := newSingleInstanceCollector()
	db, mock := newMock(t)
	mysql.SetInstanceDBExport(c, db)
	mysql.SetInstanceFlavorExport(c, "mysql")
	// Preseed prevStatus so the rate-computation branch is exercised.
	mysql.SetInstancePrevStatusExport(c, map[string]uint64{"Queries": 500, "Threads_connected": 10})

	mock.ExpectQuery("VERSION").WillReturnRows(sqlmock.NewRows([]string{"v"}).AddRow("8.0.35"))
	mock.ExpectQuery("SHOW GLOBAL STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Threads_connected", "42").
			AddRow("Threads_running", "5").
			AddRow("Queries", "1500").
			AddRow("Innodb_buffer_pool_read_requests", "10000").
			AddRow("Innodb_buffer_pool_reads", "50"))
	mock.ExpectQuery("SHOW GLOBAL VARIABLES").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("max_connections", "200").
			AddRow("innodb_buffer_pool_size", "1073741824"))
	mock.ExpectQuery("SHOW ENGINE INNODB STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Type", "Name", "Status"}).AddRow("InnoDB", "", innodbStatusText))
	mock.ExpectQuery("SHOW SLAVE STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Seconds_Behind_Master", "Slave_IO_Running", "Slave_SQL_Running"}).
			AddRow("0", "Yes", "Yes"))
	mock.ExpectQuery("wsrep_on").WillReturnRows(
		sqlmock.NewRows([]string{"Variable_name", "Value"}).AddRow("wsrep_on", "OFF"))

	metrics, err := mysql.CollectInstanceExport(c, context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !hasMetric(metrics, "db.mysql.threads.connected") {
		t.Error("expected gauge metric")
	}
	if !hasMetric(metrics, "db.mysql.queries.total") {
		t.Error("expected rate metric")
	}
	if !hasMetric(metrics, "db.mysql.connections.max") {
		t.Error("expected variable metric")
	}
}

func TestCollectInstance_PerconaFlavor(t *testing.T) {
	c := newSingleInstanceCollector()
	db, mock := newMock(t)
	mysql.SetInstanceDBExport(c, db)
	mysql.SetInstanceFlavorExport(c, "percona")
	mysql.PrimePerconaExport(c)

	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery("VERSION").WillReturnRows(
		sqlmock.NewRows([]string{"v"}).AddRow("8.0-Percona"))

	if _, err := mysql.CollectInstanceExport(c, context.Background()); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestCollectMariaDB_WithDetection(t *testing.T) {
	c := newSingleInstanceCollector()
	db, mock := newMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery("information_schema.ENGINES").WillReturnRows(
		sqlmock.NewRows([]string{"ENGINE", "SUPPORT"}).
			AddRow("Aria", "YES").AddRow("Spider", "YES").AddRow("ColumnStore", "YES"))
	mock.ExpectQuery("information_schema.PLUGINS").WillReturnRows(
		sqlmock.NewRows([]string{"PLUGIN_NAME", "PLUGIN_STATUS"}).AddRow("userstat", "ACTIVE"))
	// Provide successful sub-collector responses to exercise append branches.
	gs := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"Variable_name", "Value"}).AddRow("Threadpool_threads", "8").AddRow("Qcache_hits", "1")
	}
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(gs()) // query cache
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(gs()) // thread pool
	mock.ExpectQuery("SHOW ENGINE ARIA STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Type", "Name", "Status"}).AddRow("Aria", "Aria_pagecache_reads", "1"))
	mock.ExpectQuery("columnstore_pm_cache_used").WillReturnRows(sqlmock.NewRows([]string{"v"}).AddRow("1"))
	mock.ExpectQuery("columnstore_extents").WillReturnRows(sqlmock.NewRows([]string{"used", "total"}).AddRow(1.0, 2.0))
	mock.ExpectQuery("SHOW ENGINE SPIDER STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"spider_pool_conns"}).AddRow("1"))
	mock.ExpectQuery("SHOW ALL SLAVES STATUS").WillReturnRows(
		sqlmock.NewRows([]string{"Slave_IO_Running"}).AddRow("Yes"))
	usCols := []string{"USER", "TOTAL_CONNECTIONS", "CONCURRENT_CONNECTIONS", "CPU_TIME", "ROWS_READ", "ROWS_SENT", "ROWS_INSERTED", "ROWS_UPDATED", "ROWS_DELETED", "BUSY_TIME", "SELECT_COMMANDS", "UPDATE_COMMANDS", "OTHER_COMMANDS"}
	mock.ExpectQuery("USER_STATISTICS").WillReturnRows(
		sqlmock.NewRows(usCols).AddRow("root", 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0))
	vars := map[string]string{"have_query_cache": "YES", "thread_handling": "pool-of-threads"}
	metrics := mysql.CollectMariaDBExport(c, context.Background(), db, testLabels(), vars)
	if len(metrics) == 0 {
		t.Error("expected mariadb metrics from success paths")
	}
}

func TestCollectPercona_WithDetection(t *testing.T) {
	c := newSingleInstanceCollector()
	db, mock := newMock(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery("information_schema.PLUGINS").WillReturnRows(
		sqlmock.NewRows([]string{"PLUGIN_NAME", "PLUGIN_STATUS"}).
			AddRow("QUERY_RESPONSE_TIME", "ACTIVE").
			AddRow("USERSTAT", "ACTIVE").
			AddRow("audit_log", "ACTIVE"))
	// QRT
	mock.ExpectQuery("query_response_time_appliers").WillReturnRows(
		sqlmock.NewRows([]string{"time", "count", "total"}).AddRow("0.001", 5, 0.1))
	usCols := []string{"USER", "TOTAL_CONNECTIONS", "CONCURRENT_CONNECTIONS", "CPU_TIME", "ROWS_READ", "ROWS_SENT", "ROWS_INSERTED", "ROWS_UPDATED", "ROWS_DELETED", "BUSY_TIME", "SELECT_COMMANDS", "UPDATE_COMMANDS", "OTHER_COMMANDS"}
	mock.ExpectQuery("USER_STATISTICS").WillReturnRows(
		sqlmock.NewRows(usCols).AddRow("root", 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0))
	gs := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Threadpool_threads", "8").
			AddRow("wsrep_local_state", "4").
			AddRow("Audit_log_events", "1")
	}
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(gs()) // thread pool
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(gs()) // pxc
	mock.ExpectQuery("SHOW GLOBAL STATUS WHERE").WillReturnRows(gs()) // audit
	mock.ExpectQuery("INNODB_CHANGED_PAGES").WillReturnRows(sqlmock.NewRows([]string{"c"}).AddRow(1.0))
	mock.ExpectQuery("INNODB_CHANGED_PAGES").WillReturnRows(sqlmock.NewRows([]string{"lsn"}).AddRow(1.0))
	esqCols := []string{"DIGEST", "SCHEMA_NAME", "SUM_ROWS_SENT", "SUM_ROWS_EXAMINED", "SUM_ROWS_AFFECTED", "SUM_CREATED_TMP_TABLES", "SUM_CREATED_TMP_DISK_TABLES", "SUM_NO_INDEX_USED", "SUM_SORT_ROWS", "COUNT_STAR"}
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnRows(
		sqlmock.NewRows(esqCols).AddRow("d1", "appdb", 1, 1, 1, 1, 1, 1, 1, 5))
	vars := map[string]string{
		"log_slow_extra":     "ON",
		"log_slow_verbosity": "query_plan",
		"wsrep_on":           "ON",
		"thread_handling":    "pool-of-threads",
	}
	metrics := mysql.CollectPerconaExport(c, context.Background(), db, testLabels(), vars, map[string]uint64{})
	if len(metrics) == 0 {
		t.Error("expected percona metrics from success paths")
	}
}

func TestUnusedConstructorExports(t *testing.T) {
	cfg := mysql.NewConfigExport(config.MySQLCollectorConfig{})
	_ = cfg
	b := mysql.NewQrtBucketExport("<1", 5)
	if b.TimeRange != "<1" || b.Count != 5 {
		t.Error("qrt bucket export wrong")
	}
}

func TestCollect_InstanceConnectionError(t *testing.T) {
	c := newSingleInstanceCollector()
	// Force the instance into a back-off window so every ensureConnection call
	// fails immediately without network I/O. This drives the error/continue
	// branches in Collect, collectAllQueryAnalytics and collectAllSchema.
	mysql.AdvanceBackoffExport(c)
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should aggregate errors, got: %v", err)
	}
	if m != nil {
		t.Errorf("expected no metrics, got %d", len(m))
	}
}

func TestCollect_NoInstances(t *testing.T) {
	c := mysql.NewMySQLCollector(config.MySQLCollectorConfig{}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if m != nil {
		t.Error("expected nil metrics with no instances")
	}
}

func TestCollect_WithInjectedInstance(t *testing.T) {
	c := newSingleInstanceCollector()
	db, mock := newMock(t)
	mysql.SetInstanceDBExport(c, db)
	mock.MatchExpectationsInOrder(false)
	// Queries can fail; Collect must aggregate without returning an error.
	mock.ExpectQuery("VERSION").WillReturnRows(
		sqlmock.NewRows([]string{"v"}).AddRow("8.0.35"))
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect err: %v", err)
	}
}

// --- Lifecycle -------------------------------------------------------------

func TestCollectorLifecycle(t *testing.T) {
	c := newSingleInstanceCollector()
	db, _ := newMock(t)
	mysql.SetInstanceDBExport(c, db) // exercise the db-close branch in Stop
	if c.IsRunning() {
		t.Error("should not be running")
	}
	// Start blocks until ctx cancel; run it in the background.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	// Give Start a moment to flip running; then cancel.
	for i := 0; i < 1000 && !c.IsRunning(); i++ {
	}
	cancel()
	<-done
	if err := c.Stop(); err != nil {
		t.Errorf("Stop err: %v", err)
	}
	// Second stop is a no-op.
	if err := c.Stop(); err != nil {
		t.Errorf("Stop (2) err: %v", err)
	}
}

func TestCollectorStart_AlreadyRunning(t *testing.T) {
	c := newSingleInstanceCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Start(ctx) }()
	for i := 0; i < 100000 && !c.IsRunning(); i++ {
	}
	if err := c.Start(ctx); err == nil {
		t.Error("expected already-running error")
	}
	cancel()
}

// --- QAN collector ---------------------------------------------------------

func qanPerfCols() []string {
	return []string{"DIGEST_TEXT", "COUNT_STAR", "SUM_TIMER_WAIT", "MIN_TIMER_WAIT", "MAX_TIMER_WAIT",
		"SUM_LOCK_TIME", "SUM_ROWS_SENT", "SUM_ROWS_EXAMINED", "SUM_ROWS_AFFECTED",
		"SUM_CREATED_TMP_TABLES", "SUM_CREATED_TMP_DISK_TABLES", "SUM_MERGE_PASSES",
		"SUM_NO_INDEX_USED", "SUM_NO_GOOD_INDEX_USED"}
}

func TestQANCollector_Lifecycle(t *testing.T) {
	c := mysql.NewQANMySQLCollector(mysql.QANMySQLConfig{
		Instances: []config.MySQLInstanceConfig{{Name: "i"}},
	}, zap.NewNop())
	db, _ := newMock(t)
	mysql.SetQANInstanceDBExport(c, db) // exercise db-close branch in Stop
	if c.Name() != "qan-mysql-perfschema" {
		t.Errorf("name = %q", c.Name())
	}
	if c.AgentType() == "" {
		t.Error("expected agent type")
	}
	if c.IsRunning() {
		t.Error("should not be running")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !c.IsRunning() {
		t.Error("should be running")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Error("expected already-running error")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("stop 2: %v", err)
	}
	// No instances -> nil buckets.
	b, err := c.CollectQAN(context.Background())
	if err != nil || b != nil {
		t.Errorf("expected nil buckets, got %v err %v", b, err)
	}
}

func TestQANCollector_CollectDelta(t *testing.T) {
	c := mysql.NewQANMySQLCollector(mysql.QANMySQLConfig{
		Instances: []config.MySQLInstanceConfig{{Name: "i", Host: "h"}},
		Labels:    map[string]string{"env": "test"},
	}, zap.NewNop())
	db, mock := newMock(t)
	mysql.SetQANInstanceDBExport(c, db)

	row := func(count uint64) *sqlmock.Rows {
		return sqlmock.NewRows(qanPerfCols()).
			AddRow("SELECT * FROM t", count, 2000000000000, 100, 5000000000000,
				1000, 50, 200, 10, 1, 0, 0, 0, 0)
	}
	// First collect: no prev -> establishes baseline.
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnRows(row(10))
	// Second collect: higher counter -> emits a delta bucket.
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnRows(row(30))

	if _, err := c.CollectQAN(context.Background()); err != nil {
		t.Fatalf("first collect: %v", err)
	}
	buckets, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("second collect: %v", err)
	}
	if len(buckets) == 0 {
		t.Error("expected delta buckets on second collect")
	}
}

func TestQANCollector_QueryError(t *testing.T) {
	c := mysql.NewQANMySQLCollector(mysql.QANMySQLConfig{
		Instances: []config.MySQLInstanceConfig{{Name: "i"}},
	}, zap.NewNop())
	db, mock := newMock(t)
	mysql.SetQANInstanceDBExport(c, db)
	mock.ExpectQuery("events_statements_summary_by_digest").WillReturnError(errBoom)
	// Instance error is logged and swallowed; CollectQAN returns nil error.
	if _, err := c.CollectQAN(context.Background()); err != nil {
		t.Fatalf("expected swallowed err, got %v", err)
	}
}

func TestQANCollector_ConnectionError(t *testing.T) {
	// No db injected: ensureConnection calls sql.Open("mysql", ...) which fails
	// because the mysql driver is not registered in the test binary. The error
	// is logged and swallowed by CollectQAN.
	c := mysql.NewQANMySQLCollector(mysql.QANMySQLConfig{
		Instances: []config.MySQLInstanceConfig{{Name: "i", Host: "127.0.0.1", Port: 1}},
	}, zap.NewNop())
	b, err := c.CollectQAN(context.Background())
	if err != nil {
		t.Fatalf("expected swallowed err, got %v", err)
	}
	if b != nil {
		t.Error("expected nil buckets")
	}
}

func TestQANCollector_NilLoggerAndDefaults(t *testing.T) {
	// nil logger triggers the zap.NewProduction() fallback; zero TopQueriesLimit
	// triggers the default of 200.
	c := mysql.NewQANMySQLCollector(mysql.QANMySQLConfig{
		Instances: []config.MySQLInstanceConfig{{Name: "i"}},
	}, nil)
	if c == nil {
		t.Fatal("expected collector")
	}
	if c.Name() != "qan-mysql-perfschema" {
		t.Error("name wrong")
	}
}

func TestCollectGlobalStatus_ScanErrorSkipped(t *testing.T) {
	db, mock := newMock(t)
	rows := sqlmock.NewRows([]string{"Variable_name", "Value"}).
		AddRow("ok", "1").
		AddRow("bad", "2").RowError(1, errBoom)
	mock.ExpectQuery("SHOW GLOBAL STATUS").WillReturnRows(rows)
	out, _, err := mysql.CollectGlobalStatusExport(context.Background(), db)
	if err == nil {
		t.Fatal("expected rows.Err propagated")
	}
	if len(out) != 1 {
		t.Errorf("expected 1 good row, got %d", len(out))
	}
}

func TestFingerprintMySQL(t *testing.T) {
	a := mysql.FingerprintMySQLExport("SELECT * FROM t")
	b := mysql.FingerprintMySQLExport("select   *   from t")
	if a != b {
		t.Error("normalised fingerprints should match")
	}
	if len(a) != 32 {
		t.Errorf("fingerprint len = %d, want 32", len(a))
	}
}
