// Package mssql white-box coverage tests.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// These tests live in-package (white-box) because the collector query
// functions are unexported and accept *sql.DB. They are exercised with
// github.com/DATA-DOG/go-sqlmock. No production code is modified.

package mssql

import (
	"context"
	"database/sql"
	"math"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/qan"
)

func newMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func nop() *zap.Logger { return zap.NewNop() }

func baseLabels() map[string]string {
	return map[string]string{"mssql_instance": "inst1", "mssql_host": "h1"}
}

func findMetric(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

// ---------- helpers.go ----------

func TestSafeDiv(t *testing.T) {
	assert.Equal(t, 5.0, safeDiv(10, 2))
	assert.Equal(t, 0.0, safeDiv(10, 0))
	assert.Equal(t, 0.0, safeDiv(0, 0))
}

func TestMakeMetric(t *testing.T) {
	m := makeMetric("m.name", 3.5, collector.MetricTypeGauge, map[string]string{"a": "b"})
	assert.Equal(t, "m.name", m.Name)
	assert.Equal(t, 3.5, m.Value)
	assert.Equal(t, collector.MetricTypeGauge, m.Type)
	assert.Equal(t, "b", m.Labels["a"])
	assert.False(t, m.Timestamp.IsZero())
}

func TestParseFloat(t *testing.T) {
	assert.Equal(t, 1.5, parseFloat(1.5))
	assert.Equal(t, 2.0, parseFloat(float32(2)))
	assert.Equal(t, 3.0, parseFloat(int64(3)))
	assert.Equal(t, 4.0, parseFloat(4))
	assert.Equal(t, 5.0, parseFloat("5"))
	assert.Equal(t, 0.0, parseFloat("nope"))
	assert.Equal(t, 0.0, parseFloat(struct{}{}))
}

func TestEmitCounterRate(t *testing.T) {
	m := emitCounterRate("r", math.NaN(), nil)
	assert.Equal(t, 0.0, m.Value)
	m = emitCounterRate("r", math.Inf(1), nil)
	assert.Equal(t, 0.0, m.Value)
	m = emitCounterRate("r", 7, nil)
	assert.Equal(t, 7.0, m.Value)
}

func TestInstanceLabels(t *testing.T) {
	inst := &mssqlInstance{
		config: config.MSSQLInstanceConfig{
			Name: "n", Host: "h", InstanceName: "SQLEXPRESS",
			Tags: map[string]string{"env": "prod"},
		},
		version: "16.0",
	}
	l := instanceLabels(inst)
	assert.Equal(t, "n", l["mssql_instance"])
	assert.Equal(t, "h", l["mssql_host"])
	assert.Equal(t, "16.0", l["mssql_version"])
	assert.Equal(t, "SQLEXPRESS", l["mssql_instance_name"])
	assert.Equal(t, "prod", l["env"])

	// no version, no instance name
	l2 := instanceLabels(&mssqlInstance{config: config.MSSQLInstanceConfig{Name: "x", Host: "y"}})
	_, hasVer := l2["mssql_version"]
	assert.False(t, hasVer)
}

func TestCopyLabels(t *testing.T) {
	src := map[string]string{"a": "1"}
	dst := copyLabels(src)
	dst["a"] = "2"
	assert.Equal(t, "1", src["a"])
}

// ---------- config.go ----------

func TestNewConfigDefaults(t *testing.T) {
	c := NewConfig(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	})
	assert.Equal(t, 15*time.Second, c.MetricsInterval)
	assert.Equal(t, 60*time.Second, c.QueryInterval)
	assert.Equal(t, 300*time.Second, c.IndexInterval)
	assert.Equal(t, 3, c.MaxConnections)
	assert.Equal(t, 50, c.TopQueriesLimit)

	inst := c.Instances[0]
	assert.Equal(t, "localhost", inst.Host)
	assert.Equal(t, 1433, inst.Port)
	assert.Equal(t, "sql_server", inst.AuthType)
	assert.Equal(t, "sa", inst.Username)
	assert.Equal(t, "master", inst.Database)
	assert.Equal(t, "true", inst.Encrypt)
	assert.Equal(t, 15, inst.CollectionIntervalSeconds)
}

func TestNewConfigOverrides(t *testing.T) {
	c := NewConfig(config.MSSQLCollectorConfig{
		MetricsInterval: time.Second, QueryInterval: 2 * time.Second,
		IndexInterval: 3 * time.Second, MaxConnections: 9, TopQueriesLimit: 11,
		Instances: []config.MSSQLInstanceConfig{{
			Name: "i", Host: "db", Port: 1444, AuthType: "windows_ntlm",
			Username: "u", Database: "app", Encrypt: "strict", CollectionIntervalSeconds: 30,
		}},
	})
	assert.Equal(t, time.Second, c.MetricsInterval)
	assert.Equal(t, 9, c.MaxConnections)
	assert.Equal(t, "db", c.Instances[0].Host)
	assert.Equal(t, "windows_ntlm", c.Instances[0].AuthType)
	assert.Equal(t, "u", c.Instances[0].Username)
}

// ---------- connection.go ----------

func TestResolveEnvVars(t *testing.T) {
	t.Setenv("MSSQL_PW", "secret")
	assert.Equal(t, "secret", resolveEnvVars("${MSSQL_PW}"))
	assert.Equal(t, "fallback", resolveEnvVars("${MSSQL_MISSING:-fallback}"))
	assert.Equal(t, "", resolveEnvVars("${MSSQL_MISSING}"))
	assert.Equal(t, "plain", resolveEnvVars("plain"))
	assert.Equal(t, "prefix-secret", resolveEnvVars("prefix-${MSSQL_PW}"))
}

func TestFindDefaultSep(t *testing.T) {
	assert.True(t, findDefaultSep("VAR:-def") >= 0)
	assert.Equal(t, -1, findDefaultSep("VAR"))
}

func TestBuildConnString(t *testing.T) {
	dsn := buildConnString(config.MSSQLInstanceConfig{
		Username: "sa", Password: "pw", Host: "h", Port: 1433,
		Database: "master", Encrypt: "true", TrustServerCertificate: true,
	})
	assert.Contains(t, dsn, "sqlserver://sa:pw@h:1433")
	assert.Contains(t, dsn, "database=master")

	dsnNamed := buildConnString(config.MSSQLInstanceConfig{
		Username: "sa", Password: "pw", Host: "h", Port: 1433,
		InstanceName: "SQLEXPRESS", Database: "master", Encrypt: "true",
	})
	assert.Contains(t, dsnNamed, "instanceName=SQLEXPRESS")
}

func TestHostPort(t *testing.T) {
	assert.Equal(t, "h:1", hostPort(config.MSSQLInstanceConfig{Host: "h", Port: 1}))
}

func TestEnsureConnectionExistingDB(t *testing.T) {
	db, _ := newMock(t)
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	inst := c.instances[0]
	inst.db = db
	got, err := c.ensureConnection(context.Background(), inst)
	require.NoError(t, err)
	assert.Equal(t, db, got)
}

func TestEnsureConnectionBackoff(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	inst := c.instances[0]
	inst.lastConnErr = time.Now()
	inst.backoff = 30 * time.Second
	_, err := c.ensureConnection(context.Background(), inst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "back-off")
}

func TestEnsureConnectionBackoffZeroWait(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	inst := c.instances[0]
	inst.lastConnErr = time.Now()
	inst.backoff = 0
	_, err := c.ensureConnection(context.Background(), inst)
	require.Error(t, err)
}

func TestCloseConnection(t *testing.T) {
	db, _ := newMock(t)
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	inst := c.instances[0]
	inst.db = db
	c.closeConnection(inst)
	assert.Nil(t, inst.db)
	c.closeConnection(inst) // idempotent
}

func TestAdvanceBackoff(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	inst := c.instances[0]
	c.advanceBackoff(inst)
	assert.Equal(t, time.Second, inst.backoff)
	c.advanceBackoff(inst)
	assert.Equal(t, 2*time.Second, inst.backoff)
	inst.backoff = 40 * time.Second
	c.advanceBackoff(inst)
	assert.Equal(t, 60*time.Second, inst.backoff) // capped
}

// ---------- mssql.go ----------

func TestCollectorLifecycle(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	assert.Equal(t, "mssql", c.Name())
	assert.False(t, c.IsRunning())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	// wait until running
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)

	// double start
	require.Error(t, c.Start(context.Background()))

	cancel()
	<-done
	assert.False(t, c.IsRunning())

	// stop when already stopped
	require.NoError(t, c.Stop())
}

func TestStartStopViaStop(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	go func() { _ = c.Start(context.Background()) }()
	require.Eventually(t, c.IsRunning, time.Second, 5*time.Millisecond)
	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())
}

func TestCollectNoInstances(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{}, nop())
	m, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestCollectWithMockInstance(t *testing.T) {
	db, mock := newMock(t)
	mock.MatchExpectationsInOrder(false)
	// All queries error (no expectations) except we allow any; collectInstance
	// handles errors gracefully. Perf counters always return partial metrics.
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		CollectQueryStore: true, CollectIndexStats: true,
		CollectAGStatus: true, CollectAgentJobs: true,
		Instances: []config.MSSQLInstanceConfig{{Name: "i", Host: "h"}},
	}, nop())
	c.instances[0].db = db
	c.instances[0].engineEdition = 5 // trigger azure path
	m, err := c.Collect(context.Background())
	require.NoError(t, err)
	// perf counters always yields the buffer cache hit ratio metric
	assert.NotNil(t, findMetric(m, "mssql.buffer_cache_hit_ratio"))
}

func TestCollectHappyPath(t *testing.T) {
	db, mock := newMock(t)
	mock.MatchExpectationsInOrder(false)

	// version detection -> engine edition 5 (Azure) so azure branch runs
	mock.ExpectQuery("SERVERPROPERTY").WillReturnRows(
		sqlmock.NewRows([]string{"v", "e"}).AddRow("16.0", 5))

	// 17 perf counters
	for i := 0; i < len(perfCounterQueries); i++ {
		mock.ExpectQuery("dm_os_performance_counters").WillReturnRows(
			sqlmock.NewRows([]string{"cntr_value"}).AddRow(100.0))
	}

	// wait stats
	mock.ExpectQuery("waiting_tasks_count > 0").WillReturnRows(
		sqlmock.NewRows([]string{"wait_type", "waiting_tasks_count", "wait_time_ms", "signal_wait_time_ms", "max_wait_time_ms"}).
			AddRow("SOS_SCHEDULER_YIELD", 10.0, 100.0, 5.0, 20.0))

	// file io
	mock.ExpectQuery("dm_io_virtual_file_stats").WillReturnRows(
		sqlmock.NewRows([]string{"database_name", "file_id", "num_of_reads", "num_of_writes", "mb_read", "mb_written", "io_stall_read_ms", "io_stall_write_ms", "size_mb", "file_type", "file_name"}).
			AddRow("appdb", 1, 100.0, 50.0, 10.0, 5.0, 200.0, 100.0, 1024.0, "ROWS", "app.mdf"))

	// tempdb space + contention
	mock.ExpectQuery("dm_db_file_space_usage").WillReturnRows(
		sqlmock.NewRows([]string{"a", "b", "c", "d", "e"}).AddRow(1.0, 2.0, 3.0, 4.0, 5.0))
	mock.ExpectQuery("PAGELATCH").WillReturnRows(
		sqlmock.NewRows([]string{"waiting_tasks_count", "wait_duration_ms"}).AddRow(10.0, 20.0))

	// AG status
	agCols := []string{"replica_server_name", "availability_mode_desc", "failover_mode_desc", "synchronization_health_desc", "synchronization_state_desc", "database_health", "database_name", "log_send_queue_size", "log_send_rate", "redo_queue_size", "redo_rate", "secondary_lag_seconds"}
	mock.ExpectQuery("dm_hadr_availability_replica_states").WillReturnRows(
		sqlmock.NewRows(agCols).AddRow("node1", "SYNCHRONOUS_COMMIT", "AUTOMATIC", "HEALTHY", "SYNCHRONIZED", "HEALTHY", "appdb", 100.0, 10.0, 50.0, 5.0, 1.0))

	// agent jobs
	mock.ExpectQuery("sysjobs").WillReturnRows(
		sqlmock.NewRows([]string{"job_name", "job_enabled", "last_run_status", "run_duration", "run_date", "run_time", "next_run_date", "next_run_time"}).
			AddRow("backup", 1, "succeeded", 130, 20240101, 120000, 20240102, 120000))

	// query stats
	qCols := []string{"query_hash", "plan_count", "total_executions", "total_elapsed_ms", "total_cpu_ms", "total_logical_reads", "total_physical_reads", "total_logical_writes", "avg_elapsed_ms", "avg_cpu_ms", "max_elapsed_ms", "max_cpu_ms", "max_logical_reads", "max_dop"}
	mock.ExpectQuery("dm_exec_query_stats").WillReturnRows(
		sqlmock.NewRows(qCols).AddRow([]byte{0xAB}, 1, 10, 100.0, 80.0, 500.0, 10.0, 20.0, 10.0, 8.0, 50.0, 40.0, 500.0, 4.0))

	// query store
	mock.ExpectQuery("database_query_store_query").WillReturnRows(
		sqlmock.NewRows([]string{"query_id", "plan_id", "avg_duration_ms", "avg_cpu_ms", "avg_logical_io_reads", "avg_logical_io_writes", "avg_physical_io_reads", "count_executions", "query_sql_text"}).
			AddRow(int64(1), int64(2), 10.0, 8.0, 100.0, 20.0, 5.0, int64(50), "SELECT 1"))

	// azure DTU + storage
	mock.ExpectQuery("DTU limit").WillReturnRows(
		sqlmock.NewRows([]string{"c", "r", "w", "d", "l"}).AddRow(10.0, 20.0, 30.0, 40.0, 100))
	mock.ExpectQuery("Storage space used").WillReturnRows(
		sqlmock.NewRows([]string{"used", "alloc"}).AddRow(500.0, 1000.0))

	// index stats
	mock.ExpectQuery("dm_db_missing_index_details").WillReturnRows(
		sqlmock.NewRows([]string{"database_name", "table_name", "equality_columns", "inequality_columns", "included_columns", "user_seeks", "user_scans", "avg_total_user_cost", "avg_user_impact", "improvement_measure"}).
			AddRow("appdb", "dbo.t", "c1", nil, "c2", int64(100), int64(10), 5.0, 90.0, 450.0))
	mock.ExpectQuery("dm_db_index_physical_stats").WillReturnRows(
		sqlmock.NewRows([]string{"database_name", "table_name", "index_name", "avg_fragmentation_in_percent", "page_count", "avg_page_space_used_in_percent"}).
			AddRow("appdb", "dbo.t", "ix_1", 45.0, 2000.0, 80.0))

	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		CollectQueryStore: true, CollectIndexStats: true,
		CollectAGStatus: true, CollectAgentJobs: true,
		Instances: []config.MSSQLInstanceConfig{{Name: "i", Host: "h"}},
	}, nop())
	c.instances[0].db = db

	m, err := c.Collect(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.wait.wait_time_ms"))
	assert.NotNil(t, findMetric(m, "mssql.fileio.num_reads"))
	assert.NotNil(t, findMetric(m, "mssql.tempdb.total_size_mb"))
	assert.NotNil(t, findMetric(m, "mssql.ag.sync_state"))
	assert.NotNil(t, findMetric(m, "mssql.agent_job.enabled"))
	assert.NotNil(t, findMetric(m, "mssql.query.total_executions"))
	assert.NotNil(t, findMetric(m, "mssql.querystore.avg_duration_ms"))
	assert.NotNil(t, findMetric(m, "mssql.azure.cpu_percent"))
	assert.NotNil(t, findMetric(m, "mssql.index.missing.user_seeks"))
}

func TestCollectAllIndexesDisabled(t *testing.T) {
	db, _ := newMock(t)
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		CollectIndexStats: false,
		Instances:         []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	c.instances[0].db = db
	m, err := c.collectAllIndexes(context.Background())
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestCollectAllQueriesConnFail(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	c.instances[0].lastConnErr = time.Now()
	c.instances[0].backoff = time.Minute
	m, err := c.collectAllQueries(context.Background())
	require.NoError(t, err)
	assert.Nil(t, m)
	m2, err2 := c.collectAllIndexes(context.Background())
	require.NoError(t, err2)
	assert.Nil(t, m2)
}

// ---------- version.go ----------

func TestDetectVersion(t *testing.T) {
	db, mock := newMock(t)
	inst := &mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i"}}
	mock.ExpectQuery("SERVERPROPERTY").WillReturnRows(
		sqlmock.NewRows([]string{"v", "e"}).AddRow("16.0.1000", 3))
	require.NoError(t, detectVersion(context.Background(), db, inst, nop()))
	assert.Equal(t, "16.0.1000", inst.version)
	assert.Equal(t, 3, inst.engineEdition)
}

func TestDetectVersionError(t *testing.T) {
	db, mock := newMock(t)
	inst := &mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i"}}
	mock.ExpectQuery("SERVERPROPERTY").WillReturnError(sql.ErrConnDone)
	require.Error(t, detectVersion(context.Background(), db, inst, nop()))
}

// ---------- waits.go ----------

func TestCategorizeWait(t *testing.T) {
	assert.Equal(t, "CPU", categorizeWait("SOS_SCHEDULER_YIELD"))
	assert.Equal(t, "Lock", categorizeWait("LCK_M_X"))         // prefix pattern
	assert.Equal(t, "Latches", categorizeWait("PAGELATCH_EX")) // prefix pattern
	assert.Equal(t, "Other", categorizeWait("SOMETHING_ELSE"))
}

func TestCollectWaitStats(t *testing.T) {
	db, mock := newMock(t)
	rows := sqlmock.NewRows([]string{"wait_type", "waiting_tasks_count", "wait_time_ms", "signal_wait_time_ms", "max_wait_time_ms"}).
		AddRow("SOS_SCHEDULER_YIELD", 10.0, 100.0, 5.0, 20.0).
		AddRow("LAZYWRITER_SLEEP", 1.0, 1.0, 1.0, 1.0). // benign -> skipped
		AddRow("bad", "x", 1.0, 1.0, 1.0)               // scan error -> skipped
	mock.ExpectQuery("dm_os_wait_stats").WillReturnRows(rows)
	m, err := collectWaitStats(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.wait.wait_time_ms"))
	// only one wait row survived -> 4 metrics
	assert.Len(t, m, 4)
}

func TestCollectWaitStatsQueryError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_os_wait_stats").WillReturnError(sql.ErrConnDone)
	_, err := collectWaitStats(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- perfcounters.go ----------

func TestCollectPerfCounters(t *testing.T) {
	db, mock := newMock(t)
	mock.MatchExpectationsInOrder(false)
	inst := &mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i"}, prevCounters: map[string]float64{}}
	// 17 counters -> answer each with a value
	for i := 0; i < len(perfCounterQueries); i++ {
		mock.ExpectQuery("dm_os_performance_counters").
			WillReturnRows(sqlmock.NewRows([]string{"cntr_value"}).AddRow(100.0))
	}
	m, err := collectPerfCounters(context.Background(), db, inst, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.buffer_cache_hit_ratio"))
	assert.NotEmpty(t, inst.prevCounters)

	// Second pass: prev counters present -> rate branch executes
	inst.prevTimestamp = time.Now().Add(-10 * time.Second)
	for i := 0; i < len(perfCounterQueries); i++ {
		mock.ExpectQuery("dm_os_performance_counters").
			WillReturnRows(sqlmock.NewRows([]string{"cntr_value"}).AddRow(200.0))
	}
	m2, err := collectPerfCounters(context.Background(), db, inst, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m2, "mssql.batch_requests_per_sec"))
	assert.NotNil(t, findMetric(m2, "mssql.user_connections"))
}

func TestCollectPerfCountersNoRows(t *testing.T) {
	db, mock := newMock(t)
	mock.MatchExpectationsInOrder(false)
	inst := &mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i"}, prevCounters: map[string]float64{}}
	for i := 0; i < len(perfCounterQueries); i++ {
		mock.ExpectQuery("dm_os_performance_counters").WillReturnError(sql.ErrNoRows)
	}
	m, err := collectPerfCounters(context.Background(), db, inst, baseLabels(), nop())
	require.NoError(t, err)
	// still emits buffer cache hit ratio (0/0 -> 0)
	assert.NotNil(t, findMetric(m, "mssql.buffer_cache_hit_ratio"))
}

func TestQueryCounter(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"v"}).AddRow(42.0))
	v, err := queryCounter(context.Background(), db, "SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, 42.0, v)

	mock.ExpectQuery("SELECT").WillReturnError(sql.ErrConnDone)
	_, err = queryCounter(context.Background(), db, "SELECT 1")
	require.Error(t, err)
}

// ---------- fileio.go ----------

func TestCollectFileIO(t *testing.T) {
	db, mock := newMock(t)
	inst := &mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i"}}
	rows := sqlmock.NewRows([]string{"database_name", "file_id", "num_of_reads", "num_of_writes", "mb_read", "mb_written", "io_stall_read_ms", "io_stall_write_ms", "size_mb", "file_type", "file_name"}).
		AddRow("appdb", 1, 100.0, 50.0, 10.0, 5.0, 200.0, 100.0, 1024.0, "ROWS", "app.mdf").
		AddRow("bad", "x", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, "ROWS", "b") // scan error
	mock.ExpectQuery("dm_io_virtual_file_stats").WillReturnRows(rows)
	m, err := collectFileIO(context.Background(), db, inst, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.fileio.avg_read_stall_ms"))
}

func TestCollectFileIOError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_io_virtual_file_stats").WillReturnError(sql.ErrConnDone)
	_, err := collectFileIO(context.Background(), db, &mssqlInstance{}, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- tempdb.go ----------

func TestCollectTempDB(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_db_file_space_usage").WillReturnRows(
		sqlmock.NewRows([]string{"user_objects_mb", "internal_objects_mb", "version_store_mb", "free_space_mb", "mixed_extents_mb"}).
			AddRow(1.0, 2.0, 3.0, 4.0, 5.0))
	mock.ExpectQuery("dm_os_wait_stats").WillReturnRows(
		sqlmock.NewRows([]string{"waiting_tasks_count", "wait_duration_ms"}).AddRow(10.0, 20.0))
	m, err := collectTempDB(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.tempdb.total_size_mb"))
	assert.NotNil(t, findMetric(m, "mssql.tempdb.contention.wait_count"))
}

func TestCollectTempDBSpaceErrors(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_db_file_space_usage").WillReturnError(sql.ErrConnDone)
	_, err := collectTempDBSpace(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)

	// scan error path
	db2, mock2 := newMock(t)
	mock2.ExpectQuery("dm_db_file_space_usage").WillReturnRows(
		sqlmock.NewRows([]string{"a", "b", "c", "d", "e"}).AddRow("x", 1.0, 1.0, 1.0, 1.0))
	_, err = collectTempDBSpace(context.Background(), db2, baseLabels(), nop())
	require.Error(t, err)

	// no rows -> returns nil, nil (rows.Err)
	db3, mock3 := newMock(t)
	mock3.ExpectQuery("dm_db_file_space_usage").WillReturnRows(
		sqlmock.NewRows([]string{"a", "b", "c", "d", "e"}))
	m, err := collectTempDBSpace(context.Background(), db3, baseLabels(), nop())
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestCollectTempDBContentionError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_os_wait_stats").WillReturnError(sql.ErrConnDone)
	_, err := collectTempDBContention(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- ag.go ----------

func TestCollectAGStatus(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"replica_server_name", "availability_mode_desc", "failover_mode_desc",
		"synchronization_health_desc", "synchronization_state_desc", "database_health",
		"database_name", "log_send_queue_size", "log_send_rate", "redo_queue_size", "redo_rate", "secondary_lag_seconds"}
	rows := sqlmock.NewRows(cols).
		AddRow("node1", "SYNCHRONOUS_COMMIT", "AUTOMATIC", "HEALTHY", "SYNCHRONIZED", "HEALTHY", "appdb", 100.0, 10.0, 50.0, 5.0, 1.0).
		AddRow("node2", "ASYNCHRONOUS_COMMIT", "MANUAL", "HEALTHY", "SYNCHRONIZING", "HEALTHY", "appdb", nil, nil, nil, nil, nil).
		AddRow("node3", "x", "y", "z", "NOT SYNCHRONIZING", "q", "db2", nil, nil, nil, nil, nil).
		AddRow("bad", "x", "y", "z", "REVERTING", "q", "db3", "notafloat", nil, nil, nil, nil) // scan err
	mock.ExpectQuery("dm_hadr_availability_replica_states").WillReturnRows(rows)
	m, err := collectAGStatus(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.ag.sync_state"))
	assert.NotNil(t, findMetric(m, "mssql.ag.log_send_queue_size_kb"))
}

func TestCollectAGStatusError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_hadr_availability_replica_states").WillReturnError(sql.ErrConnDone)
	_, err := collectAGStatus(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- agentjobs.go ----------

func TestHHMMSSToSeconds(t *testing.T) {
	assert.Equal(t, 3661.0, hhmmssToSeconds(10101)) // 1h 1m 1s
	assert.Equal(t, 0.0, hhmmssToSeconds(0))
}

func TestCollectAgentJobs(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"job_name", "job_enabled", "last_run_status", "run_duration", "run_date", "run_time", "next_run_date", "next_run_time"}
	rows := sqlmock.NewRows(cols).
		AddRow("backup", 1, "succeeded", 130, 20240101, 120000, 20240102, 120000).
		AddRow("etl", 1, "failed", 5000, 20240101, 120000, nil, nil).
		AddRow("bad", "x", "failed", 0, nil, nil, nil, nil) // scan err
	mock.ExpectQuery("sysjobs").WillReturnRows(rows)
	m, err := collectAgentJobs(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.agent_job.enabled"))
	assert.NotNil(t, findMetric(m, "mssql.agent_job.failed"))
}

func TestCollectAgentJobsError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("sysjobs").WillReturnError(sql.ErrConnDone)
	_, err := collectAgentJobs(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- azure.go ----------

func TestCollectAzureSQLDBMetrics(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("Azure SQL Database").WillReturnRows(
		sqlmock.NewRows([]string{"c", "r", "w", "d", "l"}).AddRow(10.0, 20.0, 30.0, 40.0, 100))
	mock.ExpectQuery("Azure SQL Database").WillReturnRows(
		sqlmock.NewRows([]string{"used", "alloc"}).AddRow(500.0, 1000.0))
	m, err := collectAzureSQLDBMetrics(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.azure.cpu_percent"))
	assert.NotNil(t, findMetric(m, "mssql.azure.storage_percent"))
}

func TestCollectAzureErrorsHandled(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("Azure SQL Database").WillReturnError(sql.ErrConnDone)
	mock.ExpectQuery("Azure SQL Database").WillReturnError(sql.ErrConnDone)
	m, err := collectAzureSQLDBMetrics(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err) // errors are logged, not returned
	assert.Empty(t, m)
}

func TestCollectAzureDTUError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("Azure SQL Database").WillReturnError(sql.ErrConnDone)
	_, err := collectAzureDTU(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

func TestCollectAzureStorageError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("Azure SQL Database").WillReturnError(sql.ErrConnDone)
	_, err := collectAzureStorage(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- indexes.go ----------

func TestCollectIndexStats(t *testing.T) {
	db, mock := newMock(t)
	missCols := []string{"database_name", "table_name", "equality_columns", "inequality_columns", "included_columns", "user_seeks", "user_scans", "avg_total_user_cost", "avg_user_impact", "improvement_measure"}
	mock.ExpectQuery("dm_db_missing_index_details").WillReturnRows(
		sqlmock.NewRows(missCols).
			AddRow("appdb", "dbo.t", "c1", nil, "c2", int64(100), int64(10), 5.0, 90.0, 450.0).
			AddRow("bad", "t", nil, nil, nil, "x", int64(1), 1.0, 1.0, 1.0)) // scan err
	fragCols := []string{"database_name", "table_name", "index_name", "avg_fragmentation_in_percent", "page_count", "avg_page_space_used_in_percent"}
	mock.ExpectQuery("dm_db_index_physical_stats").WillReturnRows(
		sqlmock.NewRows(fragCols).
			AddRow("appdb", "dbo.t", "ix_1", 45.0, 2000.0, 80.0).
			AddRow("bad", "t", "ix", "x", 1.0, 1.0)) // scan err
	m, err := collectIndexStats(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.index.missing.user_seeks"))
	assert.NotNil(t, findMetric(m, "mssql.index.fragmentation_percent"))
}

func TestCollectIndexStatsErrorsHandled(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_db_missing_index_details").WillReturnError(sql.ErrConnDone)
	mock.ExpectQuery("dm_db_index_physical_stats").WillReturnError(sql.ErrConnDone)
	m, err := collectIndexStats(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.Empty(t, m)
}

func TestCollectMissingIndexesError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_db_missing_index_details").WillReturnError(sql.ErrConnDone)
	_, err := collectMissingIndexes(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

func TestCollectIndexFragmentationError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_db_index_physical_stats").WillReturnError(sql.ErrConnDone)
	_, err := collectIndexFragmentation(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

func TestFmtNullString(t *testing.T) {
	assert.Equal(t, "hi", fmtNullString(sql.NullString{String: "hi", Valid: true}))
	assert.Equal(t, "", fmtNullString(sql.NullString{Valid: false}))
}

// ---------- queries.go ----------

func TestCollectQueryStats(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"query_hash", "plan_count", "total_executions", "total_elapsed_ms", "total_cpu_ms", "total_logical_reads", "total_physical_reads", "total_logical_writes", "avg_elapsed_ms", "avg_cpu_ms", "max_elapsed_ms", "max_cpu_ms", "max_logical_reads", "max_dop"}
	mock.ExpectQuery("dm_exec_query_stats").WillReturnRows(
		sqlmock.NewRows(cols).
			AddRow([]byte{0xAB, 0xCD}, 2, 100, 1000.0, 800.0, 5000.0, 100.0, 200.0, 10.0, 8.0, 50.0, 40.0, 500.0, 4.0).
			AddRow("bad", 1, 1, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0)) // scan err
	m, err := collectQueryStats(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.query.total_executions"))
}

func TestCollectQueryStatsError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("dm_exec_query_stats").WillReturnError(sql.ErrConnDone)
	_, err := collectQueryStats(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- querystore.go ----------

func TestCollectQueryStore(t *testing.T) {
	db, mock := newMock(t)
	cols := []string{"query_id", "plan_id", "avg_duration_ms", "avg_cpu_ms", "avg_logical_io_reads", "avg_logical_io_writes", "avg_physical_io_reads", "count_executions", "query_sql_text"}
	mock.ExpectQuery("database_query_store_query").WillReturnRows(
		sqlmock.NewRows(cols).
			AddRow(int64(1), int64(2), 10.0, 8.0, 100.0, 20.0, 5.0, int64(50), "SELECT 1").
			AddRow("bad", int64(2), 1.0, 1.0, 1.0, 1.0, 1.0, int64(1), "x")) // scan err
	m, err := collectQueryStore(context.Background(), db, baseLabels(), nop())
	require.NoError(t, err)
	assert.NotNil(t, findMetric(m, "mssql.querystore.avg_duration_ms"))
}

func TestCollectQueryStoreError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectQuery("database_query_store_query").WillReturnError(sql.ErrConnDone)
	_, err := collectQueryStore(context.Background(), db, baseLabels(), nop())
	require.Error(t, err)
}

// ---------- otlp_emit.go ----------

func TestOTLPEmitterNilBridge(t *testing.T) {
	e := NewOTLPEmitter(nil, nop())
	require.NoError(t, e.EmitMetrics(context.Background(), []collector.Metric{{Name: "m"}}))
	require.NoError(t, e.EmitMetrics(context.Background(), nil))
	inst := &mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i"}}
	require.NoError(t, e.EmitMetricsForInstance(context.Background(), []collector.Metric{{Name: "m"}}, inst))
	require.NoError(t, e.EmitMetricsForInstance(context.Background(), nil, inst))
	require.NoError(t, e.Shutdown(context.Background()))
}

func TestResourceAttrsFromMetric(t *testing.T) {
	m := collector.Metric{Labels: map[string]string{
		"mssql_instance": "i1", "mssql_host": "h1", "mssql_version": "16.0",
	}}
	attrs := resourceAttrsFromMetric(m)
	assert.Equal(t, "mssql", attrs["service.name"])
	assert.Equal(t, "i1", attrs["db.instance.id"])
	assert.Equal(t, "16.0", attrs["db.mssql.version"])

	// no version
	attrs2 := resourceAttrsFromMetric(collector.Metric{Labels: map[string]string{"mssql_instance": "i"}})
	_, has := attrs2["db.mssql.version"]
	assert.False(t, has)
}

func TestResourceAttrsFromInstance(t *testing.T) {
	inst := &mssqlInstance{
		config: config.MSSQLInstanceConfig{
			Name: "i", Host: "h", Port: 1433, Database: "app",
			InstanceName: "SQLEXPRESS",
		},
		version: "16.0", engineEdition: 3,
	}
	attrs := resourceAttrsFromInstance(inst)
	assert.Equal(t, "i", attrs["db.instance.id"])
	assert.Equal(t, "1433", attrs["net.host.port"])
	assert.Equal(t, "16.0", attrs["db.mssql.version"])
	assert.Equal(t, "app", attrs["db.name"])
	assert.Equal(t, "SQLEXPRESS", attrs["db.mssql.instance_name"])
	assert.Equal(t, "3", attrs["db.mssql.engine_edition"])

	// minimal instance
	attrs2 := resourceAttrsFromInstance(&mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i", Host: "h"}})
	_, hasVer := attrs2["db.mssql.version"]
	assert.False(t, hasVer)
}

// ---------- exports.go ----------

func TestExportedWrappers(t *testing.T) {
	assert.Equal(t, 5.0, SafeDivExported(10, 2))
	m := MakeMetricExported("m", 1, collector.MetricTypeGauge, nil)
	assert.Equal(t, "m", m.Name)
	assert.Equal(t, 0.0, EmitCounterRateExported("r", math.NaN(), nil).Value)
	assert.Equal(t, "prefix", ResolveEnvVarsExported("prefix"))
	assert.Equal(t, "x", CopyLabelsExported(map[string]string{"x": "x"})["x"])
	assert.Equal(t, "CPU", CategorizeWaitExported("SOS_SCHEDULER_YIELD"))
	assert.Equal(t, 3661.0, HHMMSSToSecondsExported(10101))

	ti := NewMSSQLTestInstance(config.MSSQLInstanceConfig{Name: "i", Host: "h"})
	assert.NotNil(t, ti.PrevCounters)
	labels := InstanceLabelsExported(ti)
	assert.Equal(t, "i", labels["mssql_instance"])

	dsn := BuildConnStringExported(config.MSSQLInstanceConfig{Username: "u", Password: "p", Host: "h", Port: 1, Database: "d"})
	assert.Contains(t, dsn, "sqlserver://")

	c := NewConfigExported(config.MSSQLCollectorConfig{})
	assert.Equal(t, 3, c.MaxConnections)

	e := NewOTLPEmitter(nil, nop())
	require.NoError(t, e.EmitMetricsForInstanceExported(context.TODO(), nil, ti))
}

// ---------- qan_collector.go ----------

func TestNewQANMSSQLCollector(t *testing.T) {
	c := NewQANMSSQLCollector(QANMSSQLConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i", Host: "h"}},
	}, nil) // nil logger -> production logger path
	assert.Equal(t, 200, c.cfg.TopQueriesLimit)
	assert.Equal(t, "qan-mssql-querystats", c.Name())
	assert.Equal(t, qan.AgentTypeMSSQLQueryStats, c.AgentType())
	assert.False(t, c.IsRunning())

	require.NoError(t, c.Start(context.Background()))
	assert.True(t, c.IsRunning())
	require.Error(t, c.Start(context.Background())) // double start
	require.NoError(t, c.Stop())
	assert.False(t, c.IsRunning())
	require.NoError(t, c.Stop()) // already stopped
}

func TestQANCollectQANNoInstances(t *testing.T) {
	c := NewQANMSSQLCollector(QANMSSQLConfig{TopQueriesLimit: 10}, nop())
	b, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Nil(t, b)
}

func TestQANStopClosesDB(t *testing.T) {
	db, _ := newMock(t)
	c := NewQANMSSQLCollector(QANMSSQLConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	c.instances[0].db = db
	require.NoError(t, c.Start(context.Background()))
	require.NoError(t, c.Stop())
	assert.Nil(t, c.instances[0].db)
}

func TestQANInstanceLabels(t *testing.T) {
	c := NewQANMSSQLCollector(QANMSSQLConfig{
		Labels:    map[string]string{"team": "obs"},
		Instances: []config.MSSQLInstanceConfig{{Name: "i", Host: "h"}},
	}, nop())
	l := c.instanceLabels(c.instances[0])
	assert.Equal(t, "obs", l["team"])
	assert.Equal(t, "i", l["mssql_instance"])
	assert.Equal(t, "mssql", l["db_system"])
}

func TestBuildQANConnString(t *testing.T) {
	dsn := buildQANConnString(config.MSSQLInstanceConfig{
		Username: "u", Password: "p", Host: "h", Port: 1433, Database: "d",
	})
	assert.Contains(t, dsn, "encrypt=disable") // default when empty
	dsnNamed := buildQANConnString(config.MSSQLInstanceConfig{
		Username: "u", Password: "p", Host: "h", Port: 1433, Database: "d",
		InstanceName: "SQLEXPRESS", Encrypt: "true",
	})
	assert.Contains(t, dsnNamed, "instanceName=SQLEXPRESS")
	assert.Contains(t, dsnNamed, "encrypt=true")
}

func TestQANCollectInstance(t *testing.T) {
	db, mock := newMock(t)
	c := NewQANMSSQLCollector(QANMSSQLConfig{
		TopQueriesLimit: 5,
		Instances:       []config.MSSQLInstanceConfig{{Name: "i", Host: "h", Database: "app", Username: "sa"}},
	}, nop())
	inst := c.instances[0]
	inst.db = db

	cols := []string{"query_hash", "execution_count", "total_worker_time", "total_elapsed_time", "total_logical_reads", "total_physical_reads", "total_logical_writes", "row_count", "max_dop", "max_grant_kb"}
	// First collection: establishes previous snapshot, no buckets yet.
	mock.ExpectQuery("dm_exec_query_stats").WillReturnRows(
		sqlmock.NewRows(cols).
			AddRow("hash1", int64(100), int64(1000000), int64(2000000), int64(5000), int64(100), int64(200), int64(500), int64(4), 128.0).
			AddRow("bad", "x", int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), int64(1), nil)) // scan err
	b, err := c.collectInstance(context.Background(), inst)
	require.NoError(t, err)
	assert.Empty(t, b) // no previous snapshot

	// Second collection: delta computed -> bucket produced.
	inst.prevTime = time.Now().Add(-60 * time.Second)
	mock.ExpectQuery("dm_exec_query_stats").WillReturnRows(
		sqlmock.NewRows(cols).
			AddRow("hash1", int64(150), int64(1500000), int64(3000000), int64(7000), int64(150), int64(300), int64(700), int64(4), 256.0).
			AddRow("hash2", int64(10), int64(1000), int64(2000), int64(5), int64(1), int64(2), int64(3), int64(1), nil)) // no prev -> skip
	b2, err := c.collectInstance(context.Background(), inst)
	require.NoError(t, err)
	require.Len(t, b2, 1)
	assert.Equal(t, "hash1", b2[0].QueryID)
	assert.Equal(t, float64(50), b2[0].NumQueries)
	require.NotNil(t, b2[0].MSSQL)
	assert.Equal(t, 256.0, b2[0].MSSQL.MaxGrantKB)

	// Third: same exec count -> delta <= 0 -> skipped
	mock.ExpectQuery("dm_exec_query_stats").WillReturnRows(
		sqlmock.NewRows(cols).
			AddRow("hash1", int64(150), int64(1500000), int64(3000000), int64(7000), int64(150), int64(300), int64(700), int64(4), 256.0))
	b3, err := c.collectInstance(context.Background(), inst)
	require.NoError(t, err)
	assert.Empty(t, b3)
}

func TestQANCollectInstanceQueryError(t *testing.T) {
	db, mock := newMock(t)
	c := NewQANMSSQLCollector(QANMSSQLConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	inst := c.instances[0]
	inst.db = db
	mock.ExpectQuery("dm_exec_query_stats").WillReturnError(sql.ErrConnDone)
	_, err := c.collectInstance(context.Background(), inst)
	require.Error(t, err)
}

func TestQANCollectQANWithInstance(t *testing.T) {
	db, mock := newMock(t)
	c := NewQANMSSQLCollector(QANMSSQLConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	c.instances[0].db = db
	cols := []string{"query_hash", "execution_count", "total_worker_time", "total_elapsed_time", "total_logical_reads", "total_physical_reads", "total_logical_writes", "row_count", "max_dop", "max_grant_kb"}
	mock.ExpectQuery("dm_exec_query_stats").WillReturnRows(sqlmock.NewRows(cols))
	b, err := c.CollectQAN(context.Background())
	require.NoError(t, err)
	assert.Empty(t, b)
}

// ---------- ensureConnection reopen / failure paths ----------

func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestEnsureConnectionOpenPingFail(t *testing.T) {
	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i", Host: "127.0.0.1", Port: 1, Username: "sa", Password: "p", Database: "master", Encrypt: "disable"}},
	}, nop())
	inst := c.instances[0]
	_, err := c.ensureConnection(cancelledCtx(), inst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ping")
	assert.NotZero(t, inst.backoff) // advanceBackoff invoked
}

func TestEnsureConnectionStaleDBReopen(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing().WillReturnError(sql.ErrConnDone)

	c := NewMSSQLCollector(config.MSSQLCollectorConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i", Host: "127.0.0.1", Port: 1, Username: "sa", Password: "p", Database: "master", Encrypt: "disable"}},
	}, nop())
	inst := c.instances[0]
	inst.db = db
	// stale db ping fails -> closed -> reopen with cancelled ctx -> ping fails
	_, err = c.ensureConnection(cancelledCtx(), inst)
	require.Error(t, err)
}

func TestQANEnsureConnectionReopen(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectPing().WillReturnError(sql.ErrConnDone)

	c := NewQANMSSQLCollector(QANMSSQLConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i", Host: "127.0.0.1", Port: 1, Username: "sa", Password: "p", Database: "master", Encrypt: "disable"}},
	}, nop())
	inst := c.instances[0]
	inst.db = db
	_, err = c.ensureConnection(cancelledCtx(), inst)
	require.Error(t, err)
}

// ---------- OTLP emit with a real bridge (export error path) ----------

func newErrorBridge(t *testing.T) *exporter.OTLPMetricBridge {
	t.Helper()
	b, err := exporter.NewOTLPMetricBridge(context.Background(), exporter.OTLPMetricBridgeConfig{
		Endpoint: "127.0.0.1:1", Logger: nop(),
	})
	require.NoError(t, err)
	return b
}

func TestOTLPEmitMetricsExportError(t *testing.T) {
	b := newErrorBridge(t)
	e := NewOTLPEmitter(b, nop())
	metrics := []collector.Metric{makeMetric("mssql.test", 1, collector.MetricTypeGauge, baseLabels())}
	err := e.EmitMetrics(cancelledCtx(), metrics)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mssql otlp emit")

	inst := &mssqlInstance{config: config.MSSQLInstanceConfig{Name: "i", Host: "h", Port: 1433}}
	err = e.EmitMetricsForInstance(cancelledCtx(), metrics, inst)
	require.Error(t, err)

	require.NoError(t, e.Shutdown(context.Background()))
}

func TestQANEnsureConnectionExisting(t *testing.T) {
	db, _ := newMock(t)
	c := NewQANMSSQLCollector(QANMSSQLConfig{
		Instances: []config.MSSQLInstanceConfig{{Name: "i"}},
	}, nop())
	inst := c.instances[0]
	inst.db = db
	got, err := c.ensureConnection(context.Background(), inst)
	require.NoError(t, err)
	assert.Equal(t, db, got)
}
