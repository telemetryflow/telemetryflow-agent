// Package mysql_test contains unit tests for the corresponding collector module.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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

package mysql_test

import (
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	mysql "github.com/telemetryflow/telemetryflow-agent/internal/collector/mysql"
)

func TestInitMariaDBExtension(t *testing.T) {
	ext := mysql.InitMariaDBExtensionExport()
	if ext == nil {
		t.Fatal("expected non-nil extension")
	}
	if ext.QueryCacheEnabled() {
		t.Error("query cache should default to false")
	}
	if ext.DetectedEngines() == nil {
		t.Error("detectedEngines map should be initialized")
	}
	if ext.DetectedPlugins() == nil {
		t.Error("detectedPlugins map should be initialized")
	}
}

func TestCollectMariaDBQueryCacheMetrics(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.ComputeMariaDBQueryCacheFromStatus(
		map[string]float64{
			"Qcache_hits":             800,
			"Qcache_inserts":          200,
			"Qcache_lowmem_prunes":    50,
			"Qcache_free_memory":      1048576,
			"Qcache_queries_in_cache": 100,
			"Qcache_not_cached":       30,
			"Qcache_free_blocks":      40,
			"Qcache_total_blocks":     200,
		},
		labels,
	)

	hitRatio := findMetric(metrics, "db.mysql.qcache.hit_ratio")
	if hitRatio == nil {
		t.Fatal("expected hit_ratio metric")
	}
	expectedHitRatio := 800.0 / (800.0 + 200.0) // 0.8
	if diff := hitRatio.Value - expectedHitRatio; diff > 0.001 || diff < -0.001 {
		t.Errorf("hit_ratio: got %f, want %f", hitRatio.Value, expectedHitRatio)
	}

	fragmentation := findMetric(metrics, "db.mysql.qcache.fragmentation")
	if fragmentation == nil {
		t.Fatal("expected fragmentation metric")
	}
	expectedFrag := 40.0 / 200.0 // 0.2
	if diff := fragmentation.Value - expectedFrag; diff > 0.001 || diff < -0.001 {
		t.Errorf("fragmentation: got %f, want %f", fragmentation.Value, expectedFrag)
	}

	if m := findMetric(metrics, "db.mysql.qcache.lowmem_prunes"); m == nil || m.Value != 50 {
		t.Error("lowmem_prunes metric wrong")
	}
	if m := findMetric(metrics, "db.mysql.qcache.queries_in_cache"); m == nil || m.Value != 100 {
		t.Error("queries_in_cache metric wrong")
	}
	if m := findMetric(metrics, "db.mysql.qcache.free_memory"); m == nil || m.Value != 1048576 {
		t.Error("free_memory metric wrong")
	}
}

func TestCollectMariaDBQueryCacheZeroHits(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.ComputeMariaDBQueryCacheFromStatus(
		map[string]float64{
			"Qcache_hits":    0,
			"Qcache_inserts": 0,
		},
		labels,
	)
	hitRatio := findMetric(metrics, "db.mysql.qcache.hit_ratio")
	if hitRatio == nil {
		t.Fatal("expected hit_ratio metric")
	}
	if hitRatio.Value != 0 {
		t.Errorf("hit_ratio with zero hits/inserts should be 0, got %f", hitRatio.Value)
	}
}

func TestCollectMariaDBAriaMetrics(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.ComputeMariaDBAriaFromStatus(
		map[string]float64{
			"read_requests":      10000,
			"reads":              100,
			"blocks_used":        500,
			"blocks_unused":      200,
			"blocks_not_flushed": 10,
		},
		labels,
	)

	hitRatio := findMetric(metrics, "db.mysql.aria.pagecache.hit_ratio")
	if hitRatio == nil {
		t.Fatal("expected pagecache hit_ratio metric")
	}
	expectedHitRatio := 1 - 100.0/10000.0 // 0.99
	if diff := hitRatio.Value - expectedHitRatio; diff > 0.001 || diff < -0.001 {
		t.Errorf("pagecache hit_ratio: got %f, want %f", hitRatio.Value, expectedHitRatio)
	}

	if m := findMetric(metrics, "db.mysql.aria.pagecache.blocks_used"); m == nil || m.Value != 500 {
		t.Error("blocks_used metric wrong")
	}
	if m := findMetric(metrics, "db.mysql.aria.pagecache.blocks_not_flushed"); m == nil || m.Value != 10 {
		t.Error("blocks_not_flushed metric wrong")
	}
}

func TestCollectMariaDBThreadPoolMetrics(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test"}
	metrics := mysql.ComputeMariaDBThreadPoolFromStatus(
		map[string]float64{
			"Threadpool_threads":        20,
			"Threadpool_active_threads": 8,
			"Threadpool_idle_threads":   12,
			"Threadpool_overflows":      5,
			"Threadpool_waits":          100,
			"Threadpool_queues":         3,
		},
		labels,
	)

	if m := findMetric(metrics, "db.mysql.threadpool.threads"); m == nil || m.Value != 20 {
		t.Error("threads metric wrong")
	}
	if m := findMetric(metrics, "db.mysql.threadpool.active_threads"); m == nil || m.Value != 8 {
		t.Error("active_threads metric wrong")
	}
	utilMetric := findMetric(metrics, "db.mysql.threadpool.utilization")
	if utilMetric == nil {
		t.Fatal("expected utilization metric")
	}
	expectedUtil := 8.0 / 20.0 // 0.4
	if diff := utilMetric.Value - expectedUtil; diff > 0.001 || diff < -0.001 {
		t.Errorf("utilization: got %f, want %f", utilMetric.Value, expectedUtil)
	}
	if m := findMetric(metrics, "db.mysql.threadpool.overflows"); m == nil || m.Value != 5 {
		t.Error("overflows metric wrong")
	}
}

func TestCollectMariaDBUserStatsFromRows(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test"}
	rows := []mysql.UserStatsRowExport{
		{User: "app_user", TotalConns: 100, ConcurrentConns: 5, CPUTime: 12.5, RowsRead: 50000, RowsSent: 10000, RowsInserted: 2000, RowsUpdated: 500, RowsDeleted: 100, BusyTime: 8.3, SelectCmds: 3000, UpdateCmds: 600, OtherCmds: 400},
		{User: "readonly", TotalConns: 50, ConcurrentConns: 2, CPUTime: 3.2, RowsRead: 20000, RowsSent: 20000, RowsInserted: 0, RowsUpdated: 0, RowsDeleted: 0, BusyTime: 2.1, SelectCmds: 1500, UpdateCmds: 0, OtherCmds: 50},
	}

	metrics := mysql.ComputeUserStatsFromRows(rows, labels)

	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	appMetrics := filterMetricsByLabel(metrics, "user", "app_user")
	if len(appMetrics) != 8 {
		t.Errorf("expected 8 metrics for app_user, got %d", len(appMetrics))
	}
	roMetrics := filterMetricsByLabel(metrics, "user", "readonly")
	if len(roMetrics) != 8 {
		t.Errorf("expected 8 metrics for readonly, got %d", len(roMetrics))
	}

	rowsWritten := findMetric(appMetrics, "db.mysql.userstats.rows_written")
	if rowsWritten == nil {
		t.Fatal("expected rows_written for app_user")
	}
	expectedWritten := 2000.0 + 500.0 + 100.0 // 2600
	if diff := rowsWritten.Value - expectedWritten; diff > 0.001 || diff < -0.001 {
		t.Errorf("rows_written: got %f, want %f", rowsWritten.Value, expectedWritten)
	}
}

func TestParseReplicationRowWithChannel(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test", "channel": "ch1"}
	colMap := map[string]string{
		"Seconds_Behind_Master": "5",
		"Slave_IO_Running":      "Yes",
		"Slave_SQL_Running":     "Yes",
		"Relay_Log_Space":       "1024",
	}
	metrics := mysql.ParseReplicationRowExport(colMap, labels)

	lag := findMetric(metrics, "db.mysql.replication.lag_seconds")
	if lag == nil || lag.Value != 5 {
		t.Error("lag_seconds metric wrong")
	}
	ioRunning := findMetric(metrics, "db.mysql.replication.io_running")
	if ioRunning == nil || ioRunning.Value != 1 {
		t.Error("io_running should be 1 for Yes")
	}
	sqlRunning := findMetric(metrics, "db.mysql.replication.sql_running")
	if sqlRunning == nil || sqlRunning.Value != 1 {
		t.Error("sql_running should be 1 for Yes")
	}
}

func TestParseReplicationRowNotRunning(t *testing.T) {
	labels := map[string]string{"mysql_instance": "test"}
	colMap := map[string]string{
		"Seconds_Behind_Master": "NULL",
		"Slave_IO_Running":      "No",
		"Slave_SQL_Running":     "No",
	}
	metrics := mysql.ParseReplicationRowExport(colMap, labels)

	ioRunning := findMetric(metrics, "db.mysql.replication.io_running")
	if ioRunning == nil || ioRunning.Value != 0 {
		t.Error("io_running should be 0 for No")
	}
	sqlRunning := findMetric(metrics, "db.mysql.replication.sql_running")
	if sqlRunning == nil || sqlRunning.Value != 0 {
		t.Error("sql_running should be 0 for No")
	}

	// "NULL" parses to 0 via parseFloat, and 0 >= 0 passes the check,
	// so lag_seconds is emitted with value 0 — expected behavior for
	// replicas with NULL lag (replication not running).
	lag := findMetric(metrics, "db.mysql.replication.lag_seconds")
	if lag != nil && lag.Value != 0 {
		t.Errorf("lag should be 0 for NULL value, got %f", lag.Value)
	}
}

// --- test helpers ---

func filterMetricsByLabel(metrics []collector.Metric, key, val string) []collector.Metric {
	var result []collector.Metric
	for _, m := range metrics {
		if m.Labels[key] == val {
			result = append(result, m)
		}
	}
	return result
}
