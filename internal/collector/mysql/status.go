// Package mysql implements the MySQL/MariaDB/Percona database monitoring collector.
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

package mysql

import (
	"context"
	"database/sql"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

type statusRow struct {
	name  string
	value uint64
}

func collectGlobalStatus(ctx context.Context, db *sql.DB) ([]statusRow, map[string]uint64, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2, "SHOW GLOBAL STATUS")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()

	var result []statusRow
	rawMap := make(map[string]uint64)
	for rows.Next() {
		var name, val string
		if err := rows.Scan(&name, &val); err != nil {
			continue
		}
		n := parseUint(val)
		rawMap[name] = n
		result = append(result, statusRow{name: name, value: n})
	}
	return result, rawMap, rows.Err()
}

var rateCounters = map[string]string{
	"Threads_created":         "db.mysql.threads.created",
	"Aborted_clients":         "db.mysql.connections.aborted_clients",
	"Aborted_connects":        "db.mysql.connections.aborted_connects",
	"Queries":                 "db.mysql.queries.total",
	"Com_select":              "db.mysql.queries.select",
	"Com_insert":              "db.mysql.queries.insert",
	"Com_update":              "db.mysql.queries.update",
	"Com_delete":              "db.mysql.queries.delete",
	"Com_commit":              "db.mysql.queries.commit",
	"Com_rollback":            "db.mysql.queries.rollback",
	"Slow_queries":            "db.mysql.queries.slow",
	"Bytes_sent":              "db.mysql.network.bytes_sent",
	"Bytes_received":          "db.mysql.network.bytes_received",
	"Innodb_rows_read":        "db.mysql.innodb.rows.read",
	"Innodb_rows_inserted":    "db.mysql.innodb.rows.inserted",
	"Innodb_rows_updated":     "db.mysql.innodb.rows.updated",
	"Innodb_rows_deleted":     "db.mysql.innodb.rows.deleted",
	"Innodb_row_lock_waits":   "db.mysql.innodb.lock.waits",
	"Innodb_deadlocks":        "db.mysql.innodb.deadlocks",
	"Table_locks_waited":      "db.mysql.table_locks.waited",
	"Table_locks_immediate":   "db.mysql.table_locks.immediate",
	"Created_tmp_tables":      "db.mysql.tmp_tables.memory",
	"Created_tmp_disk_tables": "db.mysql.tmp_tables.disk",
	"Sort_rows":               "db.mysql.sort.rows",
	"Sort_scan":               "db.mysql.sort.scan",
	"Sort_range":              "db.mysql.sort.range",
	"Sort_merge_passes":       "db.mysql.sort.merge_passes",
	"Handler_read_key":        "db.mysql.handler.read_key",
	"Handler_read_rnd_next":   "db.mysql.handler.read_rnd_next",
	"Handler_write":           "db.mysql.handler.write",
	"Binlog_cache_use":        "db.mysql.binlog.cache_use",
	"Binlog_cache_disk_use":   "db.mysql.binlog.cache_disk_use",
	"Table_open_cache_hits":   "db.mysql.table_cache.hits",
	"Table_open_cache_misses": "db.mysql.table_cache.misses",
	"Qcache_hits":             "db.mysql.qcache.hits",
	"Qcache_inserts":          "db.mysql.qcache.inserts",
	"Qcache_lowmem_prunes":    "db.mysql.qcache.lowmem_prunes",
}

func computeRates(prev, curr map[string]uint64, elapsedSec float64, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	for statusName, metricName := range rateCounters {
		prevVal, hasPrev := prev[statusName]
		currVal, hasCurr := curr[statusName]
		if !hasPrev || !hasCurr {
			continue
		}
		if currVal >= prevVal {
			delta := float64(currVal - prevVal)
			rate := safeDiv(delta, elapsedSec)
			metrics = append(metrics, emitCounterRate(metricName, rate, labels))
		}
	}
	return metrics
}

var gaugeMappings = map[string]string{
	"Threads_connected":              "db.mysql.threads.connected",
	"Threads_running":                "db.mysql.threads.running",
	"Innodb_buffer_pool_pages_total": "db.mysql.innodb.buffer_pool.pages.total",
	"Innodb_buffer_pool_pages_free":  "db.mysql.innodb.buffer_pool.pages.free",
	"Innodb_buffer_pool_pages_dirty": "db.mysql.innodb.buffer_pool.pages.dirty",
	"Innodb_buffer_pool_bytes_data":  "db.mysql.innodb.buffer_pool.bytes.data",
	"Innodb_buffer_pool_bytes_dirty": "db.mysql.innodb.buffer_pool.bytes.dirty",
	"Open_tables":                    "db.mysql.open_tables",
	"Innodb_row_lock_time_avg":       "db.mysql.innodb.lock.time_avg",
}

func emitGaugeMetrics(rawStatus map[string]uint64, rows []statusRow, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	for statusName, metricName := range gaugeMappings {
		if val, ok := rawStatus[statusName]; ok {
			metrics = append(metrics, makeMetric(metricName, float64(val), collector.MetricTypeGauge, labels))
		}
	}
	return metrics
}

func emitVariableMetrics(vars map[string]string, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	if val, ok := vars["max_connections"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.connections.max", parseFloat(val), collector.MetricTypeGauge, labels))
	}
	if val, ok := vars["innodb_buffer_pool_size"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.innodb.buffer_pool.size", parseFloat(val), collector.MetricTypeGauge, labels))
	}
	return metrics
}

func computeDerivedMetrics(status map[string]uint64, vars map[string]string, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric

	bpReadReqs := float64(status["Innodb_buffer_pool_read_requests"])
	bpReads := float64(status["Innodb_buffer_pool_reads"])
	hitRatio := 1 - safeDiv(bpReads, bpReadReqs)
	metrics = append(metrics, makeMetric("db.mysql.innodb.buffer_pool.hit_ratio", hitRatio, collector.MetricTypeGauge, labels))

	threadsConnected := float64(status["Threads_connected"])
	maxConns := parseFloat(vars["max_connections"])
	if maxConns > 0 {
		utilization := safeDiv(threadsConnected, maxConns)
		metrics = append(metrics, makeMetric("db.mysql.connections.utilization", utilization, collector.MetricTypeGauge, labels))
	}

	tmpTables := float64(status["Created_tmp_tables"])
	tmpDisk := float64(status["Created_tmp_disk_tables"])
	if tmpTables > 0 {
		ratio := safeDiv(tmpDisk, tmpTables)
		metrics = append(metrics, makeMetric("db.mysql.tmp_tables.disk_ratio", ratio, collector.MetricTypeGauge, labels))
	}

	threadsCreated := float64(status["Threads_created"])
	connections := float64(status["Connections"])
	if connections > 0 {
		threadCacheHitRate := 1 - safeDiv(threadsCreated, connections)
		metrics = append(metrics, makeMetric("db.mysql.threads.cache_hit_rate", threadCacheHitRate, collector.MetricTypeGauge, labels))
	}

	return metrics
}
