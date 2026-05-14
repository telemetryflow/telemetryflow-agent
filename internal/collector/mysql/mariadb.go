// Package mysql implements the MySQL/MariaDB/Percona database monitoring collector.
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

package mysql

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func initMariaDBExtension() *mariaDBExtension {
	return &mariaDBExtension{
		detectedEngines: make(map[string]bool),
		detectedPlugins: make(map[string]bool),
	}
}

func detectMariaDBEngines(ctx context.Context, db *sql.DB, ext *mariaDBExtension) error {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SELECT ENGINE, SUPPORT FROM information_schema.ENGINES WHERE ENGINE IN ('Aria', 'ColumnStore', 'Spider')")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var engine, support string
		if err := rows.Scan(&engine, &support); err != nil {
			continue
		}
		if strings.EqualFold(support, "YES") || strings.EqualFold(support, "DEFAULT") {
			ext.detectedEngines[engine] = true
		}
	}

	ext.ariaStatsEnabled = ext.detectedEngines["Aria"]
	ext.columnStoreStatsEnabled = ext.detectedEngines["ColumnStore"]
	ext.spiderStatsEnabled = ext.detectedEngines["Spider"]
	return rows.Err()
}

func detectMariaDBPlugins(ctx context.Context, db *sql.DB, ext *mariaDBExtension, vars map[string]string) error {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME IN ('userstat', 'query_cache')")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name, status string
		if err := rows.Scan(&name, &status); err != nil {
			continue
		}
		if strings.EqualFold(status, "ACTIVE") {
			ext.detectedPlugins[name] = true
		}
	}

	ext.userStatsEnabled = ext.detectedPlugins["userstat"]

	if v, ok := vars["have_query_cache"]; ok && strings.EqualFold(v, "YES") {
		ext.queryCacheEnabled = true
	}

	if v, ok := vars["thread_handling"]; ok && strings.EqualFold(v, "pool-of-threads") {
		ext.threadPoolStatsEnabled = true
	}

	return rows.Err()
}

func collectMariaDBQueryCache(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SHOW GLOBAL STATUS WHERE Variable_name IN ("+
			"'Qcache_hits', 'Qcache_inserts', 'Qcache_lowmem_prunes', "+
			"'Qcache_free_memory', 'Qcache_total_blocks', 'Qcache_free_blocks', "+
			"'Qcache_queries_in_cache', 'Qcache_not_cached')")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	status := make(map[string]float64)
	for rows.Next() {
		var name, val string
		if err := rows.Scan(&name, &val); err != nil {
			continue
		}
		status[name] = parseFloat(val)
	}

	var metrics []collector.Metric

	hits := status["Qcache_hits"]
	inserts := status["Qcache_inserts"]
	total := hits + inserts
	hitRatio := safeDiv(hits, total)
	metrics = append(metrics, makeMetric("db.mysql.qcache.hit_ratio", hitRatio, collector.MetricTypeGauge, labels))

	freeBlocks := status["Qcache_free_blocks"]
	totalBlocks := status["Qcache_total_blocks"]
	fragmentation := safeDiv(freeBlocks, totalBlocks)
	metrics = append(metrics, makeMetric("db.mysql.qcache.fragmentation", fragmentation, collector.MetricTypeGauge, labels))

	if val, ok := status["Qcache_free_memory"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.free_memory", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Qcache_queries_in_cache"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.queries_in_cache", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Qcache_lowmem_prunes"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.lowmem_prunes", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Qcache_not_cached"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.qcache.not_cached", val, collector.MetricTypeGauge, labels))
	}

	return metrics, rows.Err()
}

func collectMariaDBAria(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2, "SHOW ENGINE ARIA STATUS")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	status := make(map[string]float64)
	for rows.Next() {
		var typ, name, val string
		if err := rows.Scan(&typ, &name, &val); err != nil {
			continue
		}
		switch name {
		case "Aria_pagecache_blocks_not_flushed":
			status["blocks_not_flushed"] = parseFloat(val)
		case "Aria_pagecache_blocks_used":
			status["blocks_used"] = parseFloat(val)
		case "Aria_pagecache_blocks_unused":
			status["blocks_unused"] = parseFloat(val)
		case "Aria_pagecache_read_requests":
			status["read_requests"] = parseFloat(val)
		case "Aria_pagecache_reads":
			status["reads"] = parseFloat(val)
		case "Aria_pagecache_write_requests":
			status["write_requests"] = parseFloat(val)
		case "Aria_pagecache_writes":
			status["writes"] = parseFloat(val)
		}
	}

	var metrics []collector.Metric

	readReqs := status["read_requests"]
	reads := status["reads"]
	hitRatio := 1 - safeDiv(reads, readReqs)
	metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.hit_ratio", hitRatio, collector.MetricTypeGauge, labels))

	if val, ok := status["blocks_used"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.blocks_used", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["blocks_unused"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.blocks_unused", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["blocks_not_flushed"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.aria.pagecache.blocks_not_flushed", val, collector.MetricTypeGauge, labels))
	}

	return metrics, rows.Err()
}

func collectMariaDBColumnStore(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var metrics []collector.Metric

	rows, err := db.QueryContext(ctx2,
		"SELECT variable_value FROM information_schema.system_variables WHERE variable_name = 'columnstore_pm_cache_used'")
	if err == nil {
		defer func() { _ = rows.Close() }()
		if rows.Next() {
			var val string
			if err := rows.Scan(&val); err == nil {
				metrics = append(metrics, makeMetric("db.mysql.columnstore.pm.cache.blocks_used", parseFloat(val), collector.MetricTypeGauge, labels))
			}
		}
	}

	rows2, err := db.QueryContext(ctx2,
		"SELECT SUM(extent_state = 'USED') as used, COUNT(*) as total FROM information_schema.columnstore_extents")
	if err == nil {
		defer func() { _ = rows2.Close() }()
		if rows2.Next() {
			var used, total float64
			if err := rows2.Scan(&used, &total); err == nil {
				metrics = append(metrics, makeMetric("db.mysql.columnstore.extent.used", used, collector.MetricTypeGauge, labels))
				metrics = append(metrics, makeMetric("db.mysql.columnstore.extent.total", total, collector.MetricTypeGauge, labels))
			}
		}
	}

	return metrics, nil
}

func collectMariaDBSpider(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2, "SHOW ENGINE SPIDER STATUS")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	poolUsed := 0.0
	poolTotal := 0.0
	linkErrors := 0.0
	linkThreadsRunning := 0.0

	for rows.Next() {
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		colMap := make(map[string]string)
		for i, col := range cols {
			colMap[col] = toStr(values[i])
		}

		if v := colMap["spider_pool_conns"]; v != "" {
			poolUsed = parseFloat(v)
		}
		if v := colMap["spider_pool_total_conns"]; v != "" {
			poolTotal = parseFloat(v)
		}
		if v := colMap["spider_link_error_count"]; v != "" {
			linkErrors = parseFloat(v)
		}
		if v := colMap["spider_link_threads_running"]; v != "" {
			linkThreadsRunning = parseFloat(v)
		}
	}

	var metrics []collector.Metric
	metrics = append(metrics, makeMetric("db.mysql.spider.conn_pool.used", poolUsed, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.spider.conn_pool.total", poolTotal, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.spider.link_errors", linkErrors, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.spider.link_threads_running", linkThreadsRunning, collector.MetricTypeGauge, labels))

	return metrics, rows.Err()
}

func collectMariaDBThreadPool(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SHOW GLOBAL STATUS WHERE Variable_name IN ("+
			"'Threadpool_threads', 'Threadpool_active_threads', 'Threadpool_idle_threads', "+
			"'Threadpool_overflows', 'Threadpool_waits', 'Threadpool_queues')")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	status := make(map[string]float64)
	for rows.Next() {
		var name, val string
		if err := rows.Scan(&name, &val); err != nil {
			continue
		}
		status[name] = parseFloat(val)
	}

	var metrics []collector.Metric

	threads := status["Threadpool_threads"]
	active := status["Threadpool_active_threads"]
	idle := status["Threadpool_idle_threads"]

	metrics = append(metrics, makeMetric("db.mysql.threadpool.threads", threads, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.threadpool.active_threads", active, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.threadpool.idle_threads", idle, collector.MetricTypeGauge, labels))

	if val, ok := status["Threadpool_overflows"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.overflows", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Threadpool_waits"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.waits", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Threadpool_queues"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.queues", val, collector.MetricTypeGauge, labels))
	}

	utilization := safeDiv(active, threads)
	metrics = append(metrics, makeMetric("db.mysql.threadpool.utilization", utilization, collector.MetricTypeGauge, labels))

	return metrics, rows.Err()
}

func collectMariaDBMultiSourceReplication(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2, "SHOW ALL SLAVES STATUS")
	if err != nil {
		return collectReplicationStatus(ctx, db, labels)
	}
	defer func() { _ = rows.Close() }()

	var allMetrics []collector.Metric
	for rows.Next() {
		cols, err := rows.Columns()
		if err != nil {
			continue
		}
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}

		colMap := make(map[string]string)
		for i, col := range cols {
			colMap[col] = toStr(values[i])
		}

		channelLabels := make(map[string]string, len(labels))
		for k, v := range labels {
			channelLabels[k] = v
		}
		if ch, ok := colMap["Connection_name"]; ok && ch != "" {
			channelLabels["channel"] = ch
		}

		allMetrics = append(allMetrics, parseReplicationRow(colMap, channelLabels)...)
	}
	return allMetrics, rows.Err()
}

func collectMariaDBUserStats(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SELECT USER, TOTAL_CONNECTIONS, CONCURRENT_CONNECTIONS, "+
			"CPU_TIME, ROWS_READ, ROWS_SENT, ROWS_INSERTED, ROWS_UPDATED, ROWS_DELETED, "+
			"BUSY_TIME, SELECT_COMMANDS, UPDATE_COMMANDS, OTHER_COMMANDS "+
			"FROM information_schema.USER_STATISTICS")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var allMetrics []collector.Metric
	for rows.Next() {
		var user string
		var totalConns, concurrentConns float64
		var cpuTime, rowsRead, rowsSent, rowsInserted, rowsUpdated, rowsDeleted float64
		var busyTime, selectCmds, updateCmds, otherCmds float64

		if err := rows.Scan(&user, &totalConns, &concurrentConns,
			&cpuTime, &rowsRead, &rowsSent, &rowsInserted, &rowsUpdated, &rowsDeleted,
			&busyTime, &selectCmds, &updateCmds, &otherCmds); err != nil {
			continue
		}

		userLabels := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			userLabels[k] = v
		}
		userLabels["user"] = user

		allMetrics = append(allMetrics,
			makeMetric("db.mysql.userstats.total_connections", totalConns, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.concurrent_connections", concurrentConns, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.cpu_time", cpuTime, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.rows_read", rowsRead, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.rows_written", rowsInserted+rowsUpdated+rowsDeleted, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.busy_time", busyTime, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.select_commands", selectCmds, collector.MetricTypeGauge, userLabels),
			makeMetric("db.mysql.userstats.update_commands", updateCmds, collector.MetricTypeGauge, userLabels),
		)
	}
	return allMetrics, rows.Err()
}
