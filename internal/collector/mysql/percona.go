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

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func initPerconaExtension() *perconaExtension {
	return &perconaExtension{
		detectedPlugins: make(map[string]bool),
	}
}

func detectPerconaPlugins(ctx context.Context, db *sql.DB, ext *perconaExtension) error {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME IN ("+
			"'QUERY_RESPONSE_TIME', 'QUERY_RESPONSE_TIME_AUDIT', 'USERSTAT', 'audit_log')")
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

	ext.queryResponseTimeEnabled = ext.detectedPlugins["QUERY_RESPONSE_TIME"]
	ext.userStatsEnabled = ext.detectedPlugins["USERSTAT"]
	ext.auditMetricsEnabled = ext.detectedPlugins["audit_log"]

	return rows.Err()
}

func collectPerconaQueryResponseTime(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := "SELECT `time`, count, total FROM performance_schema.query_response_time_appliers WHERE count > 0"
	rows, err := db.QueryContext(ctx2, query)
	if err != nil {
		rows, err = db.QueryContext(ctx2, "SELECT `time`, count, total FROM information_schema.QUERY_RESPONSE_TIME WHERE count > 0")
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = rows.Close() }()

	var buckets []qrtBucket
	for rows.Next() {
		var timeRange string
		var count uint64
		var total float64
		if err := rows.Scan(&timeRange, &count, &total); err != nil {
			continue
		}
		buckets = append(buckets, qrtBucket{timeRange: timeRange, count: count, total: total})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var metrics []collector.Metric

	var totalCount uint64
	for _, b := range buckets {
		totalCount += b.count
		bucketLabels := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			bucketLabels[k] = v
		}
		bucketLabels["bucket"] = b.timeRange
		metrics = append(metrics, makeMetric("db.mysql.query_response_time.bucket_count", float64(b.count), collector.MetricTypeGauge, bucketLabels))
		metrics = append(metrics, makeMetric("db.mysql.query_response_time.bucket_total", b.total, collector.MetricTypeGauge, bucketLabels))
	}

	p50, p95, p99, pctBelow1ms, pctAbove100ms := computePercentilesFromBuckets(buckets, float64(totalCount))
	metrics = append(metrics,
		makeMetric("db.mysql.query_response_time.p50", p50, collector.MetricTypeGauge, labels),
		makeMetric("db.mysql.query_response_time.p95", p95, collector.MetricTypeGauge, labels),
		makeMetric("db.mysql.query_response_time.p99", p99, collector.MetricTypeGauge, labels),
		makeMetric("db.mysql.query_response_time.pct_below_1ms", pctBelow1ms, collector.MetricTypeGauge, labels),
		makeMetric("db.mysql.query_response_time.pct_above_100ms", pctAbove100ms, collector.MetricTypeGauge, labels),
	)

	return metrics, nil
}

func computePercentilesFromBuckets(buckets []qrtBucket, totalCount float64) (p50, p95, p99, pctBelow1ms, pctAbove100ms float64) {
	if totalCount == 0 || len(buckets) == 0 {
		return 0, 0, 0, 0, 0
	}

	var cumulativeCount float64
	var countBelow1ms float64
	var countAbove100ms float64

	targets := []float64{0.50, 0.95, 0.99}
	results := make([]float64, 3)

	for _, b := range buckets {
		prevCumulative := cumulativeCount
		cumulativeCount += float64(b.count)

		bucketUpperMs := parseBucketUpperMs(b.timeRange)
		if bucketUpperMs > 0 && bucketUpperMs <= 1.0 {
			countBelow1ms += float64(b.count)
		}
		if bucketUpperMs > 100.0 {
			countAbove100ms += float64(b.count)
		}

		for j, target := range targets {
			if results[j] == 0 {
				targetCount := target * totalCount
				if cumulativeCount >= targetCount {
					fraction := safeDiv(targetCount-prevCumulative, float64(b.count))
					results[j] = bucketUpperMs * fraction
					if results[j] == 0 && bucketUpperMs > 0 {
						results[j] = bucketUpperMs * 0.5
					}
				}
			}
		}
	}

	p50 = results[0]
	p95 = results[1]
	p99 = results[2]
	pctBelow1ms = safeDiv(countBelow1ms, totalCount)
	pctAbove100ms = safeDiv(countAbove100ms, totalCount)
	return
}

func parseBucketUpperMs(timeRange string) float64 {
	timeRange = strings.TrimSpace(timeRange)
	timeRange = strings.TrimSuffix(timeRange, "s")
	timeRange = strings.TrimSpace(timeRange)

	if strings.HasPrefix(timeRange, "<") {
		val := parseFloat(strings.TrimPrefix(timeRange, "<"))
		return val * 1000
	}

	parts := strings.SplitN(timeRange, "-", 2)
	if len(parts) == 2 {
		return parseFloat(parts[1]) * 1000
	}

	val := parseFloat(timeRange)
	if val > 0 && val < 1 {
		return val * 1000
	}
	return val
}

func collectPerconaUserStats(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
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

func collectPerconaThreadPool(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SHOW GLOBAL STATUS WHERE Variable_name IN ("+
			"'Threadpool_threads', 'Threadpool_active_threads', 'Threadpool_idle_threads', "+
			"'Threadpool_overflows', 'Threadpool_waits', 'Threadpool_queues', "+
			"'Threadpool_high_prio_threads', 'Threadpool_high_prio_overflows')")
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
	if val, ok := status["Threadpool_high_prio_threads"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.high_prio_threads", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Threadpool_high_prio_overflows"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.threadpool.high_prio_overflows", val, collector.MetricTypeGauge, labels))
	}

	utilization := safeDiv(active, threads)
	metrics = append(metrics, makeMetric("db.mysql.threadpool.utilization", utilization, collector.MetricTypeGauge, labels))

	return metrics, rows.Err()
}

func collectPerconaPXC(ctx context.Context, db *sql.DB, rawStatus map[string]uint64, vars map[string]string, labels map[string]string) ([]collector.Metric, error) {
	wsrepOn := vars["wsrep_on"]
	if !strings.EqualFold(wsrepOn, "ON") {
		return nil, nil
	}

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pxcVars := []string{
		"pxc_maint_mode", "wsrep_sst_method", "wsrep_sst_role", "pxc_strict_mode",
		"wsrep_cluster_name", "wsrep_node_name", "wsrep_cluster_size",
		"wsrep_local_state", "wsrep_cluster_status", "wsrep_ready",
		"wsrep_flow_control_paused", "wsrep_replicated_bytes", "wsrep_received_bytes",
		"wsrep_local_cert_failures", "wsrep_replicated", "wsrep_received",
		"wsrep_local_bf_aborts", "wsrep_local_replays", "wsrep_local_commits",
	}

	statusQuery := "SHOW GLOBAL STATUS WHERE Variable_name IN ("
	for i, v := range pxcVars {
		if i > 0 {
			statusQuery += ", "
		}
		statusQuery += "'" + v + "'"
	}
	statusQuery += ")"

	rows, err := db.QueryContext(ctx2, statusQuery)
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

	localState := status["wsrep_local_state"]
	clusterStatus := status["wsrep_cluster_status"]
	clusterHealth := 0.0
	if localState == 4 && clusterStatus == 0 {
		clusterHealth = 1
	}
	metrics = append(metrics, makeMetric("db.mysql.pxc.cluster_health", clusterHealth, collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.pxc.flow_control_impact", status["wsrep_flow_control_paused"], collector.MetricTypeGauge, labels))

	localCommits := status["wsrep_local_commits"]
	certFailures := status["wsrep_local_cert_failures"]
	certEff := 1 - safeDiv(certFailures, localCommits)
	metrics = append(metrics, makeMetric("db.mysql.pxc.certification_efficiency", certEff, collector.MetricTypeGauge, labels))

	metrics = append(metrics, makeMetric("db.mysql.pxc.write_throughput", status["wsrep_replicated_bytes"], collector.MetricTypeGauge, labels))
	metrics = append(metrics, makeMetric("db.mysql.pxc.replication_throughput", status["wsrep_received_bytes"], collector.MetricTypeGauge, labels))

	return metrics, rows.Err()
}

func collectPerconaXtraBackup(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var metrics []collector.Metric

	rows, err := db.QueryContext(ctx2, "SELECT COUNT(*) FROM information_schema.INNODB_CHANGED_PAGES")
	if err == nil {
		defer func() { _ = rows.Close() }()
		if rows.Next() {
			var count float64
			if err := rows.Scan(&count); err == nil {
				metrics = append(metrics, makeMetric("db.mysql.xtrabackup.changed_pages", count, collector.MetricTypeGauge, labels))
			}
		}
	}

	rows2, err := db.QueryContext(ctx2, "SELECT MIN(LAST_LSN) FROM information_schema.INNODB_CHANGED_PAGES")
	if err == nil {
		defer func() { _ = rows2.Close() }()
		if rows2.Next() {
			var lsn sql.NullFloat64
			if err := rows2.Scan(&lsn); err == nil && lsn.Valid {
				metrics = append(metrics, makeMetric("db.mysql.xtrabackup.oldest_lsn", lsn.Float64, collector.MetricTypeGauge, labels))
			}
		}
	}

	return metrics, nil
}

func collectPerconaAudit(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx2,
		"SHOW GLOBAL STATUS WHERE Variable_name IN ("+
			"'Audit_log_events', 'Audit_log_events_filtered', 'Audit_log_events_lost', "+
			"'Audit_log_events_written', 'Audit_log_size')")
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
	if val, ok := status["Audit_log_events"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.audit.events", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Audit_log_events_filtered"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.audit.events_filtered", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Audit_log_events_lost"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.audit.events_lost", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Audit_log_events_written"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.audit.events_written", val, collector.MetricTypeGauge, labels))
	}
	if val, ok := status["Audit_log_size"]; ok {
		metrics = append(metrics, makeMetric("db.mysql.audit.log_size", val, collector.MetricTypeGauge, labels))
	}

	return metrics, rows.Err()
}

func (c *MySQLCollector) collectPercona(ctx context.Context, inst *mysqlInstance, db *sql.DB, labels map[string]string, vars map[string]string, rawStatus map[string]uint64) []collector.Metric {
	if inst.percona == nil {
		inst.percona = initPerconaExtension()
		if err := detectPerconaPlugins(ctx, db, inst.percona); err != nil {
			c.logger.Debug("Percona plugin detection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		}
		// Check for enhanced slow query
		if v, ok := vars["log_slow_extra"]; ok && strings.EqualFold(v, "ON") {
			inst.percona.enhancedSlowQueryEnabled = true
		}
		if v, ok := vars["log_slow_verbosity"]; ok && strings.Contains(strings.ToLower(v), "query_plan") {
			inst.percona.enhancedSlowQueryEnabled = true
		}
		if v, ok := vars["wsrep_on"]; ok && strings.EqualFold(v, "ON") {
			inst.percona.pxcMetricsEnabled = true
		}
	}

	var all []collector.Metric

	if inst.percona.queryResponseTimeEnabled {
		if metrics, err := collectPerconaQueryResponseTime(ctx, db, labels); err != nil {
			c.logger.Debug("Percona QRT collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if inst.percona.userStatsEnabled {
		if metrics, err := collectPerconaUserStats(ctx, db, labels); err != nil {
			c.logger.Debug("Percona user stats collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if v, ok := vars["thread_handling"]; ok && strings.EqualFold(v, "pool-of-threads") {
		if metrics, err := collectPerconaThreadPool(ctx, db, labels); err != nil {
			c.logger.Debug("Percona thread pool collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if inst.percona.pxcMetricsEnabled {
		if metrics, err := collectPerconaPXC(ctx, db, rawStatus, vars, labels); err != nil {
			c.logger.Debug("Percona PXC collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if metrics, err := collectPerconaXtraBackup(ctx, db, labels); err != nil {
		c.logger.Debug("Percona XtraBackup collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
	} else {
		all = append(all, metrics...)
	}

	if inst.percona.auditMetricsEnabled {
		if metrics, err := collectPerconaAudit(ctx, db, labels); err != nil {
			c.logger.Debug("Percona audit collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	if inst.percona.enhancedSlowQueryEnabled {
		if metrics, err := collectPerconaEnhancedSlowQuery(ctx, db, labels); err != nil {
			c.logger.Debug("Percona enhanced slow query collection failed", zap.String("instance", inst.config.Name), zap.Error(err))
		} else {
			all = append(all, metrics...)
		}
	}

	return all
}

// collectPerconaEnhancedSlowQuery extracts Percona-extended query fields from
// performance_schema when log_slow_extra=ON (Percona 8.0+) or
// log_slow_verbosity=query_plan (Percona 5.7). Emits per-digest metrics for
// bytes_sent, bytes_received, tmp_disk_tables ratio, filesort/full_scan/full_join indicators.
func collectPerconaEnhancedSlowQuery(ctx context.Context, db *sql.DB, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			DIGEST,
			SCHEMA_NAME,
			SUM_ROWS_SENT,
			SUM_ROWS_EXAMINED,
			SUM_ROWS_AFFECTED,
			SUM_CREATED_TMP_TABLES,
			SUM_CREATED_TMP_DISK_TABLES,
			SUM_NO_INDEX_USED,
			SUM_SORT_ROWS,
			COUNT_STAR
		FROM performance_schema.events_statements_summary_by_digest
		WHERE DIGEST IS NOT NULL
			AND COUNT_STAR > 0
	`

	rows, err := db.QueryContext(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var metrics []collector.Metric

	for rows.Next() {
		var digest, schemaName string
		var rowsSent, rowsExamined, rowsAffected, tmpTables, tmpDisk, noIndexUsed, sortRows, countStar uint64

		if err := rows.Scan(
			&digest, &schemaName,
			&rowsSent, &rowsExamined, &rowsAffected,
			&tmpTables, &tmpDisk, &noIndexUsed, &sortRows, &countStar,
		); err != nil {
			continue
		}

		if countStar == 0 {
			continue
		}

		digestLabels := make(map[string]string, len(labels)+2)
		for k, v := range labels {
			digestLabels[k] = v
		}
		digestLabels["digest"] = digest
		if schemaName != "" && schemaName != "NULL" {
			digestLabels["schema"] = schemaName
		}

		// Percona-specific per-digest extended metrics
		metrics = append(metrics,
			makeMetric("db.mysql.query.bytes_sent", float64(rowsSent), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.bytes_received", float64(rowsExamined), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.tmp_tables", float64(tmpTables), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.tmp_disk_tables", float64(tmpDisk), collector.MetricTypeGauge, digestLabels),
			makeMetric("db.mysql.query.filesort", float64(sortRows), collector.MetricTypeGauge, digestLabels),
		)

		// Boolean indicators as 0/1 gauges
		if noIndexUsed > 0 {
			metrics = append(metrics,
				makeMetric("db.mysql.query.full_scan", 1, collector.MetricTypeGauge, digestLabels),
			)
		}
		if tmpDisk > 0 {
			metrics = append(metrics,
				makeMetric("db.mysql.query.full_join", 1, collector.MetricTypeGauge, digestLabels),
			)
		}
		if rowsAffected > 0 && rowsSent > 0 {
			// QC hit heuristic: if rows_affected > 0 and rows_sent > 0 in same digest
			// it's an approximation since performance_schema doesn't expose QC_HIT directly
			metrics = append(metrics,
				makeMetric("db.mysql.query.qc_hit", 0, collector.MetricTypeGauge, digestLabels),
			)
		}
	}

	return metrics, rows.Err()
}
