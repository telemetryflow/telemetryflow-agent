package mssql

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectQueryStats(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TOP 50
			qs.query_hash,
			COUNT(*) as plan_count,
			SUM(qs.execution_count) as total_executions,
			SUM(qs.total_elapsed_time) / 1000.0 as total_elapsed_ms,
			SUM(qs.total_worker_time) / 1000.0 as total_cpu_ms,
			SUM(qs.total_logical_reads) as total_logical_reads,
			SUM(qs.total_physical_reads) as total_physical_reads,
			SUM(qs.total_logical_writes) as total_logical_writes,
			AVG(qs.total_elapsed_time / NULLIF(qs.execution_count, 0)) / 1000.0 as avg_elapsed_ms,
			AVG(qs.total_worker_time / NULLIF(qs.execution_count, 0)) / 1000.0 as avg_cpu_ms,
			MAX(qs.max_elapsed_time) / 1000.0 as max_elapsed_ms,
			MAX(qs.max_worker_time) / 1000.0 as max_cpu_ms,
			MAX(qs.max_logical_reads) as max_logical_reads,
			MAX(qs.max_dop) as max_dop
		FROM sys.dm_exec_query_stats qs
		GROUP BY qs.query_hash
		ORDER BY SUM(qs.total_elapsed_time) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var queryHash []byte
		var planCount, totalExecs int
		var totalElapsedMs, totalCpuMs, totalLogicalReads, totalPhysicalReads, totalLogicalWrites float64
		var avgElapsedMs, avgCpuMs, maxElapsedMs, maxCpuMs, maxLogicalReads, maxDop float64
		if err := rows.Scan(
			&queryHash, &planCount, &totalExecs,
			&totalElapsedMs, &totalCpuMs, &totalLogicalReads, &totalPhysicalReads, &totalLogicalWrites,
			&avgElapsedMs, &avgCpuMs, &maxElapsedMs, &maxCpuMs, &maxLogicalReads, &maxDop,
		); err != nil {
			continue
		}

		hashStr := fmt.Sprintf("%x", queryHash)
		qLabels := copyLabels(labels)
		qLabels["mssql_query_hash"] = hashStr

		all = append(all,
			makeMetric("mssql.query.plan_count", float64(planCount), collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.total_executions", float64(totalExecs), collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.total_elapsed_ms", totalElapsedMs, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.total_cpu_ms", totalCpuMs, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.total_logical_reads", totalLogicalReads, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.total_physical_reads", totalPhysicalReads, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.total_logical_writes", totalLogicalWrites, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.avg_elapsed_ms", avgElapsedMs, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.avg_cpu_ms", avgCpuMs, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.max_elapsed_ms", maxElapsedMs, collector.MetricTypeGauge, qLabels),
			makeMetric("mssql.query.max_cpu_ms", maxCpuMs, collector.MetricTypeGauge, qLabels),
		)
	}
	return all, rows.Err()
}
