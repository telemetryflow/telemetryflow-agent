package mssql

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectQueryStore(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TOP 30
			qs.query_id,
			qs.plan_id,
			rs.avg_duration / 1000.0 as avg_duration_ms,
			rs.avg_cpu_time / 1000.0 as avg_cpu_ms,
			rs.avg_logical_io_reads,
			rs.avg_logical_io_writes,
			rs.avg_physical_io_reads,
			rs.count_executions,
			qs.query_sql_text
		FROM sys.database_query_store_query qs
		JOIN sys.database_query_store_plan qp ON qs.query_id = qp.query_id
		JOIN sys.database_query_store_runtime_stats rs ON qp.plan_id = rs.plan_id
		WHERE rs.last_execution_time >= DATEADD(HOUR, -1, GETUTCDATE())
		ORDER BY rs.avg_duration DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var queryID, planID int64
		var avgDurationMs, avgCpuMs float64
		var avgLogicalReads, avgLogicalWrites, avgPhysicalReads float64
		var countExecs int64
		var sqlText string
		if err := rows.Scan(
			&queryID, &planID,
			&avgDurationMs, &avgCpuMs,
			&avgLogicalReads, &avgLogicalWrites, &avgPhysicalReads,
			&countExecs, &sqlText,
		); err != nil {
			continue
		}

		qsLabels := copyLabels(labels)
		qsLabels["mssql_query_store_id"] = fmt.Sprintf("%d", queryID)
		qsLabels["mssql_query_store_plan_id"] = fmt.Sprintf("%d", planID)

		all = append(all,
			makeMetric("mssql.querystore.avg_duration_ms", avgDurationMs, collector.MetricTypeGauge, qsLabels),
			makeMetric("mssql.querystore.avg_cpu_ms", avgCpuMs, collector.MetricTypeGauge, qsLabels),
			makeMetric("mssql.querystore.avg_logical_reads", avgLogicalReads, collector.MetricTypeGauge, qsLabels),
			makeMetric("mssql.querystore.avg_logical_writes", avgLogicalWrites, collector.MetricTypeGauge, qsLabels),
			makeMetric("mssql.querystore.avg_physical_reads", avgPhysicalReads, collector.MetricTypeGauge, qsLabels),
			makeMetric("mssql.querystore.count_executions", float64(countExecs), collector.MetricTypeGauge, qsLabels),
		)
	}
	return all, rows.Err()
}
