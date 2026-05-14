package mssql

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectIndexStats(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var all []collector.Metric

	missingIdxMetrics, err := collectMissingIndexes(ctx, db, labels, logger)
	if err != nil {
		logger.Debug("Missing index collection failed", zap.Error(err))
	} else {
		all = append(all, missingIdxMetrics...)
	}

	fragMetrics, err := collectIndexFragmentation(ctx, db, labels, logger)
	if err != nil {
		logger.Debug("Index fragmentation collection failed", zap.Error(err))
	} else {
		all = append(all, fragMetrics...)
	}

	return all, nil
}

func collectMissingIndexes(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TOP 30
			DB_NAME(mid.database_id) as database_name,
			mid.statement as table_name,
			mid.equality_columns,
			mid.inequality_columns,
			mid.included_columns,
			migs.user_seeks,
			migs.user_scans,
			migs.avg_total_user_cost,
			migs.avg_user_impact,
			migs.user_seeks * migs.avg_total_user_cost * migs.avg_user_impact / 100.0 as improvement_measure
		FROM sys.dm_db_missing_index_details mid
		JOIN sys.dm_db_missing_index_groups mig ON mid.index_handle = mig.index_handle
		JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
		ORDER BY improvement_measure DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var dbName, tableName string
		var eqCols, ineqCols, incCols sql.NullString
		var userSeeks, userScans int64
		var avgCost, avgImpact, improvement float64
		if err := rows.Scan(
			&dbName, &tableName,
			&eqCols, &ineqCols, &incCols,
			&userSeeks, &userScans,
			&avgCost, &avgImpact, &improvement,
		); err != nil {
			continue
		}

		idxLabels := copyLabels(labels)
		idxLabels["mssql_database"] = dbName
		idxLabels["mssql_table"] = tableName

		all = append(all,
			makeMetric("mssql.index.missing.user_seeks", float64(userSeeks), collector.MetricTypeGauge, idxLabels),
			makeMetric("mssql.index.missing.user_scans", float64(userScans), collector.MetricTypeGauge, idxLabels),
			makeMetric("mssql.index.missing.avg_cost", avgCost, collector.MetricTypeGauge, idxLabels),
			makeMetric("mssql.index.missing.avg_impact", avgImpact, collector.MetricTypeGauge, idxLabels),
			makeMetric("mssql.index.missing.improvement_measure", improvement, collector.MetricTypeGauge, idxLabels),
		)
	}
	return all, rows.Err()
}

func collectIndexFragmentation(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT TOP 50
			DB_NAME(ps.database_id) as database_name,
			OBJECT_NAME(ps.object_id, ps.database_id) as table_name,
			b.name as index_name,
			ps.avg_fragmentation_in_percent,
			ps.page_count,
			ps.avg_page_space_used_in_percent
		FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ps
		JOIN sys.indexes b ON ps.object_id = b.object_id AND ps.index_id = b.index_id
		WHERE ps.avg_fragmentation_in_percent > 10
			AND ps.page_count > 1000
			AND b.name IS NOT NULL
		ORDER BY ps.avg_fragmentation_in_percent DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var dbName, tableName, indexName string
		var fragPercent, pageCount, avgPageSpace float64
		if err := rows.Scan(
			&dbName, &tableName, &indexName,
			&fragPercent, &pageCount, &avgPageSpace,
		); err != nil {
			continue
		}

		idxLabels := copyLabels(labels)
		idxLabels["mssql_database"] = dbName
		idxLabels["mssql_table"] = tableName
		idxLabels["mssql_index_name"] = indexName

		all = append(all,
			makeMetric("mssql.index.fragmentation_percent", fragPercent, collector.MetricTypeGauge, idxLabels),
			makeMetric("mssql.index.page_count", pageCount, collector.MetricTypeGauge, idxLabels),
			makeMetric("mssql.index.avg_page_space_used_percent", avgPageSpace, collector.MetricTypeGauge, idxLabels),
		)
	}
	return all, rows.Err()
}

func fmtNullString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// unused but kept for potential future use
var (
	_ = fmt.Sprintf
	_ = fmtNullString
)
