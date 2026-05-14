package mssql

import (
	"context"
	"database/sql"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectTempDB(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var all []collector.Metric

	spaceMetrics, err := collectTempDBSpace(ctx, db, labels, logger)
	if err != nil {
		logger.Debug("TempDB space collection failed", zap.Error(err))
	} else {
		all = append(all, spaceMetrics...)
	}

	contentionMetrics, err := collectTempDBContention(ctx, db, labels, logger)
	if err != nil {
		logger.Debug("TempDB contention collection failed", zap.Error(err))
	} else {
		all = append(all, contentionMetrics...)
	}

	return all, nil
}

func collectTempDBSpace(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			SUM(user_object_reserved_page_count) * 8.0 / 1024.0 as user_objects_mb,
			SUM(internal_object_reserved_page_count) * 8.0 / 1024.0 as internal_objects_mb,
			SUM(version_store_reserved_page_count) * 8.0 / 1024.0 as version_store_mb,
			SUM(unallocated_extent_page_count) * 8.0 / 1024.0 as free_space_mb,
			SUM(mixed_extent_page_count) * 8.0 / 1024.0 as mixed_extents_mb
		FROM sys.dm_db_file_space_usage
		WHERE database_id = 2
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		var userObjMB, internalObjMB, versionStoreMB, freeSpaceMB, mixedExtMB float64
		if err := rows.Scan(&userObjMB, &internalObjMB, &versionStoreMB, &freeSpaceMB, &mixedExtMB); err != nil {
			return nil, err
		}

		totalMB := userObjMB + internalObjMB + versionStoreMB + freeSpaceMB + mixedExtMB

		all := []collector.Metric{
			makeMetric("mssql.tempdb.user_objects_mb", userObjMB, collector.MetricTypeGauge, labels),
			makeMetric("mssql.tempdb.internal_objects_mb", internalObjMB, collector.MetricTypeGauge, labels),
			makeMetric("mssql.tempdb.version_store_mb", versionStoreMB, collector.MetricTypeGauge, labels),
			makeMetric("mssql.tempdb.free_space_mb", freeSpaceMB, collector.MetricTypeGauge, labels),
			makeMetric("mssql.tempdb.total_size_mb", totalMB, collector.MetricTypeGauge, labels),
		}
		return all, nil
	}
	return nil, rows.Err()
}

func collectTempDBContention(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var waitCount, waitTimeMs float64
	err := db.QueryRowContext(ctx, `
		SELECT
			SUM(waiting_tasks_count),
			SUM(wait_duration_ms)
		FROM sys.dm_os_wait_stats
		WHERE wait_type IN ('PAGELATCH_EX', 'PAGELATCH_UP', 'PAGEIOLATCH_EX', 'PAGEIOLATCH_UP')
	`).Scan(&waitCount, &waitTimeMs)
	if err != nil {
		return nil, err
	}

	return []collector.Metric{
		makeMetric("mssql.tempdb.contention.wait_count", waitCount, collector.MetricTypeGauge, labels),
		makeMetric("mssql.tempdb.contention.wait_time_ms", waitTimeMs, collector.MetricTypeGauge, labels),
	}, nil
}
