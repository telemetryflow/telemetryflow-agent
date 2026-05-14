package mssql

import (
	"context"
	"database/sql"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectAzureSQLDBMetrics(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var all []collector.Metric

	dtuMetrics, err := collectAzureDTU(ctx, db, labels, logger)
	if err != nil {
		logger.Debug("Azure DTU metrics failed", zap.Error(err))
	} else {
		all = append(all, dtuMetrics...)
	}

	storageMetrics, err := collectAzureStorage(ctx, db, labels, logger)
	if err != nil {
		logger.Debug("Azure storage metrics failed", zap.Error(err))
	} else {
		all = append(all, storageMetrics...)
	}

	return all, nil
}

func collectAzureDTU(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var cpuPercent, readPercent, writePercent, dtuPercent float64
	var dtuLimit int

	err := db.QueryRowContext(ctx, `
		SELECT
			(SELECT cntr_value FROM sys.dm_os_performance_counters
			 WHERE object_name LIKE '%Azure SQL Database%' AND counter_name = 'CPU percentage') as cpu_percent,
			(SELECT cntr_value FROM sys.dm_os_performance_counters
			 WHERE object_name LIKE '%Azure SQL Database%' AND counter_name = 'Data IO percentage') as read_percent,
			(SELECT cntr_value FROM sys.dm_os_performance_counters
			 WHERE object_name LIKE '%Azure SQL Database%' AND counter_name = 'Log IO percentage') as write_percent,
			(SELECT cntr_value FROM sys.dm_os_performance_counters
			 WHERE object_name LIKE '%Azure SQL Database%' AND counter_name = 'DTU percentage') as dtu_percent,
			(SELECT cntr_value FROM sys.dm_os_performance_counters
			 WHERE object_name LIKE '%Azure SQL Database%' AND counter_name = 'DTU limit') as dtu_limit
	`).Scan(&cpuPercent, &readPercent, &writePercent, &dtuPercent, &dtuLimit)
	if err != nil {
		return nil, err
	}

	return []collector.Metric{
		makeMetric("mssql.azure.cpu_percent", cpuPercent, collector.MetricTypeGauge, labels),
		makeMetric("mssql.azure.data_io_percent", readPercent, collector.MetricTypeGauge, labels),
		makeMetric("mssql.azure.log_io_percent", writePercent, collector.MetricTypeGauge, labels),
		makeMetric("mssql.azure.dtu_percent", dtuPercent, collector.MetricTypeGauge, labels),
		makeMetric("mssql.azure.dtu_limit", float64(dtuLimit), collector.MetricTypeGauge, labels),
	}, nil
}

func collectAzureStorage(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var storageMB, maxStorageMB float64
	err := db.QueryRowContext(ctx, `
		SELECT
			(SELECT cntr_value FROM sys.dm_os_performance_counters
			 WHERE object_name LIKE '%Azure SQL Database%' AND counter_name = 'Storage space used (MB)'),
			(SELECT cntr_value FROM sys.dm_os_performance_counters
			 WHERE object_name LIKE '%Azure SQL Database%' AND counter_name = 'Storage space allocated (MB)')
	`).Scan(&storageMB, &maxStorageMB)
	if err != nil {
		return nil, err
	}

	storagePercent := safeDiv(storageMB, maxStorageMB) * 100

	return []collector.Metric{
		makeMetric("mssql.azure.storage_used_mb", storageMB, collector.MetricTypeGauge, labels),
		makeMetric("mssql.azure.storage_allocated_mb", maxStorageMB, collector.MetricTypeGauge, labels),
		makeMetric("mssql.azure.storage_percent", storagePercent, collector.MetricTypeGauge, labels),
	}, nil
}
