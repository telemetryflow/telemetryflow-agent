package mssql

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectFileIO(ctx context.Context, db *sql.DB, inst *mssqlInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			DB_NAME(vfs.database_id) as database_name,
			vfs.file_id,
			vfs.num_of_reads,
			vfs.num_of_writes,
			vfs.num_of_bytes_read / 1024.0 / 1024.0 as mb_read,
			vfs.num_of_bytes_written / 1024.0 / 1024.0 as mb_written,
			vfs.io_stall_read_ms,
			vfs.io_stall_write_ms,
			vfs.size_on_disk_bytes / 1024.0 / 1024.0 as size_mb,
			mf.type_desc as file_type,
			mf.name as file_name
		FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
		JOIN sys.master_files mf ON vfs.database_id = mf.database_id AND vfs.file_id = mf.file_id
		WHERE vfs.database_id > 4
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var dbName, fileType, fileName string
		var fileID int
		var numReads, numWrites float64
		var mbRead, mbWritten, stallReadMs, stallWriteMs, sizeMB float64
		if err := rows.Scan(
			&dbName, &fileID,
			&numReads, &numWrites,
			&mbRead, &mbWritten,
			&stallReadMs, &stallWriteMs,
			&sizeMB, &fileType, &fileName,
		); err != nil {
			continue
		}

		ioLabels := copyLabels(labels)
		ioLabels["mssql_database"] = dbName
		ioLabels["mssql_file_type"] = fileType

		avgReadStallMs := safeDiv(stallReadMs, numReads)
		avgWriteStallMs := safeDiv(stallWriteMs, numWrites)

		all = append(all,
			makeMetric("mssql.fileio.num_reads", numReads, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.num_writes", numWrites, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.mb_read", mbRead, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.mb_written", mbWritten, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.read_stall_ms", stallReadMs, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.write_stall_ms", stallWriteMs, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.avg_read_stall_ms", avgReadStallMs, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.avg_write_stall_ms", avgWriteStallMs, collector.MetricTypeGauge, ioLabels),
			makeMetric("mssql.fileio.size_mb", sizeMB, collector.MetricTypeGauge, ioLabels),
		)

		_ = fmt.Sprintf("%d%s", fileID, fileName)
	}
	return all, rows.Err()
}
