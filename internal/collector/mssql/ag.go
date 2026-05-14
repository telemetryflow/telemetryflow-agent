package mssql

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectAGStatus(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			ar.replica_server_name,
			ar.availability_mode_desc,
			ar.failover_mode_desc,
			ar.synchronization_health_desc,
			drs.synchronization_state_desc,
			drs.synchronization_health_desc as database_health,
			drs.database_name,
			drs.log_send_queue_size,
			drs.log_send_rate,
			drs.redo_queue_size,
			drs.redo_rate,
			drs.secondary_lag_seconds
		FROM sys.dm_hadr_availability_replica_states ars
		JOIN sys.availability_replicas ar ON ars.replica_id = ar.replica_id
		JOIN sys.dm_hadr_database_replica_states drs ON ars.replica_id = drs.replica_id
		WHERE ars.is_local = 1
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var replicaName, availMode, failoverMode, syncHealth string
		var syncState, dbHealth, dbName string
		var logSendQueue, logSendRate, redoQueue, redoRate, secondaryLag sql.NullFloat64
		if err := rows.Scan(
			&replicaName, &availMode, &failoverMode, &syncHealth,
			&syncState, &dbHealth, &dbName,
			&logSendQueue, &logSendRate, &redoQueue, &redoRate, &secondaryLag,
		); err != nil {
			continue
		}

		agLabels := copyLabels(labels)
		agLabels["mssql_ag_replica"] = replicaName
		agLabels["mssql_ag_database"] = dbName
		agLabels["mssql_ag_sync_state"] = syncState
		agLabels["mssql_ag_health"] = syncHealth

		syncStateVal := 0.0
		switch syncState {
		case "NOT SYNCHRONIZING":
			syncStateVal = 0
		case "SYNCHRONIZING":
			syncStateVal = 1
		case "SYNCHRONIZED":
			syncStateVal = 2
		case "REVERTING":
			syncStateVal = 3
		case "INITIALIZING":
			syncStateVal = 4
		}

		all = append(all,
			makeMetric("mssql.ag.sync_state", syncStateVal, collector.MetricTypeGauge, agLabels),
		)

		if logSendQueue.Valid {
			all = append(all, makeMetric("mssql.ag.log_send_queue_size_kb", logSendQueue.Float64, collector.MetricTypeGauge, agLabels))
		}
		if logSendRate.Valid {
			all = append(all, makeMetric("mssql.ag.log_send_rate_kb_sec", logSendRate.Float64, collector.MetricTypeGauge, agLabels))
		}
		if redoQueue.Valid {
			all = append(all, makeMetric("mssql.ag.redo_queue_size_kb", redoQueue.Float64, collector.MetricTypeGauge, agLabels))
		}
		if redoRate.Valid {
			all = append(all, makeMetric("mssql.ag.redo_rate_kb_sec", redoRate.Float64, collector.MetricTypeGauge, agLabels))
		}
		if secondaryLag.Valid {
			all = append(all, makeMetric("mssql.ag.secondary_lag_seconds", secondaryLag.Float64, collector.MetricTypeGauge, agLabels))
		}

		_ = fmt.Sprintf("%s%s%s", availMode, failoverMode, dbHealth)
	}
	return all, rows.Err()
}
