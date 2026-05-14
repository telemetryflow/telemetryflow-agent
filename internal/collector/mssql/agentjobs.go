package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectAgentJobs(ctx context.Context, db *sql.DB, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			j.name as job_name,
			j.enabled as job_enabled,
			CASE
				WHEN jh.run_status = 0 THEN 'failed'
				WHEN jh.run_status = 1 THEN 'succeeded'
				WHEN jh.run_status = 2 THEN 'retry'
				WHEN jh.run_status = 3 THEN 'canceled'
				WHEN jh.run_status = 4 THEN 'in_progress'
				ELSE 'unknown'
			END as last_run_status,
			jh.run_duration,
			jh.run_date,
			jh.run_time,
			js.next_run_date,
			js.next_run_time
		FROM msdb.dbo.sysjobs j
		LEFT JOIN msdb.dbo.sysjobhistory jh ON j.job_id = jh.job_id
			AND jh.step_id = 0
			AND jh.instance_id = (
				SELECT MAX(instance_id) FROM msdb.dbo.sysjobhistory WHERE job_id = j.job_id AND step_id = 0
			)
		LEFT JOIN msdb.dbo.sysjobschedules jsch ON j.job_id = jsch.job_id
		LEFT JOIN msdb.dbo.sysschedules js ON jsch.schedule_id = js.schedule_id
		WHERE j.enabled = 1
		ORDER BY j.name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []collector.Metric
	for rows.Next() {
		var jobName string
		var enabled int
		var lastRunStatus string
		var runDuration int
		var runDate, runTime, nextRunDate, nextRunTime sql.NullInt64
		if err := rows.Scan(
			&jobName, &enabled, &lastRunStatus,
			&runDuration, &runDate, &runTime,
			&nextRunDate, &nextRunTime,
		); err != nil {
			continue
		}

		jobLabels := copyLabels(labels)
		jobLabels["mssql_agent_job"] = jobName
		jobLabels["mssql_agent_job_status"] = lastRunStatus

		all = append(all,
			makeMetric("mssql.agent_job.enabled", float64(enabled), collector.MetricTypeGauge, jobLabels),
			makeMetric("mssql.agent_job.run_duration_seconds", hhmmssToSeconds(runDuration), collector.MetricTypeGauge, jobLabels),
		)

		if lastRunStatus == "failed" {
			all = append(all, makeMetric("mssql.agent_job.failed", 1, collector.MetricTypeGauge, jobLabels))
		}

		_ = fmt.Sprintf("%v%v%v%v", runDate, runTime, nextRunDate, nextRunTime)
		_ = time.Now()
	}
	return all, rows.Err()
}

func hhmmssToSeconds(hhmmss int) float64 {
	hours := hhmmss / 10000
	minutes := (hhmmss % 10000) / 100
	seconds := hhmmss % 100
	return float64(hours*3600 + minutes*60 + seconds)
}
