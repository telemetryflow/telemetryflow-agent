package timescaledb

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectJobs(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			j.job_id,
			j.application_name AS proc_name,
			COALESCE(j.schedule_interval, '0') AS schedule_interval,
			COALESCE(j.max_runtime, '0') AS max_runtime,
			COALESCE(js.last_run_status, '') AS last_run_status,
			COALESCE(EXTRACT(EPOCH FROM js.last_run_duration), 0) AS last_run_duration_s,
			COALESCE(js.total_successes, 0) AS total_successes,
			COALESCE(js.total_failures, 0) AS total_failures,
			COALESCE(js.total_crashes, 0) AS total_crashes,
			COALESCE(js.next_start, NOW()) AS next_start
		FROM timescaledb_information.jobs j
		LEFT JOIN timescaledb_information.job_stats js ON js.job_id = j.job_id`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []collector.Metric
	totalJobs := 0
	totalScheduled := 0
	totalFailed := 0
	totalCrashed := 0
	stuckCount := 0

	for rows.Next() {
		var jobID int
		var procName, schedInterval, maxRuntime, lastStatus string
		var lastDurS, totalSuccesses, totalFailures, totalCrashes float64
		var nextStart time.Time

		if err := rows.Scan(&jobID, &procName, &schedInterval, &maxRuntime, &lastStatus,
			&lastDurS, &totalSuccesses, &totalFailures, &totalCrashes, &nextStart); err != nil {
			logger.Debug("Failed to scan job row", zap.Error(err))
			continue
		}

		jobLabels := copyLabels(labels)
		jobLabels["job_id"] = time.Duration(0).String()
		if d, err := time.ParseDuration(schedInterval); err == nil {
			jobLabels["job_id"] = d.String()
		}
		jobLabels["proc_name"] = procName
		jobLabels["job_status"] = lastStatus

		nextStartIn := time.Until(nextStart).Seconds()
		if nextStartIn < 0 {
			nextStartIn = 0
		}

		all = append(all,
			makeMetric("db.timescaledb.job.last_run_duration_seconds", lastDurS, collector.MetricTypeGauge, jobLabels),
			makeMetric("db.timescaledb.job.total_successes", totalSuccesses, collector.MetricTypeCounter, jobLabels),
			makeMetric("db.timescaledb.job.total_failures", totalFailures, collector.MetricTypeCounter, jobLabels),
			makeMetric("db.timescaledb.job.total_crashes", totalCrashes, collector.MetricTypeCounter, jobLabels),
			makeMetric("db.timescaledb.job.next_start_in_seconds", nextStartIn, collector.MetricTypeGauge, jobLabels),
		)

		totalJobs++
		if lastStatus == "Success" || lastStatus == "" {
			totalScheduled++
		}
		if totalFailures > 0 {
			totalFailed++
		}
		if totalCrashes > 0 {
			totalCrashed++
		}
	}

	all = append(all,
		makeMetric("db.timescaledb.jobs.total", float64(totalJobs), collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.jobs.scheduled", float64(totalScheduled), collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.jobs.failed_total", float64(totalFailed), collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.jobs.crashed_total", float64(totalCrashed), collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.jobs.stuck_count", float64(stuckCount), collector.MetricTypeGauge, labels),
	)

	return all, nil
}
