package timescaledb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectRetention(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			j.application_name AS proc_name,
			COALESCE(js.last_run_status, '') AS last_run_status,
			COALESCE(js.total_failures, 0) AS total_failures
		FROM timescaledb_information.jobs j
		LEFT JOIN timescaledb_information.job_stats js ON js.job_id = j.job_id
		WHERE j.proc_name = 'policy_retention'`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []collector.Metric
	policyMissing := 1.0

	for rows.Next() {
		var procName, lastStatus string
		var totalFailures float64

		if err := rows.Scan(&procName, &lastStatus, &totalFailures); err != nil {
			logger.Debug("Failed to scan retention row", zap.Error(err))
			continue
		}

		policyMissing = 0.0

		all = append(all,
			makeMetric("db.timescaledb.retention.last_run_status", 0, collector.MetricTypeGauge, labels),
			makeMetric("db.timescaledb.retention.total_failures", totalFailures, collector.MetricTypeCounter, labels),
		)
	}

	all = append(all,
		makeMetric("db.timescaledb.retention.policy_missing", policyMissing, collector.MetricTypeGauge, labels),
	)

	return all, nil
}
