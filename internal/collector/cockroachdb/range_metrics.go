package cockroachdb

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectRangeMetrics(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var totalRanges, underReplicated, unavailable int
	var totalReplicas int

	err := pool.QueryRow(ctx2, `
		SELECT
			COALESCE(count(*), 0),
			COALESCE(sum(array_length(replicas, 1)), 0),
			COALESCE(count(*) FILTER (WHERE array_length(replicas, 1) < 3), 0)
		FROM crdb_internal.ranges_no_leases
	`).Scan(&totalRanges, &totalReplicas, &underReplicated)
	if err != nil {
		return nil, fmt.Errorf("query range stats: %w", err)
	}

	metrics := []collector.Metric{
		makeMetric("db.cockroachdb.ranges.total", float64(totalRanges), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.ranges.total_replicas", float64(totalReplicas), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.ranges.under_replicated", float64(underReplicated), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.ranges.unavailable", float64(unavailable), collector.MetricTypeGauge, labels),
	}

	leaseMetrics, err := collectLeaseholderMetrics(ctx2, pool, labels)
	if err != nil {
		logger.Debug("Leaseholder metrics skipped", zap.Error(err))
	} else {
		metrics = append(metrics, leaseMetrics...)
	}

	return metrics, nil
}

func collectLeaseholderMetrics(ctx context.Context, pool PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			lease_holder,
			count(*)
		FROM crdb_internal.ranges
		WHERE lease_holder IS NOT NULL
		GROUP BY lease_holder
	`)
	if err != nil {
		return nil, fmt.Errorf("query leaseholder distribution: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var leaseHolder int
		var count int
		if err := rows.Scan(&leaseHolder, &count); err != nil {
			continue
		}

		lhLabels := copyLabels(labels)
		lhLabels["lease_holder"] = fmt.Sprintf("%d", leaseHolder)
		metrics = append(metrics,
			makeMetric("db.cockroachdb.ranges.leaseholder_count", float64(count), collector.MetricTypeGauge, lhLabels),
		)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate leaseholder distribution: %w", err)
	}

	return metrics, nil
}
