package timescaledb

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectContinuousAggregates(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			cagg.view_name,
			cagg.materialized_only,
			ht.table_schema AS source_schema,
			ht.table_name AS source_hypertable
		FROM timescaledb_information.continuous_aggregates cagg
		JOIN timescaledb_information.hypertables ht
			ON ht.table_name = cagg.materialization_hypertable_name`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []collector.Metric
	caggCount := 0

	for rows.Next() {
		var viewName, srcSchema, srcHT string
		var matOnly bool

		if err := rows.Scan(&viewName, &matOnly, &srcSchema, &srcHT); err != nil {
			logger.Debug("Failed to scan CAGG row", zap.Error(err))
			continue
		}

		caggLabels := copyLabels(labels)
		caggLabels["cagg_name"] = viewName
		caggLabels["source_hypertable_schema"] = srcSchema
		caggLabels["source_hypertable_name"] = srcHT

		matOnlyF := 0.0
		if matOnly {
			matOnlyF = 1.0
		}

		all = append(all,
			makeMetric("db.timescaledb.cagg.materialized_only", matOnlyF, collector.MetricTypeGauge, caggLabels),
		)
		caggCount++
	}

	all = append(all,
		makeMetric("db.timescaledb.cagg.count", float64(caggCount), collector.MetricTypeGauge, labels),
	)

	return all, nil
}
