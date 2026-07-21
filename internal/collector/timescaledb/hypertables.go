package timescaledb

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectHypertables(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			h.table_schema,
			h.table_name,
			COALESCE(h.num_dimensions, 1),
			COALESCE(h.num_chunks, 0),
			COALESCE(h.compression_enabled, false),
			COALESCE(ds.total_bytes, 0),
			COALESCE(ds.index_bytes, 0),
			COALESCE(ds.toast_bytes, 0),
			COALESCE(d.interval_length, '')
		FROM timescaledb_information.hypertables h
		LEFT JOIN LATERAL hypertable_detailed_size(quote_ident(h.table_schema)||'.'||quote_ident(h.table_name)) ds ON true
		LEFT JOIN timescaledb_information.dimensions d ON d.hypertable_schema = h.table_schema AND d.hypertable_name = h.table_name AND d.dimension_number = 1`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []collector.Metric
	htCount := 0

	for rows.Next() {
		var schema, name, intervalLen string
		var numDim, numChunks int
		var compressionEnabled bool
		var totalB, idxB, toastB float64

		if err := rows.Scan(&schema, &name, &numDim, &numChunks, &compressionEnabled, &totalB, &idxB, &toastB, &intervalLen); err != nil {
			logger.Debug("Failed to scan hypertable row", zap.Error(err))
			continue
		}

		htLabels := copyLabels(labels)
		htLabels["hypertable_schema"] = schema
		htLabels["hypertable_name"] = name

		compressionFloat := 0.0
		if compressionEnabled {
			compressionFloat = 1.0
		}

		all = append(all,
			makeMetric("db.timescaledb.hypertable.total_bytes", totalB, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.hypertable.index_bytes", idxB, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.hypertable.toast_bytes", toastB, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.hypertable.num_chunks", float64(numChunks), collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.hypertable.num_dimensions", float64(numDim), collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.hypertable.compression_enabled", compressionFloat, collector.MetricTypeGauge, htLabels),
		)
		htCount++
	}

	all = append(all,
		makeMetric("db.timescaledb.hypertable.count", float64(htCount), collector.MetricTypeGauge, labels),
	)

	return all, nil
}
