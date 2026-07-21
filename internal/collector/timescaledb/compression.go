package timescaledb

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectCompression(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	query := `
		SELECT
			cs.hypertable_schema,
			cs.hypertable_name,
			COALESCE(SUM(cs.before_compression_total_bytes), 0) AS before_total,
			COALESCE(SUM(cs.after_compression_total_bytes), 0) AS after_total,
			COUNT(*) FILTER (WHERE cs.is_compressed) AS compressed_chunks,
			COUNT(*) FILTER (WHERE NOT cs.is_compressed) AS uncompressed_chunks
		FROM timescaledb_information.compressed_hypertable_stats cs
		GROUP BY cs.hypertable_schema, cs.hypertable_name`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []collector.Metric

	for rows.Next() {
		var schema, htName string
		var beforeTotal, afterTotal float64
		var compressed, uncompressed int

		if err := rows.Scan(&schema, &htName, &beforeTotal, &afterTotal, &compressed, &uncompressed); err != nil {
			logger.Debug("Failed to scan compression row", zap.Error(err))
			continue
		}

		htLabels := copyLabels(labels)
		htLabels["hypertable_schema"] = schema
		htLabels["hypertable_name"] = htName

		ratio := safeDiv(beforeTotal, afterTotal)
		savings := beforeTotal - afterTotal
		backlog := 0
		if uncompressed > 0 {
			backlog = uncompressed
		}

		all = append(all,
			makeMetric("db.timescaledb.compression.ratio", ratio, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.compression.before_total_bytes", beforeTotal, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.compression.after_total_bytes", afterTotal, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.compression.savings_bytes", savings, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.compression.chunks_compressed", float64(compressed), collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.compression.chunks_uncompressed", float64(uncompressed), collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.compression.backlog_chunks", float64(backlog), collector.MetricTypeGauge, htLabels),
		)
	}

	return all, nil
}
