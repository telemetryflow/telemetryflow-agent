package timescaledb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectChunks(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	query := `
		SELECT
			c.hypertable_schema,
			c.hypertable_name,
			COUNT(*) AS total_chunks,
			COUNT(*) FILTER (WHERE c.is_compressed) AS compressed_chunks,
			COUNT(*) FILTER (WHERE NOT c.is_compressed) AS uncompressed_chunks,
			COALESCE(SUM(ds.total_bytes), 0) AS total_size_bytes
		FROM timescaledb_information.chunks c
		LEFT JOIN LATERAL chunks_detailed_size(quote_ident(c.chunk_schema)||'.'||quote_ident(c.chunk_name)) ds ON true
		GROUP BY c.hypertable_schema, c.hypertable_name`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []collector.Metric
	totalChunks := 0
	totalCompressed := 0
	totalUncompressed := 0

	for rows.Next() {
		var schema, htName string
		var total, compressed, uncompressed int
		var totalSize float64

		if err := rows.Scan(&schema, &htName, &total, &compressed, &uncompressed, &totalSize); err != nil {
			logger.Debug("Failed to scan chunk row", zap.Error(err))
			continue
		}

		htLabels := copyLabels(labels)
		htLabels["hypertable_schema"] = schema
		htLabels["hypertable_name"] = htName

		avgSize := safeDiv(totalSize, float64(total))

		all = append(all,
			makeMetric("db.timescaledb.chunks.count", float64(total), collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.chunks.compressed_count", float64(compressed), collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.chunks.uncompressed_count", float64(uncompressed), collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.chunks.total_size_bytes", totalSize, collector.MetricTypeGauge, htLabels),
			makeMetric("db.timescaledb.chunks.avg_size_bytes", avgSize, collector.MetricTypeGauge, htLabels),
		)

		totalChunks += total
		totalCompressed += compressed
		totalUncompressed += uncompressed
	}

	all = append(all,
		makeMetric("db.timescaledb.chunks.total", float64(totalChunks), collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.chunks.total_compressed", float64(totalCompressed), collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.chunks.total_uncompressed", float64(totalUncompressed), collector.MetricTypeGauge, labels),
	)

	return all, nil
}
