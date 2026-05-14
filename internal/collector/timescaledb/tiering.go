package timescaledb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

var _ = collectTiering

func collectTiering(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var exists bool
	err := pool.QueryRow(ctx2,
		"SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'timescaledb_osm')",
	).Scan(&exists)
	if err != nil || !exists {
		return []collector.Metric{
			makeMetric("db.timescaledb.tiering.enabled", 0, collector.MetricTypeGauge, labels),
		}, nil
	}

	return []collector.Metric{
		makeMetric("db.timescaledb.tiering.enabled", 1, collector.MetricTypeGauge, labels),
	}, nil
}
