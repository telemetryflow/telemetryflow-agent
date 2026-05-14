package timescaledb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

var _ = collectDataNodes

func collectDataNodes(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	query := `SELECT node_name FROM timescaledb_information.data_nodes`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []collector.Metric
	nodeCount := 0

	for rows.Next() {
		var nodeName string
		if err := rows.Scan(&nodeName); err != nil {
			continue
		}

		nodeLabels := copyLabels(labels)
		nodeLabels["datanode_name"] = nodeName

		all = append(all,
			makeMetric("db.timescaledb.datanode.is_available", 1.0, collector.MetricTypeGauge, nodeLabels),
		)
		nodeCount++
	}

	all = append(all,
		makeMetric("db.timescaledb.datanodes.total", float64(nodeCount), collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.datanodes.available", float64(nodeCount), collector.MetricTypeGauge, labels),
	)

	return all, nil
}
