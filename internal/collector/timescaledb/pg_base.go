package timescaledb

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectPGBaseMetrics(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var all []collector.Metric

	if m, err := collectConnectionStats(ctx, pool, labels); err != nil {
		logger.Debug("Connection stats failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	if m, err := collectDatabaseStats(ctx, pool, labels); err != nil {
		logger.Debug("Database stats failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	if m, err := collectActivityStats(ctx, pool, labels); err != nil {
		logger.Debug("Activity stats failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	return all, nil
}

func collectConnectionStats(ctx context.Context, pool PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT
			COUNT(*) FILTER (WHERE state = 'active') AS active,
			COUNT(*) FILTER (WHERE state = 'idle') AS idle,
			COUNT(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_transaction,
			COUNT(*) AS total
		FROM pg_stat_activity
		WHERE backend_type = 'client backend'`

	var active, idle, idleInTx, total float64
	if err := pool.QueryRow(ctx2, query).Scan(&active, &idle, &idleInTx, &total); err != nil {
		return nil, err
	}

	return []collector.Metric{
		makeMetric("db.timescaledb.connections.active", active, collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.connections.idle", idle, collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.connections.idle_in_transaction", idleInTx, collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.connections.total", total, collector.MetricTypeGauge, labels),
	}, nil
}

func collectDatabaseStats(ctx context.Context, pool PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT
			SUM(xact_commit) AS commits,
			SUM(xact_rollback) AS rollbacks,
			SUM(blks_read) AS blocks_read,
			SUM(blks_hit) AS blocks_hit,
			SUM(tup_returned) AS tuples_returned,
			SUM(tup_fetched) AS tuples_fetched
		FROM pg_stat_database`

	var commits, rollbacks, blocksRead, blocksHit, tupReturned, tupFetched float64
	if err := pool.QueryRow(ctx2, query).Scan(&commits, &rollbacks, &blocksRead, &blocksHit, &tupReturned, &tupFetched); err != nil {
		return nil, err
	}

	return []collector.Metric{
		makeMetric("db.timescaledb.transactions.commits", commits, collector.MetricTypeCounter, labels),
		makeMetric("db.timescaledb.transactions.rollbacks", rollbacks, collector.MetricTypeCounter, labels),
		makeMetric("db.timescaledb.blocks.read", blocksRead, collector.MetricTypeCounter, labels),
		makeMetric("db.timescaledb.blocks.hit", blocksHit, collector.MetricTypeCounter, labels),
		makeMetric("db.timescaledb.cache_hit_ratio", safeDiv(blocksHit, blocksHit+blocksRead)*100, collector.MetricTypeGauge, labels),
	}, nil
}

func collectActivityStats(ctx context.Context, pool PgxQuerier, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT
			COUNT(*) FILTER (WHERE wait_event_type = 'Lock') AS waiting_locks,
			COUNT(*) FILTER (WHERE wait_event_type = 'LWLock') AS waiting_lwlocks
		FROM pg_stat_activity
		WHERE state = 'active'`

	var lockWaits, lwLockWaits float64
	if err := pool.QueryRow(ctx2, query).Scan(&lockWaits, &lwLockWaits); err != nil {
		return nil, err
	}

	return []collector.Metric{
		makeMetric("db.timescaledb.locks.waiting", lockWaits, collector.MetricTypeGauge, labels),
		makeMetric("db.timescaledb.lwlocks.waiting", lwLockWaits, collector.MetricTypeGauge, labels),
	}, nil
}
