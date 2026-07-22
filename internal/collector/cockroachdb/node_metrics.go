package cockroachdb

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectNodeMetrics(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var isLive bool
	var totalRanges, leaseholders, replicas int
	var liveBytes, sysBytes int64
	var uptimeSeconds float64

	err := pool.QueryRow(ctx2, `
		SELECT
			n.is_live,
			COALESCE((SELECT count(*) FROM crdb_internal.ranges_no_leases), 0),
			COALESCE((SELECT count(*) FROM crdb_internal.ranges WHERE lease_holder IS NOT NULL), 0),
			COALESCE((SELECT count(*) FROM crdb_internal.ranges_no_leases r, unnest(r.replicas) AS rep), 0),
			COALESCE((SELECT sum(capability) FROM crdb_internal.node_runtime_info), 0)::int64
	`).Scan(&isLive, &totalRanges, &leaseholders, &replicas, &liveBytes)
	if err != nil {
		// Fallback to simpler query if crdb_internal schema differs
		return collectNodeMetricsFallback(ctx2, pool, labels, logger)
	}

	metrics := []collector.Metric{
		makeMetric("db.cockroachdb.node.is_live", boolToFloat(isLive), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.node.total_ranges", float64(totalRanges), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.node.leaseholders", float64(leaseholders), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.node.replicas", float64(replicas), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.node.live_bytes", float64(liveBytes), collector.MetricTypeGauge, labels),
	}

	_ = sysBytes
	_ = uptimeSeconds

	return metrics, nil
}

func collectNodeMetricsFallback(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var isLive bool
	err := pool.QueryRow(ctx, `SELECT is_live FROM crdb_internal.gossip_liveness WHERE node_id = 1`).Scan(&isLive)
	if err != nil {
		return nil, fmt.Errorf("query node liveness: %w", err)
	}

	return []collector.Metric{
		makeMetric("db.cockroachdb.node.is_live", boolToFloat(isLive), collector.MetricTypeGauge, labels),
	}, nil
}

func collectSQLMetrics(ctx context.Context, pool PgxQuerier, inst *crdbInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var conns int
	var connsIdle int
	var connsActive int
	var totalQueries int
	var txnCommits int
	var txnRollbacks int
	var txnRestarts int

	err := pool.QueryRow(ctx2, `
		SELECT
			COALESCE(count(*), 0),
			COALESCE(count(*) FILTER (WHERE state = 'idle'), 0),
			COALESCE(count(*) FILTER (WHERE state = 'active'), 0)
		FROM crdb_internal.node_sql_sessions
	`).Scan(&conns, &connsIdle, &connsActive)
	if err != nil {
		conns, connsIdle, connsActive = 0, 0, 0
	}

	err = pool.QueryRow(ctx2, `
		SELECT
			COALESCE(sum(count), 0),
			COALESCE(sum(count) FILTER (WHERE txn_status = 'committed'), 0),
			COALESCE(sum(count) FILTER (WHERE txn_status = 'aborted'), 0),
			COALESCE(sum(restart_count), 0)
		FROM crdb_internal.node_transaction_metrics
	`).Scan(&totalQueries, &txnCommits, &txnRollbacks, &txnRestarts)
	if err != nil {
		totalQueries, txnCommits, txnRollbacks, txnRestarts = 0, 0, 0, 0
	}

	now := time.Now()
	elapsed := now.Sub(inst.prevTimestamp).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	metrics := []collector.Metric{
		makeMetric("db.cockroachdb.sql.connections", float64(conns), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.sql.connections.idle", float64(connsIdle), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.sql.connections.active", float64(connsActive), collector.MetricTypeGauge, labels),
		makeMetric("db.cockroachdb.sql.queries.total", float64(totalQueries), collector.MetricTypeCounter, labels),
		makeMetric("db.cockroachdb.sql.txn.commits", float64(txnCommits), collector.MetricTypeCounter, labels),
		makeMetric("db.cockroachdb.sql.txn.rollbacks", float64(txnRollbacks), collector.MetricTypeCounter, labels),
		makeMetric("db.cockroachdb.sql.txn.restarts", float64(txnRestarts), collector.MetricTypeCounter, labels),
	}

	counterEntries := []struct {
		key    string
		curr   uint64
		metric string
	}{
		{"sql_queries", uint64(totalQueries), "db.cockroachdb.sql.queries.rate"},
		{"sql_txn_commits", uint64(txnCommits), "db.cockroachdb.sql.txn.commit_rate"},
		{"sql_txn_rollbacks", uint64(txnRollbacks), "db.cockroachdb.sql.txn.rollback_rate"},
	}

	for _, e := range counterEntries {
		if prev, ok := inst.prevCounters[e.key]; ok && e.curr >= prev {
			delta := float64(e.curr - prev)
			rate := safeDiv(delta, elapsed)
			metrics = append(metrics, emitCounterRate(e.metric, rate, labels))
		}
		inst.prevCounters[e.key] = e.curr
	}

	inst.prevTimestamp = now
	return metrics, nil
}

func collectStoreMetrics(ctx context.Context, pool PgxQuerier, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := pool.Query(ctx2, `
		SELECT
			store_id,
			capacity,
			available,
			used,
			lease_count,
			range_count,
			rocksdb_read_amplification
		FROM crdb_internal.kv_store_status
	`)
	if err != nil {
		return nil, fmt.Errorf("query kv_store_status: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var storeID int
		var capacity, available, used int64
		var leaseCount, rangeCount int
		var readAmp int

		if err := rows.Scan(&storeID, &capacity, &available, &used, &leaseCount, &rangeCount, &readAmp); err != nil {
			continue
		}

		storeLabels := copyLabels(labels)
		storeLabels["store_id"] = fmt.Sprintf("%d", storeID)

		metrics = append(metrics,
			makeMetric("db.cockroachdb.store.capacity", float64(capacity), collector.MetricTypeGauge, storeLabels),
			makeMetric("db.cockroachdb.store.available", float64(available), collector.MetricTypeGauge, storeLabels),
			makeMetric("db.cockroachdb.store.used", float64(used), collector.MetricTypeGauge, storeLabels),
			makeMetric("db.cockroachdb.store.utilization_pct", safeDiv(float64(used), float64(capacity))*100, collector.MetricTypeGauge, storeLabels),
			makeMetric("db.cockroachdb.store.lease_count", float64(leaseCount), collector.MetricTypeGauge, storeLabels),
			makeMetric("db.cockroachdb.store.range_count", float64(rangeCount), collector.MetricTypeGauge, storeLabels),
			makeMetric("db.cockroachdb.store.read_amplification", float64(readAmp), collector.MetricTypeGauge, storeLabels),
		)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate kv_store_status: %w", err)
	}

	return metrics, nil
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
