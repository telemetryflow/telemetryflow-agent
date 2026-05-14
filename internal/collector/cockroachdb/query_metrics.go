package cockroachdb

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectStatementStats(ctx context.Context, pool *pgxpool.Pool, inst *crdbInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	limit := inst.topStmtsLimit
	if limit <= 0 {
		limit = 200
	}

	rows, err := pool.Query(ctx2, `
		SELECT
			fingerprint_id,
			app_name,
			count,
			first_attempt_count,
			max_retries,
			avg_latency,
			rows_read,
			rows_written,
			bytes_read,
			network_bytes
		FROM crdb_internal.node_statement_statistics
		ORDER BY avg_latency DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query statement statistics: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var fingerprintID string
		var appName string
		var count, firstAttempt, maxRetries int64
		var avgLatency float64
		var rowsRead, rowsWritten, bytesRead, networkBytes int64

		if err := rows.Scan(
			&fingerprintID, &appName, &count, &firstAttempt, &maxRetries,
			&avgLatency, &rowsRead, &rowsWritten, &bytesRead, &networkBytes,
		); err != nil {
			continue
		}

		stmtLabels := copyLabels(labels)
		stmtLabels["fingerprint_id"] = fingerprintID
		if appName != "" {
			stmtLabels["app_name"] = appName
		}

		metrics = append(metrics,
			makeMetric("db.cockroachdb.statement.count", float64(count), collector.MetricTypeCounter, stmtLabels),
			makeMetric("db.cockroachdb.statement.first_attempt_count", float64(firstAttempt), collector.MetricTypeCounter, stmtLabels),
			makeMetric("db.cockroachdb.statement.max_retries", float64(maxRetries), collector.MetricTypeCounter, stmtLabels),
			makeMetric("db.cockroachdb.statement.avg_latency_ns", avgLatency, collector.MetricTypeGauge, stmtLabels),
			makeMetric("db.cockroachdb.statement.rows_read", float64(rowsRead), collector.MetricTypeCounter, stmtLabels),
			makeMetric("db.cockroachdb.statement.rows_written", float64(rowsWritten), collector.MetricTypeCounter, stmtLabels),
			makeMetric("db.cockroachdb.statement.bytes_read", float64(bytesRead), collector.MetricTypeCounter, stmtLabels),
			makeMetric("db.cockroachdb.statement.network_bytes", float64(networkBytes), collector.MetricTypeCounter, stmtLabels),
		)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate statement statistics: %w", err)
	}

	return metrics, nil
}
