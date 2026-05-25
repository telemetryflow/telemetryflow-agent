// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package postgresql

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectVacuumMetrics gathers autovacuum worker counts, vacuum progress,
// XID wraparound risk, dead-tuple counts and autovacuum configuration.
func collectVacuumMetrics(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var all []collector.Metric

	// --- a) Autovacuum worker count ---
	if m, err := collectVacuumWorkers(ctx2, pool, labels, logger); err != nil {
		logger.Debug("vacuum workers query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- b) Vacuum progress ---
	if m, err := collectVacuumProgress(ctx2, pool, labels, logger); err != nil {
		logger.Debug("vacuum progress query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- c) XID wraparound risk ---
	if m, err := collectXIDAge(ctx2, pool, labels, logger); err != nil {
		logger.Debug("xid age query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- d) Per-table dead tuples ---
	if m, err := collectDeadTuples(ctx2, pool, labels, logger); err != nil {
		logger.Debug("dead tuples query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- e) Autovacuum configuration snapshot ---
	if m, err := collectVacuumConfig(ctx2, pool, labels, logger); err != nil {
		logger.Debug("vacuum config query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- f) Per-table XID age ---
	if m, err := collectTableXIDAge(ctx2, pool, labels, logger); err != nil {
		logger.Debug("per-table xid age query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- g) Vacuum needed indicator ---
	if m, err := collectVacuumNeeded(ctx2, pool, labels, logger); err != nil {
		logger.Debug("vacuum needed query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- h) Dead tuple accumulation rate ---
	if m, err := collectDeadTupleRate(ctx2, pool, inst, labels, logger); err != nil {
		logger.Debug("dead tuple rate query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- i) Logical replication (subscription) metrics ---
	if m, err := collectSubscriptionMetrics(ctx2, pool, labels, logger); err != nil {
		logger.Debug("subscription metrics query skipped", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	return all, nil
}

// collectVacuumWorkers counts active autovacuum workers from pg_stat_activity.
func collectVacuumWorkers(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'autovacuum worker'`

	var count int64
	if err := pool.QueryRow(ctx, q).Scan(&count); err != nil {
		return nil, fmt.Errorf("vacuum workers: %w", err)
	}

	return []collector.Metric{
		makeMetric("db.postgresql.vacuum.workers_active", float64(count), collector.MetricTypeGauge, labels),
	}, nil
}

// collectVacuumProgress reports progress of running vacuums from pg_stat_progress_vacuum.
func collectVacuumProgress(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT relid::regclass::text AS table_name,
	                  phase,
	                  heap_blks_total,
	                  heap_blks_scanned,
	                  heap_blks_vacuumed,
	                  index_vacuum_count,
	                  max_dead_tuples,
	                  num_dead_tuples
	           FROM pg_stat_progress_vacuum`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("vacuum progress: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var tableName, phase string
		var total, scanned, vacuumed, idxVacCount, maxDead, numDead int64

		if err := rows.Scan(&tableName, &phase, &total, &scanned, &vacuumed,
			&idxVacCount, &maxDead, &numDead); err != nil {
			logger.Debug("vacuum progress row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["table_name"] = tableName
		rowLabels["phase"] = phase

		// Progress percentage: (scanned + vacuumed) / (2 * total)
		pct := safeDiv(float64(scanned+vacuumed), float64(2*total)) * 100.0
		metrics = append(metrics,
			makeMetric("db.postgresql.vacuum.progress_pct", pct, collector.MetricTypeGauge, rowLabels),
		)

		// Also emit heap block counters for detailed analysis.
		detailLabels := copyLabels(rowLabels)
		metrics = append(metrics,
			makeMetric("db.postgresql.vacuum.heap_blks_total", float64(total), collector.MetricTypeGauge, detailLabels),
			makeMetric("db.postgresql.vacuum.heap_blks_scanned", float64(scanned), collector.MetricTypeGauge, detailLabels),
			makeMetric("db.postgresql.vacuum.heap_blks_vacuumed", float64(vacuumed), collector.MetricTypeGauge, detailLabels),
			makeMetric("db.postgresql.vacuum.index_vacuum_count", float64(idxVacCount), collector.MetricTypeGauge, detailLabels),
			makeMetric("db.postgresql.vacuum.num_dead_tuples", float64(numDead), collector.MetricTypeGauge, detailLabels),
			makeMetric("db.postgresql.vacuum.max_dead_tuples", float64(maxDead), collector.MetricTypeGauge, detailLabels),
		)
	}
	return metrics, rows.Err()
}

// collectXIDAge reports transaction ID wraparound risk per database.
func collectXIDAge(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT datname,
	                  age(datfrozenxid) AS xid_age,
	                  (SELECT setting::bigint FROM pg_settings WHERE name = 'autovacuum_freeze_max_age') AS freeze_max
	           FROM pg_database
	           WHERE datistemplate = false`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("xid age: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var dbname string
		var xidAge, freezeMax int64

		if err := rows.Scan(&dbname, &xidAge, &freezeMax); err != nil {
			logger.Debug("xid age row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["dbname"] = dbname

		pct := safeDiv(float64(xidAge), float64(freezeMax)) * 100.0
		metrics = append(metrics,
			makeMetric("db.postgresql.vacuum.xid_age_pct", pct, collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}

// collectDeadTuples reports per-table dead tuple counts (top 50).
func collectDeadTuples(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT schemaname, relname, n_dead_tup, n_live_tup
	           FROM pg_stat_user_tables
	           WHERE n_dead_tup > 0
	           ORDER BY n_dead_tup DESC
	           LIMIT 50`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("dead tuples: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schema, table string
		var deadTup, liveTup int64

		if err := rows.Scan(&schema, &table, &deadTup, &liveTup); err != nil {
			logger.Debug("dead tuples row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["schemaname"] = schema
		rowLabels["tablename"] = table

		metrics = append(metrics,
			makeMetric("db.postgresql.vacuum.dead_tuples", float64(deadTup), collector.MetricTypeGauge, rowLabels),
			makeMetric("db.postgresql.vacuum.live_tuples", float64(liveTup), collector.MetricTypeGauge, rowLabels),
		)

		// Dead-to-live ratio for quick bloat assessment.
		deadRatio := safeDiv(float64(deadTup), float64(deadTup+liveTup)) * 100.0
		metrics = append(metrics,
			makeMetric("db.postgresql.vacuum.dead_tuple_ratio_pct", deadRatio, collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}

// collectVacuumConfig emits the current autovacuum / vacuum settings as gauge metrics.
func collectVacuumConfig(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT name, setting
	           FROM pg_settings
	           WHERE name LIKE 'autovacuum%%' OR name LIKE 'vacuum%%'
	           ORDER BY name`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("vacuum config: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var name, setting string
		if err := rows.Scan(&name, &setting); err != nil {
			logger.Debug("vacuum config row scan failed", zap.Error(err))
			continue
		}

		metricName := "db.postgresql.vacuum.config." + strings.ReplaceAll(name, ".", "_")
		rowLabels := copyLabels(labels)
		rowLabels["setting_name"] = name

		val := parseFloat(setting)
		// For on/off settings, emit 1/0 so they are still numeric.
		if val == 0 && (setting == "on" || setting == "off") {
			if setting == "on" {
				val = 1
			}
		}
		metrics = append(metrics,
			makeMetric(metricName, val, collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}

// copyLabels returns a shallow copy of labels so that per-row mutations do not
// affect the parent label set.
func copyLabels(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src)+4)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// ---------------------------------------------------------------------------
// Per-table XID age
// ---------------------------------------------------------------------------

func collectTableXIDAge(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT n.nspname AS schemaname,
	                  c.relname,
	                  age(c.relfrozenxid) AS xid_age
	           FROM pg_class c
	           JOIN pg_namespace n ON n.oid = c.relnamespace
	           WHERE c.relkind = 'r'
	             AND n.nspname NOT IN ('pg_catalog', 'information_schema')
	           ORDER BY age(c.relfrozenxid) DESC
	           LIMIT 20`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("per-table xid age: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schema, table string
		var xidAge int64

		if err := rows.Scan(&schema, &table, &xidAge); err != nil {
			logger.Debug("per-table xid age row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["schemaname"] = schema
		rowLabels["tablename"] = table

		metrics = append(metrics,
			makeMetric("db.postgresql.vacuum.table_xid_age", float64(xidAge), collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}

// ---------------------------------------------------------------------------
// Vacuum needed indicator
// ---------------------------------------------------------------------------

func collectVacuumNeeded(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	// Read autovacuum settings for threshold and scale factor.
	var threshold int64
	var scaleFactor float64
	if err := pool.QueryRow(ctx,
		"SELECT setting::bigint FROM pg_settings WHERE name = 'autovacuum_vacuum_threshold'",
	).Scan(&threshold); err != nil {
		threshold = 50 // PostgreSQL default
	}
	if err := pool.QueryRow(ctx,
		"SELECT setting::float FROM pg_settings WHERE name = 'autovacuum_vacuum_scale_factor'",
	).Scan(&scaleFactor); err != nil {
		scaleFactor = 0.2 // PostgreSQL default
	}

	query := `
		SELECT schemaname, relname,
		       n_dead_tup,
		       n_live_tup
		FROM pg_stat_user_tables
		WHERE n_dead_tup > 0
		ORDER BY n_dead_tup DESC
		LIMIT 100`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("vacuum needed: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schema, table string
		var deadTup, liveTup int64

		if err := rows.Scan(&schema, &table, &deadTup, &liveTup); err != nil {
			logger.Debug("vacuum needed row scan failed", zap.Error(err))
			continue
		}

		vacuumThreshold := float64(threshold) + scaleFactor*float64(liveTup)
		needed := 0.0
		if float64(deadTup) > vacuumThreshold {
			needed = 1.0
		}

		rowLabels := copyLabels(labels)
		rowLabels["schemaname"] = schema
		rowLabels["tablename"] = table

		metrics = append(metrics,
			makeMetric("db.postgresql.vacuum.needed", needed, collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}

// ---------------------------------------------------------------------------
// Dead tuple accumulation rate
// ---------------------------------------------------------------------------

func collectDeadTupleRate(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	// Sum all dead tuples across user tables.
	var totalDead int64
	if err := pool.QueryRow(ctx,
		"SELECT COALESCE(SUM(n_dead_tup), 0) FROM pg_stat_user_tables",
	).Scan(&totalDead); err != nil {
		return nil, fmt.Errorf("dead tuple rate sum: %w", err)
	}

	now := time.Now()
	var metrics []collector.Metric

	if !inst.deadTuplePrevTime.IsZero() {
		elapsed := now.Sub(inst.deadTuplePrevTime).Seconds()
		if elapsed > 0 {
			delta := int64(totalDead) - int64(inst.deadTuplePrev)
			// On counter reset (VACUUM FULL / TRUNCATE), skip this cycle.
			if delta >= 0 {
				rate := float64(delta) / elapsed
				metrics = append(metrics,
					makeMetric("db.postgresql.vacuum.dead_tuple_rate", rate, collector.MetricTypeGauge, labels),
				)
			}
		}
	}

	inst.deadTuplePrev = uint64(totalDead)
	inst.deadTuplePrevTime = now

	return metrics, nil
}

// ---------------------------------------------------------------------------
// Logical replication subscription metrics
// ---------------------------------------------------------------------------

func collectSubscriptionMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	// pg_stat_subscription is available from PostgreSQL 10+.
	// Use EXISTS to gracefully handle the case where the view is not present.
	var viewExists bool
	if err := pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.views WHERE table_name = 'pg_stat_subscription')",
	).Scan(&viewExists); err != nil || !viewExists {
		return nil, nil
	}

	query := `
		SELECT subname,
		       COALESCE(latest_end_lsn::text, ''),
		       COALESCE(latest_end_time, now()) - now() AS lag_interval
		FROM pg_stat_subscription`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("subscription metrics: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var subName, lsn string
		var lagSec float64

		// latest_end_time may be NULL; scan as a possible NULL timestamp.
		if err := rows.Scan(&subName, &lsn, &lagSec); err != nil {
			logger.Debug("subscription row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["subscription"] = subName

		metrics = append(metrics,
			makeMetric("db.postgresql.subscription.lag_sec", lagSec, collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}
