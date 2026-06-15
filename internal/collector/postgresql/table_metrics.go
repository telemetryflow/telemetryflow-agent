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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func collectTableStats(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	limit := inst.topTablesLimit
	if limit <= 0 {
		limit = 500
	}

	var metrics []collector.Metric

	// ---------------------------------------------------------------------------
	// 1. Per-table stats from pg_stat_user_tables
	// ---------------------------------------------------------------------------
	tableMetrics, err := collectTableStatMetrics(ctx2, pool, inst, labels, limit, logger)
	if err != nil {
		logger.Debug("Table stat metrics collection skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, tableMetrics...)
	}

	// ---------------------------------------------------------------------------
	// 2. Per-table I/O from pg_statio_user_tables
	// ---------------------------------------------------------------------------
	ioMetrics, err := collectTableIOMetrics(ctx2, pool, labels, logger)
	if err != nil {
		logger.Debug("Table I/O metrics collection skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, ioMetrics...)
	}

	// ---------------------------------------------------------------------------
	// 3. Per-index stats from pg_stat_user_indexes + pg_statio_user_indexes
	// ---------------------------------------------------------------------------
	idxMetrics, err := collectIndexMetrics(ctx2, pool, labels, logger)
	if err != nil {
		logger.Debug("Index metrics collection skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, idxMetrics...)
	}

	// ---------------------------------------------------------------------------
	// 4. Table size collection
	// ---------------------------------------------------------------------------
	sizeMetrics, err := collectTableSizeMetrics(ctx2, pool, labels, limit, logger)
	if err != nil {
		logger.Debug("Table size metrics collection skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, sizeMetrics...)
	}

	// ---------------------------------------------------------------------------
	// 5. Table bloat estimation
	// ---------------------------------------------------------------------------
	bloatMetrics, err := collectBloatEstimates(ctx2, pool, labels, limit, logger)
	if err != nil {
		logger.Debug("Table bloat estimation skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, bloatMetrics...)
	}

	// ---------------------------------------------------------------------------
	// 6. Index bloat estimation
	// ---------------------------------------------------------------------------
	idxBloatMetrics, err := collectIndexBloatEstimates(ctx2, pool, labels, logger)
	if err != nil {
		logger.Debug("Index bloat estimation skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, idxBloatMetrics...)
	}

	// ---------------------------------------------------------------------------
	// 7. Unused index detection
	// ---------------------------------------------------------------------------
	unusedMetrics, err := collectUnusedIndexes(ctx2, pool, labels, logger)
	if err != nil {
		logger.Debug("Unused index detection skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, unusedMetrics...)
	}

	return metrics, nil
}

func collectTableStatMetrics(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string, limit int, logger *zap.Logger) ([]collector.Metric, error) {
	query := `
		SELECT schemaname, relname,
		       seq_scan, seq_tup_read, idx_scan, idx_tup_fetch,
		       n_tup_ins, n_tup_upd, n_tup_del, n_tup_hot_upd,
		       n_live_tup, n_dead_tup, n_mod_since_analyze,
		       last_vacuum, last_autovacuum, last_analyze, last_autoanalyze,
		       vacuum_count, autovacuum_count, analyze_count, autoanalyze_count
		FROM pg_stat_user_tables
		ORDER BY pg_total_relation_size(schemaname||'.'||relname) DESC
		LIMIT $1`

	rows, err := pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_user_tables: %w", err)
	}
	defer rows.Close()

	type tblStat struct {
		schemaName       string
		relName          string
		seqScan          uint64
		seqTupRead       uint64
		idxScan          uint64
		idxTupFetch      uint64
		nTupIns          uint64
		nTupUpd          uint64
		nTupDel          uint64
		nTupHotUpd       uint64
		nLiveTup         uint64
		nDeadTup         uint64
		nModSinceAnalyze uint64
		lastVacuum       *time.Time
		lastAutovacuum   *time.Time
		lastAnalyze      *time.Time
		lastAutoanalyze  *time.Time
		vacuumCount      uint64
		autovacuumCount  uint64
		analyzeCount     uint64
		autoanalyzeCount uint64
	}

	var tableRows []tblStat
	for rows.Next() {
		var r tblStat
		if err := rows.Scan(
			&r.schemaName, &r.relName,
			&r.seqScan, &r.seqTupRead, &r.idxScan, &r.idxTupFetch,
			&r.nTupIns, &r.nTupUpd, &r.nTupDel, &r.nTupHotUpd,
			&r.nLiveTup, &r.nDeadTup, &r.nModSinceAnalyze,
			&r.lastVacuum, &r.lastAutovacuum, &r.lastAnalyze, &r.lastAutoanalyze,
			&r.vacuumCount, &r.autovacuumCount, &r.analyzeCount, &r.autoanalyzeCount,
		); err != nil {
			logger.Debug("Failed to scan pg_stat_user_tables row", zap.Error(err))
			continue
		}
		tableRows = append(tableRows, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var metrics []collector.Metric
	for _, r := range tableRows {
		tLabels := makeTableLabels(labels, r.schemaName, r.relName)

		metrics = append(metrics,
			makeMetric("db.postgresql.table.seq_scan", float64(r.seqScan), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.seq_tup_read", float64(r.seqTupRead), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.idx_scan", float64(r.idxScan), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.idx_tup_fetch", float64(r.idxTupFetch), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.n_tup_ins", float64(r.nTupIns), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.n_tup_upd", float64(r.nTupUpd), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.n_tup_del", float64(r.nTupDel), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.n_tup_hot_upd", float64(r.nTupHotUpd), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.n_live_tup", float64(r.nLiveTup), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.n_dead_tup", float64(r.nDeadTup), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.n_mod_since_analyze", float64(r.nModSinceAnalyze), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.vacuum_count", float64(r.vacuumCount), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.autovacuum_count", float64(r.autovacuumCount), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.analyze_count", float64(r.analyzeCount), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.autoanalyze_count", float64(r.autoanalyzeCount), collector.MetricTypeGauge, tLabels),
		)

		// HOT update ratio: n_tup_hot_upd / n_tup_upd
		hotRatio := safeDiv(float64(r.nTupHotUpd), float64(r.nTupUpd))
		metrics = append(metrics,
			makeMetric("db.postgresql.table.hot_update_ratio", hotRatio, collector.MetricTypeGauge, tLabels),
		)

		// Dead tuple ratio: n_dead_tup / (n_live_tup + n_dead_tup)
		deadRatio := safeDiv(float64(r.nDeadTup), float64(r.nLiveTup+r.nDeadTup))
		metrics = append(metrics,
			makeMetric("db.postgresql.table.dead_tuple_ratio", deadRatio, collector.MetricTypeGauge, tLabels),
		)

		// Time since last vacuum/analyze (in seconds).
		if r.lastVacuum != nil {
			secs := time.Since(*r.lastVacuum).Seconds()
			metrics = append(metrics,
				makeMetric("db.postgresql.table.last_vacuum_ago", secs, collector.MetricTypeGauge, tLabels),
			)
		}
		if r.lastAutovacuum != nil {
			secs := time.Since(*r.lastAutovacuum).Seconds()
			metrics = append(metrics,
				makeMetric("db.postgresql.table.last_autovacuum_ago", secs, collector.MetricTypeGauge, tLabels),
			)
		}
		if r.lastAnalyze != nil {
			secs := time.Since(*r.lastAnalyze).Seconds()
			metrics = append(metrics,
				makeMetric("db.postgresql.table.last_analyze_ago", secs, collector.MetricTypeGauge, tLabels),
			)
		}
		if r.lastAutoanalyze != nil {
			secs := time.Since(*r.lastAutoanalyze).Seconds()
			metrics = append(metrics,
				makeMetric("db.postgresql.table.last_autoanalyze_ago", secs, collector.MetricTypeGauge, tLabels),
			)
		}
	}

	return metrics, nil
}

func collectTableIOMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	query := `
		SELECT schemaname, relname,
		       heap_blks_read, heap_blks_hit,
		       coalesce(idx_blks_read, 0), coalesce(idx_blks_hit, 0),
		       coalesce(toast_blks_read, 0), coalesce(toast_blks_hit, 0)
		FROM pg_statio_user_tables`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query pg_statio_user_tables: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schemaName, relName string
		var heapBlksRead, heapBlksHit, idxBlksRead, idxBlksHit, toastBlksRead, toastBlksHit uint64
		if err := rows.Scan(
			&schemaName, &relName,
			&heapBlksRead, &heapBlksHit,
			&idxBlksRead, &idxBlksHit,
			&toastBlksRead, &toastBlksHit,
		); err != nil {
			logger.Debug("Failed to scan pg_statio_user_tables row", zap.Error(err))
			continue
		}

		tLabels := makeTableLabels(labels, schemaName, relName)

		metrics = append(metrics,
			makeMetric("db.postgresql.table.io.heap_blks_read", float64(heapBlksRead), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.io.heap_blks_hit", float64(heapBlksHit), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.io.idx_blks_read", float64(idxBlksRead), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.io.idx_blks_hit", float64(idxBlksHit), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.io.toast_blks_read", float64(toastBlksRead), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.io.toast_blks_hit", float64(toastBlksHit), collector.MetricTypeGauge, tLabels),
		)
	}
	return metrics, rows.Err()
}

func collectIndexMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	// -----------------------------------------------------------------------
	// a) pg_stat_user_indexes — scan & tuple counts
	// -----------------------------------------------------------------------
	statQuery := `
		SELECT schemaname, relname, indexrelname,
		       coalesce(idx_scan, 0), coalesce(idx_tup_read, 0), coalesce(idx_tup_fetch, 0)
		FROM pg_stat_user_indexes`

	statRows, err := pool.Query(ctx, statQuery)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_user_indexes: %w", err)
	}
	defer statRows.Close()

	type idxStat struct {
		schemaName  string
		relName     string
		idxName     string
		idxScan     uint64
		idxTupRead  uint64
		idxTupFetch uint64
	}

	var idxStats []idxStat
	for statRows.Next() {
		var s idxStat
		if err := statRows.Scan(&s.schemaName, &s.relName, &s.idxName, &s.idxScan, &s.idxTupRead, &s.idxTupFetch); err != nil {
			logger.Debug("Failed to scan pg_stat_user_indexes row", zap.Error(err))
			continue
		}
		idxStats = append(idxStats, s)
	}
	if err := statRows.Err(); err != nil {
		return nil, err
	}

	// -----------------------------------------------------------------------
	// b) pg_statio_user_indexes — block I/O counts
	// -----------------------------------------------------------------------
	ioQuery := `
		SELECT schemaname, relname, indexrelname,
		       coalesce(idx_blks_read, 0), coalesce(idx_blks_hit, 0)
		FROM pg_statio_user_indexes`

	ioRows, err := pool.Query(ctx, ioQuery)
	if err != nil {
		return nil, fmt.Errorf("query pg_statio_user_indexes: %w", err)
	}
	defer ioRows.Close()

	type idxIO struct {
		schemaName string
		relName    string
		idxName    string
		blksRead   uint64
		blksHit    uint64
	}

	ioMap := make(map[string]idxIO) // key: schema.rel.idx
	for ioRows.Next() {
		var io idxIO
		if err := ioRows.Scan(&io.schemaName, &io.relName, &io.idxName, &io.blksRead, &io.blksHit); err != nil {
			logger.Debug("Failed to scan pg_statio_user_indexes row", zap.Error(err))
			continue
		}
		key := io.schemaName + "." + io.relName + "." + io.idxName
		ioMap[key] = io
	}
	if err := ioRows.Err(); err != nil {
		return nil, err
	}

	// -----------------------------------------------------------------------
	// Merge and emit
	// -----------------------------------------------------------------------
	var metrics []collector.Metric
	for _, s := range idxStats {
		iLabels := makeIndexLabels(labels, s.schemaName, s.relName, s.idxName)

		metrics = append(metrics,
			makeMetric("db.postgresql.index.idx_scan", float64(s.idxScan), collector.MetricTypeGauge, iLabels),
			makeMetric("db.postgresql.index.idx_tup_read", float64(s.idxTupRead), collector.MetricTypeGauge, iLabels),
			makeMetric("db.postgresql.index.idx_tup_fetch", float64(s.idxTupFetch), collector.MetricTypeGauge, iLabels),
		)

		key := s.schemaName + "." + s.relName + "." + s.idxName
		if io, ok := ioMap[key]; ok {
			metrics = append(metrics,
				makeMetric("db.postgresql.index.idx_blks_read", float64(io.blksRead), collector.MetricTypeGauge, iLabels),
				makeMetric("db.postgresql.index.idx_blks_hit", float64(io.blksHit), collector.MetricTypeGauge, iLabels),
			)
		}
	}

	return metrics, nil
}

func collectTableSizeMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, limit int, logger *zap.Logger) ([]collector.Metric, error) {
	query := `
		SELECT schemaname, relname,
		       pg_relation_size(schemaname||'.'||relname)   AS table_size,
		       pg_indexes_size(schemaname||'.'||relname)    AS index_size,
		       pg_total_relation_size(schemaname||'.'||relname) AS total_size
		FROM pg_stat_user_tables
		ORDER BY pg_total_relation_size(schemaname||'.'||relname) DESC
		LIMIT $1`

	rows, err := pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query table sizes: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schemaName, relName string
		var tableSize, indexSize, totalSize uint64
		if err := rows.Scan(&schemaName, &relName, &tableSize, &indexSize, &totalSize); err != nil {
			logger.Debug("Failed to scan table size row", zap.Error(err))
			continue
		}

		tLabels := makeTableLabels(labels, schemaName, relName)

		metrics = append(metrics,
			makeMetric("db.postgresql.table.table_size", float64(tableSize), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.index_size", float64(indexSize), collector.MetricTypeGauge, tLabels),
			makeMetric("db.postgresql.table.total_size", float64(totalSize), collector.MetricTypeGauge, tLabels),
		)
	}
	return metrics, rows.Err()
}

// ---------------------------------------------------------------------------
// Table bloat estimation using dead tuple heuristic
// ---------------------------------------------------------------------------

func collectBloatEstimates(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, limit int, logger *zap.Logger) ([]collector.Metric, error) {
	query := `
		SELECT s.schemaname, s.relname,
		       pg_relation_size(s.relid) AS total_size,
		       s.n_dead_tup,
		       c.relpages,
		       c.reltuples
		FROM pg_stat_user_tables s
		JOIN pg_class c ON c.oid = s.relid
		WHERE s.n_dead_tup > 0
		ORDER BY s.n_dead_tup DESC
		LIMIT $1`

	rows, err := pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query table bloat: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schemaName, relName string
		var totalSize, relPages int64
		var deadTup, relTuples float64

		if err := rows.Scan(&schemaName, &relName, &totalSize, &deadTup, &relPages, &relTuples); err != nil {
			logger.Debug("Failed to scan table bloat row", zap.Error(err))
			continue
		}

		tLabels := makeTableLabels(labels, schemaName, relName)

		// Compute approximate bloat percentage.
		// avg_row_size = total_size / max(reltuples, 1)
		// bloat_pct    = (dead_tup * avg_row_size) / total_size * 100
		avgRowSize := safeDiv(float64(totalSize), max(relTuples, 1))
		bloatPct := safeDiv(deadTup*avgRowSize, float64(totalSize)) * 100.0

		metrics = append(metrics,
			makeMetric("db.postgresql.table.bloat_pct", bloatPct, collector.MetricTypeGauge, tLabels),
		)
	}
	return metrics, rows.Err()
}

// ---------------------------------------------------------------------------
// Index bloat estimation
// ---------------------------------------------------------------------------

func collectIndexBloatEstimates(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	// Compare actual index page count with an expected minimum based on
	// reltuples * 8 bytes (a rough B-tree leaf-entry estimate). This heuristic
	// is deliberately conservative — real index bloat tools use pgstattuple
	// for exact numbers, but that requires superuser and the extension.
	query := `
		SELECT sui.schemaname,
		       sui.relname,
		       sui.indexrelname,
		       pg_relation_size(sui.indexrelid) AS index_bytes,
		       COALESCE(c.reltuples, 0)                         AS idx_reltuples
		FROM pg_stat_user_indexes sui
		JOIN pg_class c ON c.oid = sui.indexrelid
		WHERE c.relpages > 0`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query index bloat: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schemaName, relName, idxName string
		var indexBytes int64
		var idxReltuples float64

		if err := rows.Scan(&schemaName, &relName, &idxName, &indexBytes, &idxReltuples); err != nil {
			logger.Debug("Failed to scan index bloat row", zap.Error(err))
			continue
		}

		iLabels := makeIndexLabels(labels, schemaName, relName, idxName)

		// Expected minimum size: reltuples * 8 bytes (B-tree leaf entry overhead).
		expectedBytes := idxReltuples * 8.0
		// Bloat percentage: (actual - expected) / actual * 100, clamped to >= 0.
		bloatPct := 0.0
		if indexBytes > 0 && expectedBytes > 0 {
			bloatPct = safeDiv(float64(indexBytes)-expectedBytes, float64(indexBytes)) * 100.0
			if bloatPct < 0 {
				bloatPct = 0
			}
		}

		metrics = append(metrics,
			makeMetric("db.postgresql.index.bloat_pct", bloatPct, collector.MetricTypeGauge, iLabels),
		)
	}
	return metrics, rows.Err()
}

// ---------------------------------------------------------------------------
// Unused index detection
// ---------------------------------------------------------------------------

func collectUnusedIndexes(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	// Find indexes that have never been scanned (idx_scan = 0) and are not
	// backing a primary key or unique constraint.
	query := `
		SELECT sui.schemaname,
		       sui.relname,
		       sui.indexrelname,
		       pg_relation_size(sui.indexrelid) AS index_bytes
		FROM pg_stat_user_indexes sui
		JOIN pg_index i ON i.indexrelid = sui.indexrelid
		WHERE sui.idx_scan = 0
		  AND NOT i.indisprimary
		  AND NOT EXISTS (
		      SELECT 1 FROM pg_constraint c
		      WHERE c.conindid = sui.indexrelid
		  )`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query unused indexes: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var schemaName, relName, idxName string
		var indexBytes int64

		if err := rows.Scan(&schemaName, &relName, &idxName, &indexBytes); err != nil {
			logger.Debug("Failed to scan unused index row", zap.Error(err))
			continue
		}

		iLabels := makeIndexLabels(labels, schemaName, relName, idxName)

		metrics = append(metrics,
			makeMetric("db.postgresql.index.unused", 1, collector.MetricTypeGauge, iLabels),
			makeMetric("db.postgresql.index.unused_bytes", float64(indexBytes), collector.MetricTypeGauge, iLabels),
		)
	}
	return metrics, rows.Err()
}

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

func makeTableLabels(base map[string]string, schemaName, relName string) map[string]string {
	l := make(map[string]string, len(base)+2)
	for k, v := range base {
		l[k] = v
	}
	l["schemaname"] = schemaName
	l["tablename"] = relName
	return l
}

func makeIndexLabels(base map[string]string, schemaName, relName, idxName string) map[string]string {
	l := make(map[string]string, len(base)+3)
	for k, v := range base {
		l[k] = v
	}
	l["schemaname"] = schemaName
	l["tablename"] = relName
	l["indexname"] = idxName
	return l
}
