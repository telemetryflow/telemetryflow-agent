// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
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

func collectInstanceMetrics(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var all []collector.Metric

	if m, err := collectConnectionMetrics(ctx, pool, inst, labels); err != nil {
		logger.Debug("Connection metrics failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	if m, err := collectTransactionMetrics(ctx, pool, inst, labels); err != nil {
		logger.Debug("Transaction metrics failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	if m, err := collectBgWriterMetrics(ctx, pool, labels); err != nil {
		logger.Debug("Bgwriter metrics failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	if hasPgStatWal(inst) {
		if m, err := collectWALMetrics(ctx, pool, labels); err != nil {
			logger.Debug("WAL metrics failed", zap.Error(err))
		} else {
			all = append(all, m...)
		}
	}

	if m, err := collectDatabaseSizeMetrics(ctx, pool, labels); err != nil {
		logger.Debug("Database size metrics failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	return all, nil
}

// ---------------------------------------------------------------------------
// Connection metrics from pg_stat_activity
// ---------------------------------------------------------------------------

func collectConnectionMetrics(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT
			COALESCE(datname, '') AS dbname,
			state,
			count(*) AS cnt
		FROM pg_stat_activity
		GROUP BY datname, state
	`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_activity: %w", err)
	}
	defer rows.Close()

	type stateRow struct {
		dbname string
		state  string
		count  int64
	}

	var stateRows []stateRow
	for rows.Next() {
		var r stateRow
		if err := rows.Scan(&r.dbname, &r.state, &r.count); err != nil {
			continue
		}
		stateRows = append(stateRows, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pg_stat_activity: %w", err)
	}

	// Also fetch max_connections.
	var maxConns int64
	if err := pool.QueryRow(ctx2, "SELECT setting::int FROM pg_settings WHERE name = 'max_connections'").Scan(&maxConns); err != nil {
		maxConns = 0
	}

	var metrics []collector.Metric
	stateMapping := map[string]string{
		"active":              "db.postgresql.connections.active",
		"idle":                "db.postgresql.connections.idle",
		"idle in transaction": "db.postgresql.connections.idle_in_transaction",
		"waiting":             "db.postgresql.connections.waiting",
	}

	// Per-database totals.
	dbTotals := make(map[string]int64)

	for _, r := range stateRows {
		dbLabels := copyLabels(labels)
		if r.dbname != "" {
			dbLabels["dbname"] = r.dbname
		}

		if metricName, ok := stateMapping[r.state]; ok {
			metrics = append(metrics, makeMetric(metricName, float64(r.count), collector.MetricTypeGauge, dbLabels))
		}
		dbTotals[r.dbname] += r.count
	}

	for dbname, total := range dbTotals {
		dbLabels := copyLabels(labels)
		if dbname != "" {
			dbLabels["dbname"] = dbname
		}
		metrics = append(metrics, makeMetric("db.postgresql.connections.total", float64(total), collector.MetricTypeGauge, dbLabels))

		if maxConns > 0 {
			util := safeDiv(float64(total), float64(maxConns)) * 100.0
			metrics = append(metrics, makeMetric("db.postgresql.connections.utilization_pct", util, collector.MetricTypeGauge, dbLabels))
		}
	}

	return metrics, nil
}

// ---------------------------------------------------------------------------
// Transaction / tuple / cache metrics from pg_stat_database
// ---------------------------------------------------------------------------

func collectTransactionMetrics(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `
		SELECT
			datname,
			xact_commit,
			xact_rollback,
			tup_returned,
			tup_fetched,
			tup_inserted,
			tup_updated,
			tup_deleted,
			blks_hit,
			blks_read,
			temp_files,
			temp_bytes
		FROM pg_stat_database
		WHERE datname IS NOT NULL
	`

	rows, err := pool.Query(ctx2, query)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_database: %w", err)
	}
	defer rows.Close()

	type dbStat struct {
		datname      string
		xactCommit   int64
		xactRollback int64
		tupReturned  int64
		tupFetched   int64
		tupInserted  int64
		tupUpdated   int64
		tupDeleted   int64
		blksHit      int64
		blksRead     int64
		tempFiles    int64
		tempBytes    int64
	}

	var stats []dbStat
	for rows.Next() {
		var s dbStat
		if err := rows.Scan(
			&s.datname, &s.xactCommit, &s.xactRollback,
			&s.tupReturned, &s.tupFetched, &s.tupInserted, &s.tupUpdated, &s.tupDeleted,
			&s.blksHit, &s.blksRead, &s.tempFiles, &s.tempBytes,
		); err != nil {
			continue
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pg_stat_database: %w", err)
	}

	now := time.Now()
	elapsed := now.Sub(inst.prevTimestamp).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	var metrics []collector.Metric

	for _, s := range stats {
		dbLabels := copyLabels(labels)
		dbLabels["dbname"] = s.datname

		// Cache hit ratio (gauge).
		blksHitF := float64(s.blksHit)
		blksReadF := float64(s.blksRead)
		hitRatio := safeDiv(blksHitF, blksHitF+blksReadF)
		metrics = append(metrics, makeMetric("db.postgresql.cache.hit_ratio", hitRatio, collector.MetricTypeGauge, dbLabels))

		// Gauge snapshots for current counter values.
		metrics = append(metrics, makeMetric("db.postgresql.transactions.commit", float64(s.xactCommit), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.transactions.rollback", float64(s.xactRollback), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.tuples.returned", float64(s.tupReturned), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.tuples.fetched", float64(s.tupFetched), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.tuples.inserted", float64(s.tupInserted), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.tuples.updated", float64(s.tupUpdated), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.tuples.deleted", float64(s.tupDeleted), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.temp.files", float64(s.tempFiles), collector.MetricTypeCounter, dbLabels))
		metrics = append(metrics, makeMetric("db.postgresql.temp.bytes", float64(s.tempBytes), collector.MetricTypeCounter, dbLabels))

		// Per-second rates via delta tracking.
		counterEntries := []struct {
			key    string
			curr   uint64
			metric string
		}{
			{"xact_commit:" + s.datname, uint64(s.xactCommit), "db.postgresql.transactions.commit_rate"},
			{"xact_rollback:" + s.datname, uint64(s.xactRollback), "db.postgresql.transactions.rollback_rate"},
			{"tup_returned:" + s.datname, uint64(s.tupReturned), "db.postgresql.tuples.returned_rate"},
			{"tup_fetched:" + s.datname, uint64(s.tupFetched), "db.postgresql.tuples.fetched_rate"},
			{"tup_inserted:" + s.datname, uint64(s.tupInserted), "db.postgresql.tuples.inserted_rate"},
			{"tup_updated:" + s.datname, uint64(s.tupUpdated), "db.postgresql.tuples.updated_rate"},
			{"tup_deleted:" + s.datname, uint64(s.tupDeleted), "db.postgresql.tuples.deleted_rate"},
			{"blks_hit:" + s.datname, uint64(s.blksHit), "db.postgresql.blocks.hit_rate"},
			{"blks_read:" + s.datname, uint64(s.blksRead), "db.postgresql.blocks.read_rate"},
			{"temp_files:" + s.datname, uint64(s.tempFiles), "db.postgresql.temp.files_rate"},
			{"temp_bytes:" + s.datname, uint64(s.tempBytes), "db.postgresql.temp.bytes_rate"},
		}

		for _, e := range counterEntries {
			if prev, ok := inst.prevCounters[e.key]; ok && e.curr >= prev {
				delta := float64(e.curr - prev)
				rate := safeDiv(delta, elapsed)
				metrics = append(metrics, emitCounterRate(e.metric, rate, dbLabels))
			}
			inst.prevCounters[e.key] = e.curr
		}
	}

	inst.prevTimestamp = now
	return metrics, nil
}

// ---------------------------------------------------------------------------
// Background writer metrics from pg_stat_bgwriter
// ---------------------------------------------------------------------------

func collectBgWriterMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var cpTimed, cpReq int64
	var cpWriteTime, cpSyncTime float64
	var bufCkpt, bufClean, bufBackend int64
	var maxwrittenClean, bufBackendFsync, bufAlloc int64

	err := pool.QueryRow(ctx2, `
		SELECT
			checkpoints_timed,
			checkpoints_req,
			checkpoint_write_time,
			checkpoint_sync_time,
			buffers_checkpoint,
			buffers_clean,
			buffers_backend,
			maxwritten_clean,
			buffers_backend_fsync,
			buffers_alloc
		FROM pg_stat_bgwriter
	`).Scan(
		&cpTimed, &cpReq, &cpWriteTime, &cpSyncTime,
		&bufCkpt, &bufClean, &bufBackend,
		&maxwrittenClean, &bufBackendFsync, &bufAlloc,
	)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_bgwriter: %w", err)
	}

	return []collector.Metric{
		makeMetric("db.postgresql.bgwriter.checkpoints_timed", float64(cpTimed), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.checkpoints_req", float64(cpReq), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.checkpoint_write_time", cpWriteTime, collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.checkpoint_sync_time", cpSyncTime, collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.buffers_checkpoint", float64(bufCkpt), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.buffers_clean", float64(bufClean), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.buffers_backend", float64(bufBackend), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.maxwritten_clean", float64(maxwrittenClean), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.buffers_backend_fsync", float64(bufBackendFsync), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.bgwriter.buffers_alloc", float64(bufAlloc), collector.MetricTypeCounter, labels),
	}, nil
}

// ---------------------------------------------------------------------------
// WAL metrics from pg_stat_wal (PostgreSQL 14+)
// ---------------------------------------------------------------------------

func collectWALMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var walRecords, walFpi, walBuffersFull, walWrite, walSync int64
	var walBytes int64
	var walWriteTime, walSyncTime float64

	err := pool.QueryRow(ctx2, `
		SELECT
			wal_records,
			wal_fpi,
			wal_bytes,
			wal_buffers_full,
			wal_write,
			wal_sync,
			wal_write_time,
			wal_sync_time
		FROM pg_stat_wal
	`).Scan(
		&walRecords, &walFpi, &walBytes,
		&walBuffersFull, &walWrite, &walSync,
		&walWriteTime, &walSyncTime,
	)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_wal: %w", err)
	}

	return []collector.Metric{
		makeMetric("db.postgresql.wal.records", float64(walRecords), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.wal.fpi", float64(walFpi), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.wal.bytes", float64(walBytes), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.wal.buffers_full", float64(walBuffersFull), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.wal.writes", float64(walWrite), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.wal.syncs", float64(walSync), collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.wal.write_time", walWriteTime, collector.MetricTypeCounter, labels),
		makeMetric("db.postgresql.wal.sync_time", walSyncTime, collector.MetricTypeCounter, labels),
	}, nil
}

// ---------------------------------------------------------------------------
// Database size metrics
// ---------------------------------------------------------------------------

func collectDatabaseSizeMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := pool.Query(ctx2, `
		SELECT datname, pg_database_size(datname)
		FROM pg_database
		WHERE datistemplate = false
	`)
	if err != nil {
		return nil, fmt.Errorf("query database sizes: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var dbname string
		var size int64
		if err := rows.Scan(&dbname, &size); err != nil {
			continue
		}
		dbLabels := copyLabels(labels)
		dbLabels["dbname"] = dbname
		metrics = append(metrics, makeMetric("db.postgresql.db_size.bytes", float64(size), collector.MetricTypeGauge, dbLabels))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate database sizes: %w", err)
	}

	return metrics, nil
}
