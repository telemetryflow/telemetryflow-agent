// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
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
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// Regex patterns for query fingerprinting.
var (
	reQuotedString = regexp.MustCompile(`'[^']*'`)
	reDollarString = regexp.MustCompile(`\$\$.*?\$\$`)
	reNumberLit    = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	reInList       = regexp.MustCompile(`\bIN\s*\([^)]+\)`)
)

// fingerprintQuery normalises a SQL query by replacing literals with placeholders
// and returns the SHA-256 hex digest of the normalised text.
func fingerprintQuery(query string) string {
	normalised := query

	// Replace $$-delimited strings first.
	normalised = reDollarString.ReplaceAllString(normalised, "$$1$$")

	// Replace single-quoted strings.
	normalised = reQuotedString.ReplaceAllString(normalised, "'$1'")

	// Replace IN (...) lists.
	normalised = reInList.ReplaceAllString(normalised, "IN ($3)")

	// Replace numeric literals.
	normalised = reNumberLit.ReplaceAllString(normalised, "$2")

	// Collapse whitespace.
	normalised = strings.TrimSpace(normalised)
	normalised = regexp.MustCompile(`\s+`).ReplaceAllString(normalised, " ")

	h := sha256.Sum256([]byte(normalised))
	return fmt.Sprintf("%x", h[:16]) // first 16 bytes = 32 hex chars
}

func collectQueryAnalytics(ctx context.Context, pool *pgxpool.Pool, inst *pgInstance, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	limit := inst.topQueriesLimit
	if limit <= 0 {
		limit = 200
	}

	// ---------------------------------------------------------------------------
	// 1. pg_stat_statements — top N queries
	// ---------------------------------------------------------------------------

	// Check if pg_stat_statements is available.
	var extExists bool
	if err := pool.QueryRow(ctx2,
		"SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')",
	).Scan(&extExists); err != nil || !extExists {
		logger.Debug("pg_stat_statements extension not installed",
			zap.String("instance", inst.config.Name),
		)
		// Still collect wait events even without pg_stat_statements.
		return collectWaitEvents(ctx2, pool, labels, logger)
	}

	// Choose columns based on version (PG13+ renamed total_time to total_exec_time).
	useExecCols := hasExecTimeColumns(inst)

	var query string
	if useExecCols {
		query = `
			SELECT queryid, query, calls, total_exec_time, mean_exec_time, min_exec_time, max_exec_time,
			       rows, shared_blks_hit, shared_blks_read, shared_blks_dirtied, shared_blks_written,
			       temp_blks_read, temp_blks_written, blk_read_time, blk_write_time
			FROM pg_stat_statements
			ORDER BY total_exec_time DESC
			LIMIT $1`
	} else {
		query = `
			SELECT queryid, query, calls, total_time, mean_time, min_time, max_time,
			       rows, shared_blks_hit, shared_blks_read, shared_blks_dirtied, shared_blks_written,
			       temp_blks_read, temp_blks_written, blk_read_time, blk_write_time
			FROM pg_stat_statements
			ORDER BY total_time DESC
			LIMIT $1`
	}

	rows, err := pool.Query(ctx2, query, limit)
	if err != nil {
		return nil, fmt.Errorf("postgresql %s: query pg_stat_statements: %w", inst.config.Name, err)
	}
	defer rows.Close()

	type stmtRow struct {
		queryid           uint64
		query             string
		calls             uint64
		totalExecTime     float64
		meanExecTime      float64
		minExecTime       float64
		maxExecTime       float64
		rows_             uint64
		sharedBlksHit     uint64
		sharedBlksRead    uint64
		sharedBlksDirtied uint64
		sharedBlksWritten uint64
		tempBlksRead      uint64
		tempBlksWritten   uint64
		blkReadTime       float64
		blkWriteTime      float64
	}

	var current []stmtRow
	for rows.Next() {
		var r stmtRow
		if err := rows.Scan(
			&r.queryid, &r.query, &r.calls,
			&r.totalExecTime, &r.meanExecTime, &r.minExecTime, &r.maxExecTime,
			&r.rows_, &r.sharedBlksHit, &r.sharedBlksRead, &r.sharedBlksDirtied, &r.sharedBlksWritten,
			&r.tempBlksRead, &r.tempBlksWritten, &r.blkReadTime, &r.blkWriteTime,
		); err != nil {
			logger.Debug("Failed to scan pg_stat_statements row", zap.Error(err))
			continue
		}
		current = append(current, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgresql %s: iterate pg_stat_statements: %w", inst.config.Name, err)
	}

	var metrics []collector.Metric

	elapsed := time.Since(inst.prevTimestamp)
	if elapsed <= 0 {
		elapsed = time.Second
	}
	elapsedSec := elapsed.Seconds()

	for _, r := range current {
		qidStr := strconv.FormatUint(r.queryid, 10)
		fp := fingerprintQuery(r.query)

		qLabels := make(map[string]string, len(labels)+2)
		for k, v := range labels {
			qLabels[k] = v
		}
		qLabels["queryid"] = qidStr
		qLabels["fingerprint"] = fp

		// -------------------------------------------------------------------
		// Delta computation using prevCounters
		// -------------------------------------------------------------------
		callsKey := fmt.Sprintf("query:%s:calls", qidStr)
		timeKey := fmt.Sprintf("query:%s:total_exec_time", qidStr)
		rowsKey := fmt.Sprintf("query:%s:rows", qidStr)

		prevCalls, hasPrevCalls := inst.prevCounters[callsKey]
		prevTime, hasPrevTime := inst.prevCounters[timeKey]
		prevRows, hasPrevRows := inst.prevCounters[rowsKey]

		if hasPrevCalls && hasPrevTime && hasPrevRows {
			deltaCalls := int64(r.calls) - int64(prevCalls)
			deltaTime := r.totalExecTime - float64(prevTime)
			deltaRows := int64(r.rows_) - int64(prevRows)

			if deltaCalls > 0 {
				metrics = append(metrics,
					emitCounterRate("db.postgresql.queries.calls_rate", float64(deltaCalls)/elapsedSec, qLabels),
					emitCounterRate("db.postgresql.queries.exec_time_rate", deltaTime/elapsedSec, qLabels),
					emitCounterRate("db.postgresql.queries.rows_rate", float64(deltaRows)/elapsedSec, qLabels),
				)
			}
		}

		// Always emit current snapshot values.
		metrics = append(metrics,
			makeMetric("db.postgresql.queries.mean_exec_time", r.meanExecTime, collector.MetricTypeGauge, qLabels),
			makeMetric("db.postgresql.queries.max_exec_time", r.maxExecTime, collector.MetricTypeGauge, qLabels),
		)
	}

	// Update previous counters for next cycle.
	newCounters := make(map[string]uint64, len(current)*3)
	for _, r := range current {
		qidStr := strconv.FormatUint(r.queryid, 10)
		newCounters[fmt.Sprintf("query:%s:calls", qidStr)] = r.calls
		newCounters[fmt.Sprintf("query:%s:total_exec_time", qidStr)] = uint64(r.totalExecTime)
		newCounters[fmt.Sprintf("query:%s:rows", qidStr)] = r.rows_
	}
	inst.prevCounters = newCounters
	inst.prevTimestamp = time.Now()

	// ---------------------------------------------------------------------------
	// 2. Wait events from pg_stat_activity
	// ---------------------------------------------------------------------------
	waitMetrics, err := collectWaitEvents(ctx2, pool, labels, logger)
	if err != nil {
		logger.Debug("Wait event collection skipped",
			zap.String("instance", inst.config.Name),
			zap.Error(err),
		)
	} else {
		metrics = append(metrics, waitMetrics...)
	}

	return metrics, nil
}

// collectWaitEvents queries pg_stat_activity for current wait events.
func collectWaitEvents(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	query := `
		SELECT wait_event_type, wait_event, count(*)
		FROM pg_stat_activity
		WHERE wait_event IS NOT NULL
		  AND backend_type = 'client backend'
		GROUP BY wait_event_type, wait_event`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var waitEventType, waitEvent string
		var cnt uint64
		if err := rows.Scan(&waitEventType, &waitEvent, &cnt); err != nil {
			continue
		}

		wLabels := make(map[string]string, len(labels)+2)
		for k, v := range labels {
			wLabels[k] = v
		}
		wLabels["wait_event_type"] = waitEventType
		wLabels["wait_event"] = waitEvent

		metrics = append(metrics,
			makeMetric("db.postgresql.wait_events.count", float64(cnt), collector.MetricTypeGauge, wLabels),
		)
	}
	return metrics, rows.Err()
}
