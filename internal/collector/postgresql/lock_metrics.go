// Package postgresql implements the PostgreSQL database monitoring collector.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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

func collectLockMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	var metrics []collector.Metric

	if m, err := collectLocksByType(ctx, pool, labels); err != nil {
		logger.Debug("Locks by type failed", zap.Error(err))
	} else {
		metrics = append(metrics, m...)
	}

	if m, err := collectLocksByMode(ctx, pool, labels); err != nil {
		logger.Debug("Locks by mode failed", zap.Error(err))
	} else {
		metrics = append(metrics, m...)
	}

	if m, err := collectBlockedQueryMetrics(ctx, pool, labels); err != nil {
		logger.Debug("Blocked query metrics failed", zap.Error(err))
	} else {
		metrics = append(metrics, m...)
	}

	return metrics, nil
}

// ---------------------------------------------------------------------------
// Lock counts grouped by lock type
// ---------------------------------------------------------------------------

func collectLocksByType(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := pool.Query(ctx2, `
		SELECT locktype, count(*) AS cnt
		FROM pg_locks
		GROUP BY locktype
	`)
	if err != nil {
		return nil, fmt.Errorf("query locks by type: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var lockType string
		var cnt int64
		if err := rows.Scan(&lockType, &cnt); err != nil {
			continue
		}
		l := copyLabels(labels)
		l["locktype"] = lockType
		metrics = append(metrics, makeMetric("db.postgresql.locks.count", float64(cnt), collector.MetricTypeGauge, l))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locks by type: %w", err)
	}

	return metrics, nil
}

// ---------------------------------------------------------------------------
// Lock counts grouped by mode
// ---------------------------------------------------------------------------

func collectLocksByMode(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := pool.Query(ctx2, `
		SELECT mode, count(*) AS cnt
		FROM pg_locks
		GROUP BY mode
	`)
	if err != nil {
		return nil, fmt.Errorf("query locks by mode: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var mode string
		var cnt int64
		if err := rows.Scan(&mode, &cnt); err != nil {
			continue
		}
		l := copyLabels(labels)
		l["mode"] = mode
		metrics = append(metrics, makeMetric("db.postgresql.locks.count", float64(cnt), collector.MetricTypeGauge, l))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locks by mode: %w", err)
	}

	return metrics, nil
}

// ---------------------------------------------------------------------------
// Blocked queries: count and longest wait
// ---------------------------------------------------------------------------

func collectBlockedQueryMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Count blocked queries and longest wait time.
	// pg_locks.granted = false means the lock is waiting.
	// Join with pg_stat_activity to compute how long each blocked session
	// has been waiting (using now() - query_start).
	var blockedCount int64
	var longestWaitSec float64

	err := pool.QueryRow(ctx2, `
		SELECT
			count(*) AS blocked_count,
			COALESCE(EXTRACT(EPOCH FROM max(now() - a.query_start)), 0) AS longest_wait_sec
		FROM pg_locks l
		JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE NOT l.granted
	`).Scan(&blockedCount, &longestWaitSec)
	if err != nil {
		return nil, fmt.Errorf("query blocked locks: %w", err)
	}

	return []collector.Metric{
		makeMetric("db.postgresql.locks.blocked_count", float64(blockedCount), collector.MetricTypeGauge, labels),
		makeMetric("db.postgresql.locks.longest_wait_sec", longestWaitSec, collector.MetricTypeGauge, labels),
	}, nil
}
