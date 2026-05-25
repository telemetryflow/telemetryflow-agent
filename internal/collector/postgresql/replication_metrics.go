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

// collectReplicationMetrics gathers streaming replication lag, replication slot
// status and WAL retention from a PostgreSQL primary instance.
// On standby instances (pg_is_in_recovery() = true) the function returns nil.
func collectReplicationMetrics(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Determine whether this instance is a primary or a standby.
	var inRecovery bool
	if err := pool.QueryRow(ctx2, "SELECT pg_is_in_recovery()").Scan(&inRecovery); err != nil {
		return nil, fmt.Errorf("check recovery status: %w", err)
	}
	if inRecovery {
		logger.Debug("instance is a standby, skipping replication metrics")
		return nil, nil
	}

	var all []collector.Metric

	// --- a) Streaming replication from pg_stat_replication ---
	if m, err := collectReplicationLag(ctx2, pool, labels, logger); err != nil {
		logger.Debug("replication lag query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	// --- b) Replication slot metrics ---
	if m, err := collectReplicationSlots(ctx2, pool, labels, logger); err != nil {
		logger.Debug("replication slots query failed", zap.Error(err))
	} else {
		all = append(all, m...)
	}

	return all, nil
}

// collectReplicationLag queries pg_stat_replication for each connected standby
// and emits lag durations and byte-based lag.
func collectReplicationLag(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT pid,
	                  usename,
	                  application_name,
	                  client_addr::text,
	                  state,
	                  sent_lsn::text,
	                  write_lsn::text,
	                  flush_lsn::text,
	                  replay_lsn::text,
	                  write_lag,
	                  flush_lag,
	                  replay_lag,
	                  COALESCE(slot_name, '') AS slot_name
	           FROM pg_stat_replication`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("replication lag: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var pid int32
		var usename, appName, clientAddr, state string
		var sentLSN, writeLSN, flushLSN, replayLSN, slotName string
		var writeLag, flushLag, replayLag *time.Duration

		if err := rows.Scan(
			&pid, &usename, &appName, &clientAddr, &state,
			&sentLSN, &writeLSN, &flushLSN, &replayLSN,
			&writeLag, &flushLag, &replayLag,
			&slotName,
		); err != nil {
			logger.Debug("replication row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["client_addr"] = clientAddr
		rowLabels["application_name"] = appName
		rowLabels["state"] = state
		rowLabels["usename"] = usename

		// Emit lag durations in seconds.
		if writeLag != nil {
			metrics = append(metrics,
				makeMetric("db.postgresql.replication.write_lag_sec", writeLag.Seconds(), collector.MetricTypeGauge, rowLabels),
			)
		}
		if flushLag != nil {
			metrics = append(metrics,
				makeMetric("db.postgresql.replication.flush_lag_sec", flushLag.Seconds(), collector.MetricTypeGauge, rowLabels),
			)
		}
		if replayLag != nil {
			metrics = append(metrics,
				makeMetric("db.postgresql.replication.replay_lag_sec", replayLag.Seconds(), collector.MetricTypeGauge, rowLabels),
			)
		}

		// Emit PID for debugging / correlation.
		metrics = append(metrics,
			makeMetric("db.postgresql.replication.backend_pid", float64(pid), collector.MetricTypeGauge, rowLabels),
		)
	}

	if err := rows.Err(); err != nil {
		return metrics, err
	}

	// Compute byte-based LSN lag using pg_wal_lsn_diff for each standby row.
	// We run a second query to avoid complex correlated subqueries and to
	// handle the case where pg_stat_replication rows may have changed.
	byteMetrics, err := collectReplicationLagBytes(ctx, pool, labels, logger)
	if err != nil {
		logger.Debug("replication lag bytes query failed", zap.Error(err))
	} else {
		metrics = append(metrics, byteMetrics...)
	}

	return metrics, nil
}

// collectReplicationLagBytes emits byte-based replication lag for each standby
// using pg_wal_lsn_diff(sent_lsn, replay_lsn).
func collectReplicationLagBytes(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT application_name,
	                  client_addr::text,
	                  state,
	                  pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag_bytes
	           FROM pg_stat_replication`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("replication lag bytes: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var appName, clientAddr, state string
		var lagBytes int64

		if err := rows.Scan(&appName, &clientAddr, &state, &lagBytes); err != nil {
			logger.Debug("replication lag bytes row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["client_addr"] = clientAddr
		rowLabels["application_name"] = appName
		rowLabels["state"] = state

		metrics = append(metrics,
			makeMetric("db.postgresql.replication.lag_bytes", float64(lagBytes), collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}

// collectReplicationSlots queries pg_replication_slots for slot status and
// WAL retention.
func collectReplicationSlots(ctx context.Context, pool *pgxpool.Pool, labels map[string]string, logger *zap.Logger) ([]collector.Metric, error) {
	const q = `SELECT slot_name,
	                  slot_type,
	                  active,
	                  pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS retained_bytes
	           FROM pg_replication_slots`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("replication slots: %w", err)
	}
	defer rows.Close()

	var metrics []collector.Metric
	for rows.Next() {
		var slotName, slotType string
		var active bool
		var retainedBytes int64

		if err := rows.Scan(&slotName, &slotType, &active, &retainedBytes); err != nil {
			logger.Debug("replication slot row scan failed", zap.Error(err))
			continue
		}

		rowLabels := copyLabels(labels)
		rowLabels["slot_name"] = slotName
		rowLabels["slot_type"] = slotType

		activeVal := 0.0
		if active {
			activeVal = 1.0
		}

		metrics = append(metrics,
			makeMetric("db.postgresql.replication.slot.active", activeVal, collector.MetricTypeGauge, rowLabels),
			makeMetric("db.postgresql.replication.slot.retain_bytes", float64(retainedBytes), collector.MetricTypeGauge, rowLabels),
		)
	}
	return metrics, rows.Err()
}
