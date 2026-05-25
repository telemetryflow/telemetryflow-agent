// Package clickhouse — replication lag, replica health, and cluster topology metrics.
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
package clickhouse

import (
	"context"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectReplication gathers replica queue depths, health flags, and cluster layout metrics.
func collectReplication(
	ctx context.Context,
	conn *connection,
	labels map[string]string,
	logger *zap.Logger,
) ([]collector.Metric, error) {
	var metrics []collector.Metric

	// -----------------------------------------------------------------
	// system.replicas — per-table replica health
	// -----------------------------------------------------------------
	replicaQuery := `
		SELECT
			database,
			table,
			is_leader,
			is_readonly,
			is_session_expired,
			future_parts,
			parts_to_check,
			queue_size,
			inserts_in_queue,
			merges_in_queue,
			total_replicas,
			active_replicas,
			absolute_delay
		FROM system.replicas`

	replicaRows, err := conn.Execute(ctx, replicaQuery)
	if err != nil {
		logger.Debug("system.replicas query failed", zap.Error(err))
		// Non-fatal — table is empty on non-replicated setups.
		return metrics, nil
	}

	for _, row := range replicaRows {
		db := toString(row["database"])
		table := toString(row["table"])
		if db == "" || table == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{"db": db, "table": table})

		type rfield struct {
			key  string
			name string
		}
		rfields := []rfield{
			{"is_leader", "db.clickhouse.replica.is_leader"},
			{"is_readonly", "db.clickhouse.replica.is_readonly"},
			{"is_session_expired", "db.clickhouse.replica.is_session_expired"},
			{"future_parts", "db.clickhouse.replica.future_parts"},
			{"parts_to_check", "db.clickhouse.replica.parts_to_check"},
			{"queue_size", "db.clickhouse.replica.queue_size"},
			{"inserts_in_queue", "db.clickhouse.replica.inserts_in_queue"},
			{"merges_in_queue", "db.clickhouse.replica.merges_in_queue"},
			{"total_replicas", "db.clickhouse.replica.total_replicas"},
			{"active_replicas", "db.clickhouse.replica.active_replicas"},
			{"absolute_delay", "db.clickhouse.replica.absolute_delay"},
		}
		for _, f := range rfields {
			val, err := toFloat64(row[f.key])
			if err != nil {
				continue
			}
			metrics = append(metrics, makeMetric(f.name, val, collector.MetricTypeGauge, lbl))
		}
	}

	// -----------------------------------------------------------------
	// system.clusters — cluster topology info
	// -----------------------------------------------------------------
	clusterQuery := `
		SELECT
			cluster,
			shard_num,
			shard_weight,
			replica_num,
			host_name,
			host_address,
			port,
			is_local,
			errors_count
		FROM system.clusters`

	clusterRows, err := conn.Execute(ctx, clusterQuery)
	if err != nil {
		logger.Debug("system.clusters query failed", zap.Error(err))
		return metrics, nil
	}

	for _, row := range clusterRows {
		cluster := toString(row["cluster"])
		hostName := toString(row["host_name"])
		shardNum := toString(row["shard_num"])
		replicaNum := toString(row["replica_num"])
		if cluster == "" {
			continue
		}
		lbl := mergeLabels(labels, map[string]string{
			"cluster":     cluster,
			"host":        hostName,
			"shard_num":   shardNum,
			"replica_num": replicaNum,
		})

		type cfield struct {
			key  string
			name string
		}
		cfields := []cfield{
			{"shard_weight", "db.clickhouse.cluster.shard_weight"},
			{"is_local", "db.clickhouse.cluster.is_local"},
			{"errors_count", "db.clickhouse.cluster.errors_count"},
		}
		for _, f := range cfields {
			val, err := toFloat64(row[f.key])
			if err != nil {
				continue
			}
			metrics = append(metrics, makeMetric(f.name, val, collector.MetricTypeGauge, lbl))
		}
	}

	return metrics, nil
}
