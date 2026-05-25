// Package clickhouse_test contains unit tests for the corresponding collector module.
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

package clickhouse_test

import (
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	clickhouse "github.com/telemetryflow/telemetryflow-agent/internal/collector/clickhouse"
)

// processReplicaRows simulates the replicas section of collectReplication for testing.
func processReplicaRows(rows []map[string]interface{}, baseLabels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	for _, row := range rows {
		db := clickhouse.ToStringExported(row["database"])
		table := clickhouse.ToStringExported(row["table"])
		if db == "" || table == "" {
			continue
		}
		lbl := clickhouse.MergeLabelsExported(baseLabels, map[string]string{"db": db, "table": table})

		type rfield struct {
			key  string
			name string
		}
		rfields := []rfield{
			{"is_leader", "db.clickhouse.replica.is_leader"},
			{"is_readonly", "db.clickhouse.replica.is_readonly"},
			{"queue_size", "db.clickhouse.replica.queue_size"},
			{"absolute_delay", "db.clickhouse.replica.absolute_delay"},
		}
		for _, f := range rfields {
			val, err := clickhouse.ToFloat64Exported(row[f.key])
			if err != nil {
				continue
			}
			metrics = append(metrics, clickhouse.MakeMetricExported(f.name, val, collector.MetricTypeGauge, lbl))
		}
	}
	return metrics
}

func TestProcessReplicaRows(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"database": "mydb", "table": "events",
			"is_leader": "1", "is_readonly": "0",
			"queue_size": "5", "absolute_delay": "12.5",
		},
	}
	metrics := processReplicaRows(rows, map[string]string{"instance": "ch1"})

	leader := findMetric(metrics, "db.clickhouse.replica.is_leader")
	if leader == nil || leader.Value != 1 {
		t.Error("is_leader should be 1")
	}
	readonly := findMetric(metrics, "db.clickhouse.replica.is_readonly")
	if readonly == nil || readonly.Value != 0 {
		t.Error("is_readonly should be 0")
	}
	queue := findMetric(metrics, "db.clickhouse.replica.queue_size")
	if queue == nil || queue.Value != 5 {
		t.Error("queue_size should be 5")
	}
	delay := findMetric(metrics, "db.clickhouse.replica.absolute_delay")
	if delay == nil || delay.Value != 12.5 {
		t.Error("absolute_delay should be 12.5")
	}
	if len(metrics) != 4 {
		t.Errorf("expected 4 metrics, got %d", len(metrics))
	}
}

func TestProcessReplicaRows_EmptyDB(t *testing.T) {
	rows := []map[string]interface{}{
		{"database": "", "table": "events", "is_leader": "1"},
	}
	metrics := processReplicaRows(rows, nil)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for empty database, got %d", len(metrics))
	}
}

func TestProcessClusterRows(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"cluster": "prod", "host_name": "ch1",
			"shard_num": "1", "replica_num": "1",
			"shard_weight": "1", "is_local": "1", "errors_count": "0",
		},
	}
	var metrics []collector.Metric
	for _, row := range rows {
		cluster := clickhouse.ToStringExported(row["cluster"])
		if cluster == "" {
			continue
		}
		lbl := clickhouse.MergeLabelsExported(nil, map[string]string{
			"cluster":     cluster,
			"host":        clickhouse.ToStringExported(row["host_name"]),
			"shard_num":   clickhouse.ToStringExported(row["shard_num"]),
			"replica_num": clickhouse.ToStringExported(row["replica_num"]),
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
			val, err := clickhouse.ToFloat64Exported(row[f.key])
			if err != nil {
				continue
			}
			metrics = append(metrics, clickhouse.MakeMetricExported(f.name, val, collector.MetricTypeGauge, lbl))
		}
	}

	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics, got %d", len(metrics))
	}
	isLocal := findMetric(metrics, "db.clickhouse.cluster.is_local")
	if isLocal == nil || isLocal.Value != 1 {
		t.Error("is_local should be 1")
	}
	if isLocal.Labels["cluster"] != "prod" {
		t.Error("cluster label missing")
	}
}
