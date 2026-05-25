// Package clickhouse_test contains unit tests for the corresponding collector module.
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

package clickhouse_test

import (
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	clickhouse "github.com/telemetryflow/telemetryflow-agent/internal/collector/clickhouse"
)

// processDiskRows simulates the disk section of collectStorage for testing.
func processDiskRows(rows []map[string]interface{}, baseLabels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	for _, row := range rows {
		diskName := clickhouse.ToStringExported(row["name"])
		if diskName == "" {
			continue
		}
		lbl := clickhouse.MergeLabelsExported(baseLabels, map[string]string{
			"disk":      diskName,
			"disk_type": clickhouse.ToStringExported(row["type"]),
		})

		type dfield struct {
			key  string
			name string
		}
		dfields := []dfield{
			{"free_space", "db.clickhouse.disk.free_space"},
			{"total_space", "db.clickhouse.disk.total_space"},
			{"unreserved_space", "db.clickhouse.disk.unreserved_space"},
		}
		for _, f := range dfields {
			val, err := clickhouse.ToFloat64Exported(row[f.key])
			if err != nil {
				continue
			}
			m := clickhouse.MakeMetricExported(f.name, val, collector.MetricTypeGauge, lbl)
			m.Unit = "By"
			metrics = append(metrics, m)
		}

		freeVal, ferr := clickhouse.ToFloat64Exported(row["free_space"])
		totalVal, terr := clickhouse.ToFloat64Exported(row["total_space"])
		if ferr == nil && terr == nil && totalVal > 0 {
			usedPct := (totalVal - freeVal) / totalVal * 100
			m := clickhouse.MakeMetricExported("db.clickhouse.disk.used_percent", usedPct, collector.MetricTypeGauge, lbl)
			m.Unit = "%"
			metrics = append(metrics, m)
		}
	}
	return metrics
}

func TestProcessDiskRows(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"name": "default", "type": "local",
			"free_space": "30000000000", "total_space": "100000000000",
			"unreserved_space": "25000000000",
		},
	}
	metrics := processDiskRows(rows, map[string]string{"instance": "ch1"})

	// 3 basic fields + 1 derived used_percent = 4
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metrics, got %d", len(metrics))
	}

	free := findMetric(metrics, "db.clickhouse.disk.free_space")
	if free == nil || free.Value != 3e10 {
		t.Errorf("free_space = %f, want 3e10", free.Value)
	}

	used := findMetric(metrics, "db.clickhouse.disk.used_percent")
	if used == nil {
		t.Fatal("missing used_percent")
	}
	// (1e11 - 3e10) / 1e11 * 100 = 70
	expectedUsed := 70.0
	if used.Value != expectedUsed {
		t.Errorf("used_percent = %f, want %f", used.Value, expectedUsed)
	}
	if used.Unit != "%" {
		t.Errorf("used_percent unit = %q, want %%", used.Unit)
	}
	if used.Labels["disk"] != "default" {
		t.Error("disk label missing")
	}
}

func TestProcessDiskRows_ZeroTotalSpace(t *testing.T) {
	rows := []map[string]interface{}{
		{"name": "empty", "type": "local", "free_space": "0", "total_space": "0", "unreserved_space": "0"},
	}
	metrics := processDiskRows(rows, nil)
	// Should have 3 basic metrics but no used_percent (total=0)
	used := findMetric(metrics, "db.clickhouse.disk.used_percent")
	if used != nil {
		t.Error("should not emit used_percent when total_space is 0")
	}
}

func TestProcessDiskRows_EmptyName(t *testing.T) {
	rows := []map[string]interface{}{
		{"name": "", "type": "local", "free_space": "100", "total_space": "200"},
	}
	metrics := processDiskRows(rows, nil)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for empty disk name, got %d", len(metrics))
	}
}
