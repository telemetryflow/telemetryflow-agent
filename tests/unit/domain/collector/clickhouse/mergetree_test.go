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

// processPartsRows simulates the parts section of collectMergeTree for testing.
func processPartsRows(rows []map[string]interface{}, baseLabels map[string]string) []collector.Metric {
	var metrics []collector.Metric
	for _, row := range rows {
		db := clickhouse.ToStringExported(row["database"])
		table := clickhouse.ToStringExported(row["table"])
		if db == "" || table == "" {
			continue
		}
		lbl := clickhouse.MergeLabelsExported(baseLabels, map[string]string{"db": db, "table": table})

		type field struct {
			key  string
			name string
			unit string
		}
		fields := []field{
			{"parts_count", "db.clickhouse.mergetree.parts_count", ""},
			{"total_rows", "db.clickhouse.mergetree.rows", ""},
			{"bytes_on_disk", "db.clickhouse.mergetree.bytes_on_disk", "By"},
			{"compressed_bytes", "db.clickhouse.mergetree.compressed_bytes", "By"},
			{"uncompressed_bytes", "db.clickhouse.mergetree.uncompressed_bytes", "By"},
			{"partition_count", "db.clickhouse.mergetree.partition_count", ""},
		}
		for _, f := range fields {
			val, err := clickhouse.ToFloat64Exported(row[f.key])
			if err != nil {
				continue
			}
			m := clickhouse.MakeMetricExported(f.name, val, collector.MetricTypeGauge, lbl)
			if f.unit != "" {
				m.Unit = f.unit
			}
			metrics = append(metrics, m)
		}
	}
	return metrics
}

func TestProcessPartsRows(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"database": "mydb", "table": "events",
			"parts_count": "10", "total_rows": "1000000",
			"bytes_on_disk": "52428800", "compressed_bytes": "31457280",
			"uncompressed_bytes": "83886080", "partition_count": "5",
		},
	}
	metrics := processPartsRows(rows, map[string]string{"instance": "ch1"})

	expected := []struct {
		name  string
		value float64
		unit  string
	}{
		{"db.clickhouse.mergetree.parts_count", 10, ""},
		{"db.clickhouse.mergetree.rows", 1000000, ""},
		{"db.clickhouse.mergetree.bytes_on_disk", 52428800, "By"},
		{"db.clickhouse.mergetree.compressed_bytes", 31457280, "By"},
		{"db.clickhouse.mergetree.uncompressed_bytes", 83886080, "By"},
		{"db.clickhouse.mergetree.partition_count", 5, ""},
	}

	if len(metrics) != len(expected) {
		t.Fatalf("expected %d metrics, got %d", len(expected), len(metrics))
	}

	for _, exp := range expected {
		m := findMetric(metrics, exp.name)
		if m == nil {
			t.Errorf("missing metric %s", exp.name)
			continue
		}
		if m.Value != exp.value {
			t.Errorf("%s = %f, want %f", exp.name, m.Value, exp.value)
		}
		if m.Unit != exp.unit {
			t.Errorf("%s unit = %q, want %q", exp.name, m.Unit, exp.unit)
		}
		if m.Labels["db"] != "mydb" {
			t.Errorf("%s labels[db] = %q, want mydb", exp.name, m.Labels["db"])
		}
	}
}

func TestProcessPartsRows_MissingFields(t *testing.T) {
	rows := []map[string]interface{}{
		{"database": "db1", "table": "t1", "parts_count": "5"},
	}
	metrics := processPartsRows(rows, nil)
	// Missing keys resolve to nil which toFloat64 converts to 0 (no error)
	// So all 6 fields are emitted, with missing ones as 0
	if len(metrics) != 6 {
		t.Errorf("expected 6 metrics (missing fields become 0), got %d", len(metrics))
	}
	partsCount := findMetric(metrics, "db.clickhouse.mergetree.parts_count")
	if partsCount == nil || partsCount.Value != 5 {
		t.Error("parts_count should be 5")
	}
	rowsCount := findMetric(metrics, "db.clickhouse.mergetree.rows")
	if rowsCount == nil || rowsCount.Value != 0 {
		t.Error("missing rows should be 0")
	}
}

func TestProcessPartsRows_EmptyDBOrTable(t *testing.T) {
	rows := []map[string]interface{}{
		{"database": "", "table": "t1", "parts_count": "5"},
		{"database": "db1", "table": "", "parts_count": "5"},
	}
	metrics := processPartsRows(rows, nil)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for empty db/table, got %d", len(metrics))
	}
}

func TestProcessMutationRows(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"database": "mydb", "table": "events",
			"mutation_id": "mut_001",
			"is_done":     "1", "parts_to_do": "0",
			"latest_fail_reason": "",
		},
		{
			"database": "mydb", "table": "logs",
			"mutation_id": "mut_002",
			"is_done":     "0", "parts_to_do": "3",
			"latest_fail_reason": "Timeout",
		},
	}

	var metrics []collector.Metric
	for _, row := range rows {
		db := clickhouse.ToStringExported(row["database"])
		table := clickhouse.ToStringExported(row["table"])
		mutID := clickhouse.ToStringExported(row["mutation_id"])
		if db == "" || table == "" {
			continue
		}
		lbl := clickhouse.MergeLabelsExported(nil, map[string]string{
			"db": db, "table": table, "mutation_id": mutID,
		})
		isDone, _ := clickhouse.ToFloat64Exported(row["is_done"])
		partsToDo, _ := clickhouse.ToFloat64Exported(row["parts_to_do"])
		hasFail := 0.0
		if reason := clickhouse.ToStringExported(row["latest_fail_reason"]); reason != "" {
			hasFail = 1.0
		}
		metrics = append(metrics,
			clickhouse.MakeMetricExported("db.clickhouse.mutation.is_done", isDone, collector.MetricTypeGauge, lbl),
			clickhouse.MakeMetricExported("db.clickhouse.mutation.parts_to_do", partsToDo, collector.MetricTypeGauge, lbl),
			clickhouse.MakeMetricExported("db.clickhouse.mutation.has_failure", hasFail, collector.MetricTypeGauge, lbl),
		)
	}

	if len(metrics) != 6 {
		t.Fatalf("expected 6 metrics (3 per row * 2), got %d", len(metrics))
	}
	doneMut1 := findMetric(metrics, "db.clickhouse.mutation.is_done")
	if doneMut1 == nil || doneMut1.Value != 1 {
		t.Error("mut_001 is_done should be 1")
	}
	failMut2 := findMetric(metrics, "db.clickhouse.mutation.has_failure")
	if failMut2 == nil || failMut2.Value != 0 {
		t.Error("first has_failure should be 0 (no reason)")
	}
}
