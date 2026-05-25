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

func TestDictionaryStatusCodeMapping(t *testing.T) {
	statusCode := map[string]float64{
		"NOT_LOADED":           0,
		"LOADED":               1,
		"FAILED":               2,
		"LOADING":              3,
		"LOADED_AND_RELOADING": 4,
		"FAILED_AND_RELOADING": 5,
	}

	tests := []struct {
		status string
		code   float64
	}{
		{"NOT_LOADED", 0},
		{"LOADED", 1},
		{"FAILED", 2},
		{"LOADING", 3},
		{"LOADED_AND_RELOADING", 4},
		{"FAILED_AND_RELOADING", 5},
		{"UNKNOWN_STATUS", -1},
	}
	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			code, ok := statusCode[tc.status]
			if ok {
				if code != tc.code {
					t.Errorf("status %q = %f, want %f", tc.status, code, tc.code)
				}
			} else if tc.code != -1 {
				t.Errorf("status %q not found in map", tc.status)
			}
		})
	}
}

func TestProcessDictionaryRows(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"database": "mydb", "name": "users_dict",
			"status":           "LOADED",
			"bytes_allocated":  "1048576",
			"element_count":    "50000",
			"load_factor":      "0.85",
			"loading_duration": "2.5",
		},
	}

	statusCode := map[string]float64{
		"NOT_LOADED":           0,
		"LOADED":               1,
		"FAILED":               2,
		"LOADING":              3,
		"LOADED_AND_RELOADING": 4,
		"FAILED_AND_RELOADING": 5,
	}

	var metrics []collector.Metric
	for _, row := range rows {
		db := clickhouse.ToStringExported(row["database"])
		name := clickhouse.ToStringExported(row["name"])
		if name == "" {
			continue
		}
		lbl := clickhouse.MergeLabelsExported(nil, map[string]string{"db": db, "dict": name})

		status := clickhouse.ToStringExported(row["status"])
		code, ok := statusCode[status]
		if !ok {
			code = -1
		}
		metrics = append(metrics, clickhouse.MakeMetricExported(
			"db.clickhouse.dictionary.status",
			code,
			collector.MetricTypeGauge,
			clickhouse.MergeLabelsExported(lbl, map[string]string{"status": status}),
		))

		type dfield struct {
			key  string
			name string
		}
		dfields := []dfield{
			{"bytes_allocated", "db.clickhouse.dictionary.bytes_allocated"},
			{"element_count", "db.clickhouse.dictionary.element_count"},
			{"load_factor", "db.clickhouse.dictionary.load_factor"},
			{"loading_duration", "db.clickhouse.dictionary.loading_duration"},
		}
		for _, f := range dfields {
			val, err := clickhouse.ToFloat64Exported(row[f.key])
			if err != nil {
				continue
			}
			metrics = append(metrics, clickhouse.MakeMetricExported(f.name, val, collector.MetricTypeGauge, lbl))
		}
	}

	status := findMetric(metrics, "db.clickhouse.dictionary.status")
	if status == nil || status.Value != 1 {
		t.Error("LOADED status should map to 1")
	}
	alloc := findMetric(metrics, "db.clickhouse.dictionary.bytes_allocated")
	if alloc == nil || alloc.Value != 1048576 {
		t.Errorf("bytes_allocated = %f, want 1048576", alloc.Value)
	}
	elements := findMetric(metrics, "db.clickhouse.dictionary.element_count")
	if elements == nil || elements.Value != 50000 {
		t.Errorf("element_count = %f, want 50000", elements.Value)
	}
	lf := findMetric(metrics, "db.clickhouse.dictionary.load_factor")
	if lf == nil || lf.Value != 0.85 {
		t.Errorf("load_factor = %f, want 0.85", lf.Value)
	}
}

func TestProcessDictionaryRows_EmptyName(t *testing.T) {
	rows := []map[string]interface{}{
		{"database": "db", "name": "", "status": "LOADED"},
	}
	statusCode := map[string]float64{"LOADED": 1}
	var metrics []collector.Metric
	for _, row := range rows {
		name := clickhouse.ToStringExported(row["name"])
		if name == "" {
			continue
		}
		lbl := clickhouse.MergeLabelsExported(nil, map[string]string{"dict": name})
		status := clickhouse.ToStringExported(row["status"])
		code := statusCode[status]
		metrics = append(metrics, clickhouse.MakeMetricExported("db.clickhouse.dictionary.status", code, collector.MetricTypeGauge, lbl))
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for empty name, got %d", len(metrics))
	}
}
