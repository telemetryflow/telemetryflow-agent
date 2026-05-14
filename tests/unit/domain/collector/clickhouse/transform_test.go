// Package clickhouse_test contains unit tests for the corresponding collector module.
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

package clickhouse_test

import (
	"math"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	clickhouse "github.com/telemetryflow/telemetryflow-agent/internal/collector/clickhouse"
)

func findMetric(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

func TestMakeMetric(t *testing.T) {
	labels := map[string]string{"host": "ch1", "db": "mydb"}
	m := clickhouse.MakeMetricExported("test.metric", 42.5, collector.MetricTypeGauge, labels)

	if m.Name != "test.metric" {
		t.Errorf("Name = %q, want test.metric", m.Name)
	}
	if m.Value != 42.5 {
		t.Errorf("Value = %f, want 42.5", m.Value)
	}
	if m.Type != collector.MetricTypeGauge {
		t.Errorf("Type = %v, want gauge", m.Type)
	}
	if m.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if m.Labels["host"] != "ch1" {
		t.Error("Labels not copied correctly")
	}
}

func TestMakeMetric_LabelsIsolated(t *testing.T) {
	labels := map[string]string{"key": "val"}
	m := clickhouse.MakeMetricExported("m", 1, collector.MetricTypeGauge, labels)
	m.Labels["extra"] = "added"
	if labels["extra"] != "" {
		t.Error("mutating metric labels should not affect original map")
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		expect  float64
		wantErr bool
	}{
		{"nil", nil, 0, false},
		{"float64", float64(3.14), 3.14, false},
		{"float32", float32(1.5), 1.5, false},
		{"int", int(42), 42, false},
		{"int64", int64(100), 100, false},
		{"uint64", uint64(200), 200, false},
		{"string_number", "3.14", 3.14, false},
		{"string_empty", "", 0, false},
		{"string_invalid", "abc", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := clickhouse.ToFloat64Exported(tc.input)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if math.Abs(got-tc.expect) > 1e-9 {
				t.Errorf("toFloat64(%v) = %f, want %f", tc.input, got, tc.expect)
			}
		})
	}
}

func TestToString(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		expect string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"int", int(42), "42"},
		{"float64", float64(1.5), "1.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clickhouse.ToStringExported(tc.input)
			if got != tc.expect {
				t.Errorf("toString(%v) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

func TestMergeLabels(t *testing.T) {
	t.Run("nil_both", func(t *testing.T) {
		result := clickhouse.MergeLabelsExported(nil, nil)
		if len(result) != 0 {
			t.Errorf("expected empty map, got %d entries", len(result))
		}
	})
	t.Run("nil_base", func(t *testing.T) {
		extra := map[string]string{"a": "1"}
		result := clickhouse.MergeLabelsExported(nil, extra)
		if result["a"] != "1" {
			t.Error("extra key missing")
		}
	})
	t.Run("nil_extra", func(t *testing.T) {
		base := map[string]string{"a": "1"}
		result := clickhouse.MergeLabelsExported(base, nil)
		if result["a"] != "1" {
			t.Error("base key missing")
		}
	})
	t.Run("overlap_extra_wins", func(t *testing.T) {
		base := map[string]string{"a": "base", "b": "base"}
		extra := map[string]string{"b": "extra", "c": "extra"}
		result := clickhouse.MergeLabelsExported(base, extra)
		if result["a"] != "base" {
			t.Error("base key wrong")
		}
		if result["b"] != "extra" {
			t.Errorf("overlap: got %q, want extra", result["b"])
		}
		if result["c"] != "extra" {
			t.Error("extra key missing")
		}
	})
}

func TestFindMetric(t *testing.T) {
	metrics := []collector.Metric{
		{Name: "a", Value: 1},
		{Name: "b", Value: 2},
	}
	if m := findMetric(metrics, "b"); m == nil || m.Value != 2 {
		t.Error("findMetric failed to find b")
	}
	if m := findMetric(metrics, "c"); m != nil {
		t.Error("findMetric should return nil for missing metric")
	}
}
