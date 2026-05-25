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

// computeEventDeltas extracts the delta computation logic from collectSystemMetrics for testing.
func computeEventDeltas(prevEvents map[string]float64, eventRows []map[string]interface{}) (metrics []collector.Metric, newEvents map[string]float64) {
	newEvents = make(map[string]float64, len(eventRows))
	for _, row := range eventRows {
		name := clickhouse.ToStringExported(row["event"])
		if name == "" {
			continue
		}
		val, err := clickhouse.ToFloat64Exported(row["value"])
		if err != nil {
			continue
		}
		newEvents[name] = val

		delta := val
		if prev, ok := prevEvents[name]; ok {
			delta = val - prev
			if delta < 0 {
				delta = val
			}
		}
		metrics = append(metrics, clickhouse.MakeMetricExported(
			"db.clickhouse.events."+name,
			delta,
			collector.MetricTypeCounter,
			nil,
		))
	}
	return metrics, newEvents
}

func TestEventDeltas_FirstCollection(t *testing.T) {
	rows := []map[string]interface{}{
		{"event": "Query", "value": "100"},
		{"event": "Select", "value": "50"},
	}
	metrics, newEvents := computeEventDeltas(nil, rows)

	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
	if metrics[0].Value != 100 {
		t.Errorf("first collection delta = %f, want 100", metrics[0].Value)
	}
	if newEvents["Query"] != 100 {
		t.Errorf("newEvents[Query] = %f, want 100", newEvents["Query"])
	}
}

func TestEventDeltas_NormalIncrease(t *testing.T) {
	prev := map[string]float64{"Query": 100, "Insert": 50}
	rows := []map[string]interface{}{
		{"event": "Query", "value": "250"},
		{"event": "Insert", "value": "120"},
	}
	metrics, _ := computeEventDeltas(prev, rows)

	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
	query := findMetric(metrics, "db.clickhouse.events.Query")
	if query == nil || query.Value != 150 {
		t.Errorf("Query delta = %f, want 150", query.Value)
	}
	insert := findMetric(metrics, "db.clickhouse.events.Insert")
	if insert == nil || insert.Value != 70 {
		t.Errorf("Insert delta = %f, want 70", insert.Value)
	}
}

func TestEventDeltas_CounterReset(t *testing.T) {
	prev := map[string]float64{"Query": 9000}
	rows := []map[string]interface{}{
		{"event": "Query", "value": "500"},
	}
	metrics, _ := computeEventDeltas(prev, rows)

	query := findMetric(metrics, "db.clickhouse.events.Query")
	if query == nil {
		t.Fatal("expected Query metric")
	}
	if query.Value != 500 {
		t.Errorf("counter reset: delta = %f, want 500 (use current val)", query.Value)
	}
}

func TestEventDeltas_NewEvent(t *testing.T) {
	prev := map[string]float64{"Query": 100}
	rows := []map[string]interface{}{
		{"event": "Query", "value": "200"},
		{"event": "NewEvent", "value": "42"},
	}
	metrics, newEvents := computeEventDeltas(prev, rows)

	newEvt := findMetric(metrics, "db.clickhouse.events.NewEvent")
	if newEvt == nil || newEvt.Value != 42 {
		t.Errorf("new event delta = %f, want 42", newEvt.Value)
	}
	if newEvents["NewEvent"] != 42 {
		t.Errorf("newEvents[NewEvent] = %f, want 42", newEvents["NewEvent"])
	}
}

func TestEventDeltas_EmptyRows(t *testing.T) {
	metrics, newEvents := computeEventDeltas(nil, nil)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
	if len(newEvents) != 0 {
		t.Errorf("expected 0 new events, got %d", len(newEvents))
	}
}
