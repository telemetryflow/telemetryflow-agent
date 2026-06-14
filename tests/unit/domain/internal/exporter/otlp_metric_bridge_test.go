// Package exporter_test contains unit tests for the corresponding collector module.
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

package exporter_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

func TestLabelsToAttributeSet(t *testing.T) {
	labels := map[string]string{
		"host":   "db1.example.com",
		"port":   "5432",
		"dbname": "mydb",
	}
	set := exporter.LabelsToAttributeSetExported(labels)

	for k, v := range labels {
		val, ok := set.Value(attribute.Key(k))
		if !ok {
			t.Errorf("missing attribute %q", k)
		}
		if val.AsString() != v {
			t.Errorf("attribute %q = %q, want %q", k, val.AsString(), v)
		}
	}
}

func TestLabelsToAttributeSetEmpty(t *testing.T) {
	set := exporter.LabelsToAttributeSetExported(nil)
	if set.Len() != 0 {
		t.Errorf("expected empty set, got %d attributes", set.Len())
	}
}

func TestGroupMetricsByName(t *testing.T) {
	metrics := []collector.Metric{
		collector.NewMetric("db.postgresql.connections.active", 10.0, collector.MetricTypeGauge).WithLabel("state", "active"),
		collector.NewMetric("db.postgresql.connections.idle", 5.0, collector.MetricTypeGauge).WithLabel("state", "idle"),
		collector.NewMetric("db.postgresql.connections.active", 12.0, collector.MetricTypeGauge).WithLabel("state", "active"),
	}

	groups := exporter.GroupMetricsByNameExported(metrics)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if len(groups["db.postgresql.connections.active"]) != 2 {
		t.Errorf("expected 2 active connection points, got %d", len(groups["db.postgresql.connections.active"]))
	}
	if len(groups["db.postgresql.connections.idle"]) != 1 {
		t.Errorf("expected 1 idle connection point, got %d", len(groups["db.postgresql.connections.idle"]))
	}
}

func TestBuildAggregationGauge(t *testing.T) {
	now := time.Now()
	points := []exporter.MetricPointExported{
		{
			M:     collector.Metric{Name: "test.gauge", Type: collector.MetricTypeGauge, Value: 42.0, Timestamp: now},
			Attrs: attribute.NewSet(attribute.String("host", "a")),
		},
		{
			M:     collector.Metric{Name: "test.gauge", Type: collector.MetricTypeGauge, Value: 99.0, Timestamp: now},
			Attrs: attribute.NewSet(attribute.String("host", "b")),
		},
	}

	agg := exporter.BuildAggregationExported(points)
	gauge, ok := agg.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("expected Gauge, got %T", agg)
	}
	if len(gauge.DataPoints) != 2 {
		t.Fatalf("expected 2 data points, got %d", len(gauge.DataPoints))
	}
	if gauge.DataPoints[0].Value != 42.0 {
		t.Errorf("dp[0] value = %f, want 42.0", gauge.DataPoints[0].Value)
	}
	if gauge.DataPoints[1].Value != 99.0 {
		t.Errorf("dp[1] value = %f, want 99.0", gauge.DataPoints[1].Value)
	}
}

func TestBuildAggregationCounter(t *testing.T) {
	now := time.Now()
	points := []exporter.MetricPointExported{
		{
			M:     collector.Metric{Name: "test.counter", Type: collector.MetricTypeCounter, Value: 100.0, Timestamp: now},
			Attrs: attribute.NewSet(attribute.String("host", "a")),
		},
	}

	agg := exporter.BuildAggregationExported(points)
	sum, ok := agg.(metricdata.Sum[float64])
	if !ok {
		t.Fatalf("expected Sum, got %T", agg)
	}
	if !sum.IsMonotonic {
		t.Error("expected monotonic sum")
	}
	if sum.Temporality != metricdata.CumulativeTemporality {
		t.Errorf("expected cumulative temporality, got %v", sum.Temporality)
	}
	if len(sum.DataPoints) != 1 {
		t.Fatalf("expected 1 data point, got %d", len(sum.DataPoints))
	}
	if sum.DataPoints[0].Value != 100.0 {
		t.Errorf("value = %f, want 100.0", sum.DataPoints[0].Value)
	}
}

func TestBuildAggregationEmpty(t *testing.T) {
	agg := exporter.BuildAggregationExported(nil)
	if _, ok := agg.(metricdata.Gauge[float64]); !ok {
		t.Errorf("expected Gauge for empty input, got %T", agg)
	}
}

func TestBaseResourceAttrs(t *testing.T) {
	attrs := exporter.BaseResourceAttrsExported()
	found := false
	for _, a := range attrs {
		if string(a.Key) == "service.name" && a.Value.AsString() == "telemetryflow-agent" {
			found = true
		}
	}
	if !found {
		t.Error("expected service.name=telemetryflow-agent in base resource attrs")
	}
}

func TestOTLPMetricBridgeExportEmpty(t *testing.T) {
	bridge := &exporter.OTLPMetricBridge{}
	if err := bridge.Export(context.Background(), nil, nil); err != nil {
		t.Errorf("expected no error for empty export, got %v", err)
	}
	if err := bridge.Export(context.Background(), []collector.Metric{}, nil); err != nil {
		t.Errorf("expected no error for empty slice, got %v", err)
	}
}

func TestNewOTLPMetricBridgeInvalidEndpoint(t *testing.T) {
	_, err := exporter.NewOTLPMetricBridge(context.Background(), exporter.OTLPMetricBridgeConfig{
		Endpoint: "://invalid",
	})
	if err == nil {
		t.Error("expected error for invalid endpoint")
	}
}
