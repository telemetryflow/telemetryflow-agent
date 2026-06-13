package fsm

import (
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func TestNewMetric(t *testing.T) {
	m := collector.NewMetric("cpu.usage", 42.5, collector.MetricTypeGauge)
	if m.Name != "cpu.usage" {
		t.Fatalf("expected 'cpu.usage', got %s", m.Name)
	}
	if m.Value != 42.5 {
		t.Fatalf("expected 42.5, got %f", m.Value)
	}
	if m.Type != collector.MetricTypeGauge {
		t.Fatalf("expected gauge, got %s", m.Type)
	}
	if m.Timestamp.IsZero() {
		t.Fatal("expected non-zero timestamp")
	}
	if m.Labels == nil {
		t.Fatal("expected non-nil labels map")
	}
}

func TestMetric_WithLabels(t *testing.T) {
	m := collector.NewMetric("test", 1.0, collector.MetricTypeCounter)
	m = m.WithLabels(map[string]string{"host": "a", "dc": "us"})
	if m.Labels["host"] != "a" || m.Labels["dc"] != "us" {
		t.Fatalf("expected labels to be set, got %v", m.Labels)
	}
}

func TestMetric_WithLabel(t *testing.T) {
	m := collector.NewMetric("test", 1.0, collector.MetricTypeCounter)
	m = m.WithLabel("env", "prod")
	if m.Labels["env"] != "prod" {
		t.Fatalf("expected env=prod, got %v", m.Labels)
	}
}

func TestMetric_WithLabel_NilLabels(t *testing.T) {
	m := collector.Metric{Name: "test"}
	m = m.WithLabel("key", "val")
	if m.Labels["key"] != "val" {
		t.Fatalf("expected key=val on nil labels, got %v", m.Labels)
	}
}

func TestMetric_WithUnit(t *testing.T) {
	m := collector.NewMetric("test", 1.0, collector.MetricTypeGauge)
	m = m.WithUnit("bytes")
	if m.Unit != "bytes" {
		t.Fatalf("expected 'bytes', got %s", m.Unit)
	}
}

func TestMetric_WithDescription(t *testing.T) {
	m := collector.NewMetric("test", 1.0, collector.MetricTypeGauge)
	m = m.WithDescription("CPU usage percent")
	if m.Description != "CPU usage percent" {
		t.Fatalf("expected description, got %s", m.Description)
	}
}

func TestMetricType_Values(t *testing.T) {
	types := []collector.MetricType{
		collector.MetricTypeGauge,
		collector.MetricTypeCounter,
		collector.MetricTypeHistogram,
		collector.MetricTypeSummary,
	}
	expected := []string{"gauge", "counter", "histogram", "summary"}
	for i, mt := range types {
		if string(mt) != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], mt)
		}
	}
}
