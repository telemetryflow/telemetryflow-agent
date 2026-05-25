// Package cadvisor_test contains unit tests for the corresponding collector module.
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

package cadvisor_test

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cadvisor"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestShouldIncludeMetric(t *testing.T) {
	tests := []struct {
		name     string
		metric   string
		cfgNames []string
		expect   bool
	}{
		{"container_prefix_default", "container_cpu_usage_seconds_total", nil, true},
		{"machine_prefix_default", "machine_memory_bytes", nil, true},
		{"no_match_default", "go_goroutines", nil, false},
		{"explicit_match", "container_cpu", []string{"container_cpu", "custom_metric"}, true},
		{"explicit_no_match", "container_cpu", []string{"other_metric"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &cadvisor.CAdvisorCollector{}
			c.SetConfig(config.CAdvisorCollectorConfig{MetricNames: tc.cfgNames})
			got := c.ShouldIncludeMetricExported(tc.metric)
			if got != tc.expect {
				t.Errorf("ShouldIncludeMetric(%q) = %v, want %v", tc.metric, got, tc.expect)
			}
		})
	}
}

func TestPromLabelsToMap(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		m := cadvisor.PromLabelsToMapExported(nil)
		if len(m) != 0 {
			t.Errorf("expected empty map, got %d", len(m))
		}
	})
	t.Run("multiple_pairs", func(t *testing.T) {
		pairs := []*dto.LabelPair{
			{Name: strPtr("container"), Value: strPtr("web")},
			{Name: strPtr("image"), Value: strPtr("nginx:latest")},
		}
		m := cadvisor.PromLabelsToMapExported(pairs)
		if m["container"] != "web" {
			t.Error("container label wrong")
		}
		if m["image"] != "nginx:latest" {
			t.Error("image label wrong")
		}
	})
}

func TestParsePrometheusText(t *testing.T) {
	input := `# HELP test_gauge A test gauge
# TYPE test_gauge gauge
test_gauge{label="value"} 42.0
# HELP test_counter A test counter
# TYPE test_counter counter
test_counter{method="get"} 100
`
	families, err := cadvisor.ParsePrometheusTextExported(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParsePrometheusText failed: %v", err)
	}
	if _, ok := families["test_gauge"]; !ok {
		t.Error("test_gauge family not found")
	}
	if _, ok := families["test_counter"]; !ok {
		t.Error("test_counter family not found")
	}
	gauge := families["test_gauge"]
	if gauge.GetType() != dto.MetricType_GAUGE {
		t.Error("test_gauge should be GAUGE type")
	}
	counter := families["test_counter"]
	if counter.GetType() != dto.MetricType_COUNTER {
		t.Error("test_counter should be COUNTER type")
	}
}

func TestConvertFamilies_Gauge(t *testing.T) {
	c := &cadvisor.CAdvisorCollector{}
	c.SetConfig(config.CAdvisorCollectorConfig{})
	c.SetLogger(zap.NewNop())

	families := map[string]*dto.MetricFamily{
		"container_cpu": {
			Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{
				{
					Gauge: &dto.Gauge{Value: float64Ptr(42.5)},
					Label: []*dto.LabelPair{
						{Name: strPtr("cpu"), Value: strPtr("cpu0")},
					},
				},
			},
		},
	}
	metrics := c.ConvertFamiliesExported(families)
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].Name != "container_cpu" {
		t.Errorf("name = %q, want container_cpu", metrics[0].Name)
	}
	if metrics[0].Value != 42.5 {
		t.Errorf("value = %f, want 42.5", metrics[0].Value)
	}
	if metrics[0].Labels["cpu"] != "cpu0" {
		t.Error("cpu label missing")
	}
}

func TestConvertFamilies_Counter(t *testing.T) {
	c := &cadvisor.CAdvisorCollector{}
	c.SetConfig(config.CAdvisorCollectorConfig{})
	c.SetLogger(zap.NewNop())

	families := map[string]*dto.MetricFamily{
		"container_cpu_total": {
			Type: dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{
				{Counter: &dto.Counter{Value: float64Ptr(100)}},
			},
		},
	}
	metrics := c.ConvertFamiliesExported(families)
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].Value != 100 {
		t.Errorf("value = %f, want 100", metrics[0].Value)
	}
}

func TestConvertFamilies_Filtered(t *testing.T) {
	c := &cadvisor.CAdvisorCollector{}
	c.SetConfig(config.CAdvisorCollectorConfig{})
	c.SetLogger(zap.NewNop())

	families := map[string]*dto.MetricFamily{
		"container_cpu": {Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: float64Ptr(1)}}}},
		"go_goroutines": {Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: float64Ptr(2)}}}},
	}
	metrics := c.ConvertFamiliesExported(families)
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric (go_goroutines filtered), got %d", len(metrics))
	}
	if len(metrics) > 0 && metrics[0].Name != "container_cpu" {
		t.Errorf("expected container_cpu, got %q", metrics[0].Name)
	}
}

func strPtr(s string) *string       { return &s }
func float64Ptr(f float64) *float64 { return &f }
