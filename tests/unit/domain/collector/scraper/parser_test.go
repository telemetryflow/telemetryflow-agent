// Package scraper_test contains unit tests for the corresponding collector module.
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

package scraper_test

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	scraper "github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
)

func TestParsePrometheusText(t *testing.T) {
	input := `# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/"} 100
http_requests_total{method="POST",path="/api"} 50
# HELP temperature_celsius Current temperature
# TYPE temperature_celsius gauge
temperature_celsius{location="server-room"} 22.5
`
	metrics, err := scraper.ParsePrometheusTextExported(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParsePrometheusTextExported failed: %v", err)
	}
	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics, got %d", len(metrics))
	}

	// Verify counter
	counter := findMetricByName(metrics, "http_requests_total")
	if counter == nil {
		t.Fatal("missing http_requests_total")
	}
	if counter.Type != collector.MetricTypeCounter {
		t.Errorf("type = %v, want Counter", counter.Type)
	}

	// Verify gauge
	gauge := findMetricByName(metrics, "temperature_celsius")
	if gauge == nil {
		t.Fatal("missing temperature_celsius")
	}
	if gauge.Type != collector.MetricTypeGauge {
		t.Errorf("type = %v, want Gauge", gauge.Type)
	}
	if gauge.Value != 22.5 {
		t.Errorf("value = %f, want 22.5", gauge.Value)
	}
}

func TestParsePrometheusText_Histogram(t *testing.T) {
	input := `# HELP http_duration_seconds HTTP duration
# TYPE http_duration_seconds histogram
http_duration_seconds_bucket{le="0.1"} 10
http_duration_seconds_bucket{le="0.5"} 25
http_duration_seconds_bucket{le="+Inf"} 30
http_duration_seconds_sum 12.5
http_duration_seconds_count 30
`
	metrics, err := scraper.ParsePrometheusTextExported(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParsePrometheusTextExported failed: %v", err)
	}
	// 3 buckets + _sum + _count = 5
	if len(metrics) != 5 {
		t.Fatalf("expected 5 metrics, got %d", len(metrics))
	}

	bucket := findMetricByName(metrics, "http_duration_seconds_bucket")
	if bucket == nil {
		t.Fatal("missing bucket metric")
	}
	if bucket.Type != collector.MetricTypeHistogram {
		t.Errorf("bucket type = %v, want Histogram", bucket.Type)
	}

	sum := findMetricByName(metrics, "http_duration_seconds_sum")
	if sum == nil {
		t.Fatal("missing _sum metric")
	}
	if sum.Value != 12.5 {
		t.Errorf("sum = %f, want 12.5", sum.Value)
	}

	count := findMetricByName(metrics, "http_duration_seconds_count")
	if count == nil {
		t.Fatal("missing _count metric")
	}
	if count.Value != 30 {
		t.Errorf("count = %f, want 30", count.Value)
	}
}

func TestParsePrometheusText_Summary(t *testing.T) {
	input := `# HELP rpc_duration_seconds RPC duration
# TYPE rpc_duration_seconds summary
rpc_duration_seconds{quantile="0.5"} 0.1
rpc_duration_seconds{quantile="0.9"} 0.5
rpc_duration_seconds_sum 100
rpc_duration_seconds_count 200
`
	metrics, err := scraper.ParsePrometheusTextExported(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParsePrometheusTextExported failed: %v", err)
	}
	// 2 quantiles + _sum + _count = 4
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metrics, got %d", len(metrics))
	}

	quantile := findMetricByNameAndLabel(metrics, "rpc_duration_seconds", "quantile", "0.5")
	if quantile == nil {
		t.Fatal("missing 0.5 quantile")
	}
	if quantile.Type != collector.MetricTypeSummary {
		t.Errorf("quantile type = %v, want Summary", quantile.Type)
	}
}

func TestParsePrometheusText_Empty(t *testing.T) {
	metrics, err := scraper.ParsePrometheusTextExported(strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty input should not error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics, got %d", len(metrics))
	}
}

func TestParsePrometheusText_Invalid(t *testing.T) {
	// The Prometheus text parser is lenient — invalid lines are skipped, no error returned.
	// It returns empty metrics for completely invalid input.
	metrics, err := scraper.ParsePrometheusTextExported(strings.NewReader("not valid prometheus text !!!"))
	if err != nil {
		t.Logf("got error (acceptable): %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics from invalid input, got %d", len(metrics))
	}
}

func TestConvertFamily(t *testing.T) {
	t.Run("counter", func(t *testing.T) {
		family := &dto.MetricFamily{
			Help: strPtr("test counter"),
			Type: dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{
				{
					Counter: &dto.Counter{Value: float64Ptr(42)},
					Label:   []*dto.LabelPair{{Name: strPtr("method"), Value: strPtr("GET")}},
				},
			},
		}
		metrics := scraper.ConvertFamilyExported("test_counter", family)
		if len(metrics) != 1 {
			t.Fatalf("expected 1, got %d", len(metrics))
		}
		if metrics[0].Value != 42 {
			t.Errorf("value = %f, want 42", metrics[0].Value)
		}
		if metrics[0].Labels["method"] != "GET" {
			t.Error("method label missing")
		}
	})

	t.Run("gauge", func(t *testing.T) {
		family := &dto.MetricFamily{
			Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{
				{Gauge: &dto.Gauge{Value: float64Ptr(7.5)}},
			},
		}
		metrics := scraper.ConvertFamilyExported("test_gauge", family)
		if len(metrics) != 1 {
			t.Fatalf("expected 1, got %d", len(metrics))
		}
		if metrics[0].Value != 7.5 {
			t.Errorf("value = %f, want 7.5", metrics[0].Value)
		}
	})

	t.Run("untyped_treated_as_gauge", func(t *testing.T) {
		family := &dto.MetricFamily{
			Type: dto.MetricType_UNTYPED.Enum(),
			Metric: []*dto.Metric{
				{Untyped: &dto.Untyped{Value: float64Ptr(3.14)}},
			},
		}
		metrics := scraper.ConvertFamilyExported("test_untyped", family)
		if len(metrics) != 1 {
			t.Fatalf("expected 1, got %d", len(metrics))
		}
		if metrics[0].Type != collector.MetricTypeGauge {
			t.Error("untyped should be treated as gauge")
		}
	})
}

func TestLabelsToMap(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		m := scraper.LabelsToMapExported(nil)
		if len(m) != 0 {
			t.Errorf("expected empty, got %d", len(m))
		}
	})

	t.Run("multiple", func(t *testing.T) {
		pairs := []*dto.LabelPair{
			{Name: strPtr("job"), Value: strPtr("test")},
			{Name: strPtr("instance"), Value: strPtr("localhost:9090")},
		}
		m := scraper.LabelsToMapExported(pairs)
		if m["job"] != "test" {
			t.Error("job wrong")
		}
		if m["instance"] != "localhost:9090" {
			t.Error("instance wrong")
		}
	})
}

func TestCopyLabels(t *testing.T) {
	original := map[string]string{"a": "1", "b": "2"}
	copied := scraper.CopyLabelsExported(original)

	// Modify copy should not affect original
	copied["a"] = "changed"
	if original["a"] != "1" {
		t.Error("CopyLabelsExported should isolate mutations")
	}
}

func strPtr(s string) *string       { return &s }
func float64Ptr(f float64) *float64 { return &f }

func findMetricByName(metrics []collector.Metric, name string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

func findMetricByNameAndLabel(metrics []collector.Metric, name, labelKey, labelValue string) *collector.Metric {
	for i := range metrics {
		if metrics[i].Name == name && metrics[i].Labels[labelKey] == labelValue {
			return &metrics[i]
		}
	}
	return nil
}
