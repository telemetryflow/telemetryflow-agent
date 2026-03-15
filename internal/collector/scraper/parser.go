// Package scraper implements a Prometheus pull-based scraper that periodically
// fetches metrics from configured HTTP targets, parses Prometheus text-format
// exposition, and applies relabeling rules before forwarding to exporters.
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
package scraper

import (
	"fmt"
	"io"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// parsePrometheusText parses Prometheus text format from r and returns a flat
// slice of collector.Metric values.
//
// Type mapping:
//
//	COUNTER  → MetricTypeCounter   (value = Counter.Value)
//	GAUGE    → MetricTypeGauge     (value = Gauge.Value)
//	UNTYPED  → MetricTypeGauge     (treated as gauge)
//	HISTOGRAM→ MetricTypeHistogram (one metric per bucket + _sum + _count)
//	SUMMARY  → MetricTypeSummary   (one metric per quantile + _sum + _count)
func parsePrometheusText(r io.Reader) ([]collector.Metric, error) {
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(r)
	if err != nil {
		// TextToMetricFamilies returns a partial result alongside the error;
		// we still process whatever was parsed successfully.
		if len(families) == 0 {
			return nil, fmt.Errorf("scraper: parse prometheus text: %w", err)
		}
	}

	var metrics []collector.Metric
	for name, family := range families {
		metrics = append(metrics, convertFamily(name, family)...)
	}
	return metrics, nil
}

// convertFamily converts a single MetricFamily to []collector.Metric.
func convertFamily(name string, family *dto.MetricFamily) []collector.Metric {
	help := family.GetHelp()
	var metrics []collector.Metric

	for _, m := range family.GetMetric() {
		labels := labelsToMap(m.GetLabel())

		switch family.GetType() {
		case dto.MetricType_COUNTER:
			if m.Counter != nil {
				metrics = append(metrics, collector.NewMetric(
					name, m.Counter.GetValue(), collector.MetricTypeCounter,
				).WithLabels(labels).WithDescription(help))
			}

		case dto.MetricType_GAUGE:
			if m.Gauge != nil {
				metrics = append(metrics, collector.NewMetric(
					name, m.Gauge.GetValue(), collector.MetricTypeGauge,
				).WithLabels(labels).WithDescription(help))
			}

		case dto.MetricType_UNTYPED:
			if m.Untyped != nil {
				metrics = append(metrics, collector.NewMetric(
					name, m.Untyped.GetValue(), collector.MetricTypeGauge,
				).WithLabels(labels).WithDescription(help))
			}

		case dto.MetricType_HISTOGRAM:
			if m.Histogram != nil {
				h := m.Histogram
				// One metric per bucket with "le" label
				for _, bucket := range h.GetBucket() {
					bLabels := copyLabels(labels)
					bLabels["le"] = fmt.Sprintf("%g", bucket.GetUpperBound())
					metrics = append(metrics, collector.NewMetric(
						name+"_bucket", float64(bucket.GetCumulativeCount()), collector.MetricTypeHistogram,
					).WithLabels(bLabels).WithDescription(help))
				}
				// _sum and _count
				metrics = append(metrics,
					collector.NewMetric(name+"_sum", h.GetSampleSum(), collector.MetricTypeHistogram).
						WithLabels(labels).WithDescription(help),
					collector.NewMetric(name+"_count", float64(h.GetSampleCount()), collector.MetricTypeHistogram).
						WithLabels(labels).WithDescription(help),
				)
			}

		case dto.MetricType_SUMMARY:
			if m.Summary != nil {
				s := m.Summary
				// One metric per quantile with "quantile" label
				for _, q := range s.GetQuantile() {
					qLabels := copyLabels(labels)
					qLabels["quantile"] = fmt.Sprintf("%g", q.GetQuantile())
					metrics = append(metrics, collector.NewMetric(
						name, q.GetValue(), collector.MetricTypeSummary,
					).WithLabels(qLabels).WithDescription(help))
				}
				// _sum and _count
				metrics = append(metrics,
					collector.NewMetric(name+"_sum", s.GetSampleSum(), collector.MetricTypeSummary).
						WithLabels(labels).WithDescription(help),
					collector.NewMetric(name+"_count", float64(s.GetSampleCount()), collector.MetricTypeSummary).
						WithLabels(labels).WithDescription(help),
				)
			}
		}
	}

	return metrics
}

// labelsToMap converts a slice of Prometheus LabelPair to a map[string]string.
func labelsToMap(pairs []*dto.LabelPair) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, lp := range pairs {
		m[lp.GetName()] = lp.GetValue()
	}
	return m
}

// copyLabels returns a shallow copy of the given label map.
func copyLabels(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src)+1)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
