// Package vault_test — targeted tests for the Prometheus-text parser branches
// (type keywords, invalid names, name mapping, histogram/summary type
// inheritance, label escapes) driven end-to-end through Collect against an
// httptest server. Reuses newPromServer / newVaultCollector / findMetric from
// vault_test.go.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package vault_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// parserBranchesProm exercises every metricTypeFor keyword, the invalid-name
// skip, both mapMetricName branches, histogram/summary suffix type-inheritance
// in lookupType, an untyped (default-gauge) sample, and label escapes.
const parserBranchesProm = `
# HELP vault_counter_total a counter
# TYPE vault_counter_total counter
vault_counter_total 10

# TYPE gauge_metric gauge
gauge_metric 3

# TYPE summary_metric summary
summary_metric_sum 100
summary_metric_count 5

# TYPE hist_metric histogram
hist_metric_bucket{le="0.5"} 2
hist_metric_sum 42
hist_metric_count 7

# TYPE weird_metric somethingunknown
weird_metric 1

untyped_metric 9

0invalid_name 123

bad-name-with-dash 7

labeled_metric{a="x",b="line\nbreak",c="quote\"inside",d="back\\slash"} 4
`

func TestParserBranches_AllTypesAndNames(t *testing.T) {
	srv := newPromServer(t, http.StatusOK, parserBranchesProm)
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// metricTypeFor: counter keyword.
	if m, ok := findMetric(ms, "vault.counter_total"); !ok || m.Type != collector.MetricTypeCounter {
		t.Errorf("counter: ok=%v type=%v", ok, m.Type)
	}
	// metricTypeFor: gauge keyword + mapMetricName non-vault prefix branch.
	if m, ok := findMetric(ms, "vault.gauge_metric"); !ok || m.Type != collector.MetricTypeGauge {
		t.Errorf("gauge: ok=%v type=%v", ok, m.Type)
	}
	// lookupType: summary suffix inheritance (_sum/_count inherit summary).
	if m, ok := findMetric(ms, "vault.summary_metric_sum"); !ok || m.Type != collector.MetricTypeSummary {
		t.Errorf("summary_sum: ok=%v type=%v", ok, m.Type)
	}
	// lookupType: histogram suffix inheritance (_bucket inherits histogram).
	if m, ok := findMetric(ms, "vault.hist_metric_bucket"); !ok || m.Type != collector.MetricTypeHistogram {
		t.Errorf("hist_bucket: ok=%v type=%v", ok, m.Type)
	}
	// metricTypeFor default branch (unknown keyword → gauge).
	if m, ok := findMetric(ms, "vault.weird_metric"); !ok || m.Type != collector.MetricTypeGauge {
		t.Errorf("weird: ok=%v type=%v", ok, m.Type)
	}
	// lookupType default branch (no TYPE → gauge).
	if m, ok := findMetric(ms, "vault.untyped_metric"); !ok || m.Type != collector.MetricTypeGauge {
		t.Errorf("untyped: ok=%v type=%v", ok, m.Type)
	}
	// isValidMetricName false → the invalid sample is dropped.
	if _, ok := findMetric(ms, "vault.0invalid_name"); ok {
		t.Error("invalid metric name should have been skipped")
	}
	// parseLabels: escapes decoded; all four labels present.
	m, ok := findMetric(ms, "vault.labeled_metric")
	if !ok {
		t.Fatal("labeled_metric missing")
	}
	if m.Labels["a"] != "x" {
		t.Errorf("label a = %q", m.Labels["a"])
	}
	if m.Labels["b"] != "line\nbreak" {
		t.Errorf("label b (\\n escape) = %q", m.Labels["b"])
	}
	if m.Labels["c"] != "quote\"inside" {
		t.Errorf("label c (\\\" escape) = %q", m.Labels["c"])
	}
	if m.Labels["d"] != "back\\slash" {
		t.Errorf("label d (\\\\ escape) = %q", m.Labels["d"])
	}
}
