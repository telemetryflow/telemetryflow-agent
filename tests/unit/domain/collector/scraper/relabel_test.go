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
	"testing"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	scraper "github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
)

func TestBuildSourceValue(t *testing.T) {
	m := collector.Metric{
		Name: "test",
		Labels: map[string]string{
			"job":      "myjob",
			"instance": "localhost:9090",
		},
	}

	tests := []struct {
		name         string
		sourceLabels []string
		expect       string
	}{
		{"empty", nil, ""},
		{"single", []string{"job"}, "myjob"},
		{"multiple", []string{"job", "instance"}, "myjob;localhost:9090"},
		{"missing_label", []string{"job", "missing"}, "myjob;"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scraper.BuildSourceValueExported(m, tc.sourceLabels)
			if got != tc.expect {
				t.Errorf("BuildSourceValueExported() = %q, want %q", got, tc.expect)
			}
		})
	}
}

func TestApplyRelabelRules(t *testing.T) {
	metrics := []collector.Metric{
		{Name: "metric_a", Labels: map[string]string{"env": "prod", "team": "backend"}},
		{Name: "metric_b", Labels: map[string]string{"env": "staging", "team": "frontend"}},
		{Name: "metric_c", Labels: map[string]string{"env": "prod", "team": "frontend"}},
	}

	t.Run("empty_rules", func(t *testing.T) {
		result := scraper.ApplyRelabelRulesExported(metrics, nil)
		if len(result) != 3 {
			t.Errorf("expected 3, got %d", len(result))
		}
	})

	t.Run("drop_matching", func(t *testing.T) {
		rules := []scraper.RelabelConfig{
			{SourceLabels: []string{"env"}, Regex: "staging", Action: "drop"},
		}
		result := scraper.ApplyRelabelRulesExported(metrics, rules)
		if len(result) != 2 {
			t.Errorf("expected 2 (staging dropped), got %d", len(result))
		}
		for _, m := range result {
			if m.Labels["env"] == "staging" {
				t.Error("staging metric should have been dropped")
			}
		}
	})

	t.Run("keep_matching", func(t *testing.T) {
		rules := []scraper.RelabelConfig{
			{SourceLabels: []string{"env"}, Regex: "prod", Action: "keep"},
		}
		result := scraper.ApplyRelabelRulesExported(metrics, rules)
		if len(result) != 2 {
			t.Errorf("expected 2 (only prod kept), got %d", len(result))
		}
	})

	t.Run("replace_label", func(t *testing.T) {
		input := []collector.Metric{
			{Name: "test", Labels: map[string]string{"host": "web-01"}},
		}
		rules := []scraper.RelabelConfig{
			{
				SourceLabels: []string{"host"},
				Regex:        "web-(.*)",
				Replacement:  "app-$1",
				TargetLabel:  "host_normalized",
				Action:       "replace",
			},
		}
		result := scraper.ApplyRelabelRulesExported(input, rules)
		if len(result) != 1 {
			t.Fatalf("expected 1, got %d", len(result))
		}
		if result[0].Labels["host_normalized"] != "app-01" {
			t.Errorf("host_normalized = %q, want app-01", result[0].Labels["host_normalized"])
		}
	})

	t.Run("invalid_regex_skipped", func(t *testing.T) {
		rules := []scraper.RelabelConfig{
			{SourceLabels: []string{"env"}, Regex: "[invalid", Action: "drop"},
		}
		result := scraper.ApplyRelabelRulesExported(metrics, rules)
		if len(result) != 3 {
			t.Errorf("invalid regex should be skipped, expected 3, got %d", len(result))
		}
	})

	t.Run("multiple_rules", func(t *testing.T) {
		rules := []scraper.RelabelConfig{
			{SourceLabels: []string{"env"}, Regex: "staging", Action: "drop"},
			{SourceLabels: []string{"team"}, Regex: "frontend", Action: "drop"},
		}
		result := scraper.ApplyRelabelRulesExported(metrics, rules)
		if len(result) != 1 {
			t.Errorf("expected 1 (only prod+backend), got %d", len(result))
		}
		if result[0].Name != "metric_a" {
			t.Errorf("expected metric_a, got %q", result[0].Name)
		}
	})
}
