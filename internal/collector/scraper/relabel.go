// Package scraper implements a Prometheus pull-based scraper that periodically
// fetches metrics from configured HTTP targets, parses Prometheus text-format
// exposition, and applies relabeling rules before forwarding to exporters.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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
	"regexp"
	"strings"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// applyRelabelRules applies a sequence of relabeling rules to a slice of metrics,
// implementing a subset of Prometheus metric_relabel_configs semantics.
//
// Supported actions:
//   - drop:    remove the metric if the regex matches the source value
//   - keep:    remove the metric if the regex does NOT match the source value
//   - replace: if the regex matches, set TargetLabel to Replacement (with $1 substitution)
func applyRelabelRules(metrics []collector.Metric, rules []RelabelConfig) []collector.Metric {
	if len(rules) == 0 {
		return metrics
	}

	result := make([]collector.Metric, 0, len(metrics))

	for _, m := range metrics {
		keep := true

		for _, rule := range rules {
			// Build source value by joining SourceLabels values with ";"
			sourceValue := buildSourceValue(m, rule.SourceLabels)

			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				// Skip rules with invalid regex
				continue
			}

			matched := re.MatchString(sourceValue)

			switch strings.ToLower(rule.Action) {
			case "drop":
				if matched {
					keep = false
				}
			case "keep":
				if !matched {
					keep = false
				}
			case "replace":
				if matched {
					replacement := re.ReplaceAllString(sourceValue, rule.Replacement)
					if m.Labels == nil {
						m.Labels = make(map[string]string)
					}
					m.Labels[rule.TargetLabel] = replacement
				}
			}

			if !keep {
				break
			}
		}

		if keep {
			result = append(result, m)
		}
	}

	return result
}

// buildSourceValue concatenates the values of the given label keys from the metric,
// joined by ";", matching Prometheus relabeling semantics.
func buildSourceValue(m collector.Metric, sourceLabels []string) string {
	if len(sourceLabels) == 0 {
		return ""
	}

	parts := make([]string, 0, len(sourceLabels))
	for _, label := range sourceLabels {
		parts = append(parts, m.Labels[label])
	}

	return strings.Join(parts, ";")
}
