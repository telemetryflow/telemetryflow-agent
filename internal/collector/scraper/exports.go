// Package scraper exports internal functions for testing.
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
	"io"

	dto "github.com/prometheus/client_model/go"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// ParsePrometheusTextExported exposes parsePrometheusText for testing.
func ParsePrometheusTextExported(r io.Reader) ([]collector.Metric, error) {
	return parsePrometheusText(r)
}

// ConvertFamilyExported exposes convertFamily for testing.
func ConvertFamilyExported(name string, family *dto.MetricFamily) []collector.Metric {
	return convertFamily(name, family)
}

// LabelsToMapExported exposes labelsToMap for testing.
func LabelsToMapExported(pairs []*dto.LabelPair) map[string]string {
	return labelsToMap(pairs)
}

// CopyLabelsExported exposes copyLabels for testing.
func CopyLabelsExported(src map[string]string) map[string]string {
	return copyLabels(src)
}

// ApplyRelabelRulesExported exposes applyRelabelRules for testing.
func ApplyRelabelRulesExported(metrics []collector.Metric, rules []RelabelConfig) []collector.Metric {
	return applyRelabelRules(metrics, rules)
}

// BuildSourceValueExported exposes buildSourceValue for testing.
func BuildSourceValueExported(m collector.Metric, sourceLabels []string) string {
	return buildSourceValue(m, sourceLabels)
}

// BuildScrapeURLExported exposes buildScrapeURL for testing.
func BuildScrapeURLExported(target, scrapePath string) string {
	return buildScrapeURL(target, scrapePath)
}
