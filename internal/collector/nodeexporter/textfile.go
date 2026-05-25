// Package nodeexporter provides a prometheus/node_exporter-equivalent collector.
// When enabled, it exposes detailed system metrics (per-CPU, per-device,
// per-interface, per-mount) as continuous time-series that flow through
// OTLP export and the Prometheus /metrics endpoint.
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
package nodeexporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectTextfile reads custom *.prom files from the configured directory
// and parses them into metrics. This is equivalent to node_exporter's
// textfile collector.
//
// File format: standard Prometheus exposition format (one metric per line):
//
//	metric_name{label="value"} 123.45
//	metric_name 42
func (c *NodeExporterCollector) collectTextfile() ([]collector.Metric, error) {
	dir := c.cfg.raw.TextfilePath
	if dir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read textfile dir: %w", err)
	}

	var metrics []collector.Metric

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".prom") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			c.logger.Debug("Failed to read textfile",
				zap.String("file", entry.Name()),
			)
			continue
		}

		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			m, ok := parsePromLine(line)
			if ok {
				metrics = append(metrics, m)
			}
		}
	}

	return metrics, nil
}

// parsePromLine parses a single Prometheus exposition format line.
// Supports: metric_name 42.0
// Supports: metric_name{label="value",label2="value2"} 42.0
func parsePromLine(line string) (collector.Metric, bool) {
	// Split into name+labels and value
	var name string
	var labels map[string]string
	var valueStr string

	if idx := strings.Index(line, "{"); idx >= 0 {
		name = line[:idx]
		endBrace := strings.Index(line, "}")
		if endBrace < 0 {
			return collector.Metric{}, false
		}
		labels = parseLabels(line[idx+1 : endBrace])
		rest := strings.TrimSpace(line[endBrace+1:])
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			return collector.Metric{}, false
		}
		valueStr = parts[0]
	} else {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return collector.Metric{}, false
		}
		name = parts[0]
		valueStr = parts[1]
	}

	value := parsePromFloat(valueStr)
	m := collector.NewMetric(name, value, collector.MetricTypeGauge)
	for k, v := range labels {
		m = m.WithLabel(k, v)
	}
	return m, true
}

// parseLabels parses label pairs from: label="value",label2="value2"
func parseLabels(s string) map[string]string {
	labels := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		eqIdx := strings.Index(pair, "=")
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(pair[:eqIdx])
		val := strings.TrimSpace(pair[eqIdx+1:])
		val = strings.Trim(val, `"`)
		if key != "" {
			labels[key] = val
		}
	}
	return labels
}

// parsePromFloat parses a float64 from a Prometheus value string.
func parsePromFloat(s string) float64 {
	var v float64
	var decimal float64
	var inDecimal bool
	var negative bool
	decimalPlace := 0.1

	for i, c := range s {
		if i == 0 && c == '-' {
			negative = true
			continue
		}
		if c == '.' {
			inDecimal = true
			decimal = 0
			continue
		}
		if c >= '0' && c <= '9' {
			if inDecimal {
				decimal += float64(c-'0') * decimalPlace
				decimalPlace *= 0.1
			} else {
				v = v*10 + float64(c-'0')
			}
		}
	}

	result := v + decimal
	if negative {
		result = -result
	}
	return result
}
