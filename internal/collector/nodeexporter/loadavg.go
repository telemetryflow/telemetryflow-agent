// Package nodeexporter provides a prometheus/node_exporter-equivalent collector.
// When enabled, it exposes detailed system metrics (per-CPU, per-device,
// per-interface, per-mount) as continuous time-series that flow through
// OTLP export and the Prometheus /metrics endpoint.
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
package nodeexporter

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/load"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectLoadAvg collects load average metrics.
// Equivalent to node_exporter's loadavg collector.
func (c *NodeExporterCollector) collectLoadAvg() ([]collector.Metric, error) {
	avg, err := load.Avg()
	if err != nil {
		return nil, fmt.Errorf("load avg: %w", err)
	}

	return []collector.Metric{
		collector.NewMetric("node.load1", avg.Load1, collector.MetricTypeGauge).
			WithDescription("1-minute load average"),
		collector.NewMetric("node.load5", avg.Load5, collector.MetricTypeGauge).
			WithDescription("5-minute load average"),
		collector.NewMetric("node.load15", avg.Load15, collector.MetricTypeGauge).
			WithDescription("15-minute load average"),
	}, nil
}
