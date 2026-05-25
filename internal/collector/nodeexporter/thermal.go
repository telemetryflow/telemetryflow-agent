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
	"github.com/shirou/gopsutil/v3/host"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectThermal collects hardware temperature metrics.
// Equivalent to node_exporter's hwmon/thermal_zone collector.
func (c *NodeExporterCollector) collectThermal() ([]collector.Metric, error) {
	temps, err := host.SensorsTemperatures()
	if err != nil {
		// Sensors not available on all platforms — return empty, not error
		return nil, nil
	}

	var metrics []collector.Metric
	for _, t := range temps {
		if t.Temperature == 0 {
			continue
		}
		metrics = append(metrics, collector.NewMetric(
			"node.thermal.temperature_celsius", t.Temperature, collector.MetricTypeGauge,
		).WithLabel("sensor", t.SensorKey).
			WithUnit("celsius").
			WithDescription("Hardware temperature in Celsius"))
	}

	return metrics, nil
}
