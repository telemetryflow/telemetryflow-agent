// Package nodeexporter provides a prometheus/node_exporter-equivalent collector.
// When enabled, it exposes detailed system metrics (per-CPU, per-device,
// per-interface, per-mount) as continuous time-series that flow through
// OTLP export and the Prometheus /metrics endpoint.
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
package nodeexporter

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/disk"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectDiskIO collects per-device disk I/O counters.
// Equivalent to node_exporter's diskstats collector.
func (c *NodeExporterCollector) collectDiskIO() ([]collector.Metric, error) {
	counters, err := disk.IOCounters()
	if err != nil {
		return nil, fmt.Errorf("disk io counters: %w", err)
	}

	var metrics []collector.Metric

	for device, s := range counters {
		if c.cfg.shouldExcludeDisk(device) {
			continue
		}

		lbl := map[string]string{"device": device}

		metrics = append(metrics,
			collector.NewMetric("node.disk.read_bytes_total", float64(s.ReadBytes), collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("bytes").WithDescription("Total bytes read"),
			collector.NewMetric("node.disk.written_bytes_total", float64(s.WriteBytes), collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("bytes").WithDescription("Total bytes written"),
			collector.NewMetric("node.disk.reads_completed_total", float64(s.ReadCount), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total read operations completed"),
			collector.NewMetric("node.disk.writes_completed_total", float64(s.WriteCount), collector.MetricTypeCounter).
				WithLabels(lbl).WithDescription("Total write operations completed"),
			// ReadTime/WriteTime are in milliseconds
			collector.NewMetric("node.disk.read_time_seconds_total", float64(s.ReadTime)/1000.0, collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("seconds").WithDescription("Total time spent reading"),
			collector.NewMetric("node.disk.write_time_seconds_total", float64(s.WriteTime)/1000.0, collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("seconds").WithDescription("Total time spent writing"),
			collector.NewMetric("node.disk.io_time_seconds_total", float64(s.IoTime)/1000.0, collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("seconds").WithDescription("Total time spent doing I/O"),
			collector.NewMetric("node.disk.io_time_weighted_seconds_total", float64(s.WeightedIO)/1000.0, collector.MetricTypeCounter).
				WithLabels(lbl).WithUnit("seconds").WithDescription("Weighted time spent doing I/O"),
			collector.NewMetric("node.disk.io_now", float64(s.IopsInProgress), collector.MetricTypeGauge).
				WithLabels(lbl).WithDescription("Current I/O operations in progress"),
		)
	}

	return metrics, nil
}
