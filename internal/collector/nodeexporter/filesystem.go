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

	"github.com/shirou/gopsutil/v3/disk"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectFilesystem collects per-mountpoint filesystem metrics.
// Equivalent to node_exporter's filesystem collector.
func (c *NodeExporterCollector) collectFilesystem() ([]collector.Metric, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil, fmt.Errorf("disk partitions: %w", err)
	}

	var metrics []collector.Metric

	for _, p := range partitions {
		if c.cfg.shouldExcludeMount(p.Mountpoint) {
			continue
		}
		if c.cfg.shouldExcludeFSType(p.Fstype) {
			continue
		}

		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}

		lbl := map[string]string{
			"device":     p.Device,
			"mountpoint": p.Mountpoint,
			"fstype":     p.Fstype,
		}

		metrics = append(metrics,
			collector.NewMetric("node.filesystem.size_bytes", float64(usage.Total), collector.MetricTypeGauge).
				WithLabels(lbl).WithUnit("bytes").WithDescription("Filesystem size in bytes"),
			collector.NewMetric("node.filesystem.free_bytes", float64(usage.Free), collector.MetricTypeGauge).
				WithLabels(lbl).WithUnit("bytes").WithDescription("Filesystem free space in bytes"),
			collector.NewMetric("node.filesystem.avail_bytes", float64(usage.Free), collector.MetricTypeGauge).
				WithLabels(lbl).WithUnit("bytes").WithDescription("Filesystem available space in bytes"),
			collector.NewMetric("node.filesystem.files", float64(usage.InodesTotal), collector.MetricTypeGauge).
				WithLabels(lbl).WithDescription("Total number of inodes"),
			collector.NewMetric("node.filesystem.files_free", float64(usage.InodesFree), collector.MetricTypeGauge).
				WithLabels(lbl).WithDescription("Number of free inodes"),
		)
	}

	return metrics, nil
}
