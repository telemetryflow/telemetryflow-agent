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

	"github.com/shirou/gopsutil/v3/mem"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectMemory collects detailed memory and swap metrics.
// Equivalent to node_exporter's meminfo collector.
func (c *NodeExporterCollector) collectMemory() ([]collector.Metric, error) {
	var metrics []collector.Metric

	v, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("virtual memory: %w", err)
	}

	metrics = append(metrics,
		memGauge("node.memory.total_bytes", float64(v.Total), "Total memory in bytes"),
		memGauge("node.memory.free_bytes", float64(v.Free), "Free memory in bytes"),
		memGauge("node.memory.available_bytes", float64(v.Available), "Available memory in bytes"),
		memGauge("node.memory.buffers_bytes", float64(v.Buffers), "Buffer memory in bytes"),
		memGauge("node.memory.cached_bytes", float64(v.Cached), "Cached memory in bytes"),
		memGauge("node.memory.active_bytes", float64(v.Active), "Active memory in bytes"),
		memGauge("node.memory.inactive_bytes", float64(v.Inactive), "Inactive memory in bytes"),
		memGauge("node.memory.wired_bytes", float64(v.Wired), "Wired memory in bytes"),
		memGauge("node.memory.shared_bytes", float64(v.Shared), "Shared memory in bytes"),
		memGauge("node.memory.slab_bytes", float64(v.Slab), "Slab memory in bytes"),
		memGauge("node.memory.page_tables_bytes", float64(v.PageTables), "Page table memory in bytes"),
		memGauge("node.memory.committed_as_bytes", float64(v.CommittedAS), "Committed AS in bytes"),
		memGauge("node.memory.commit_limit_bytes", float64(v.CommitLimit), "Commit limit in bytes"),
		memGauge("node.memory.dirty_bytes", float64(v.Dirty), "Dirty pages in bytes"),
		memGauge("node.memory.writeback_bytes", float64(v.WriteBack), "Writeback pages in bytes"),
	)

	// Swap
	s, err := mem.SwapMemory()
	if err == nil {
		metrics = append(metrics,
			memGauge("node.memory.swap_total_bytes", float64(s.Total), "Swap total in bytes"),
			memGauge("node.memory.swap_used_bytes", float64(s.Used), "Swap used in bytes"),
			memGauge("node.memory.swap_free_bytes", float64(s.Free), "Swap free in bytes"),
			collector.NewMetric("node.memory.swap_in_bytes", float64(s.Sin), collector.MetricTypeCounter).
				WithUnit("bytes").WithDescription("Swap in bytes total"),
			collector.NewMetric("node.memory.swap_out_bytes", float64(s.Sout), collector.MetricTypeCounter).
				WithUnit("bytes").WithDescription("Swap out bytes total"),
		)
	}

	return metrics, nil
}

func memGauge(name string, value float64, desc string) collector.Metric {
	return collector.NewMetric(name, value, collector.MetricTypeGauge).
		WithUnit("bytes").WithDescription(desc)
}
