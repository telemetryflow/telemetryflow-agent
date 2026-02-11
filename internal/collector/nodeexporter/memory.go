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
