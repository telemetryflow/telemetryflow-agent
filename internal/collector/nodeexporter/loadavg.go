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
