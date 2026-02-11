package nodeexporter

import (
	"context"
	"fmt"

	"github.com/shirou/gopsutil/v3/cpu"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectCPU collects per-CPU-mode time metrics and CPU frequency.
// Equivalent to node_exporter's cpu collector.
func (c *NodeExporterCollector) collectCPU(ctx context.Context) ([]collector.Metric, error) {
	var metrics []collector.Metric

	// Per-CPU time breakdown by mode
	cpuTimes, err := cpu.TimesWithContext(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("cpu times: %w", err)
	}

	for i, t := range cpuTimes {
		cpuLabel := fmt.Sprintf("%d", i)
		modes := map[string]float64{
			"user":    t.User,
			"system":  t.System,
			"idle":    t.Idle,
			"iowait":  t.Iowait,
			"irq":     t.Irq,
			"softirq": t.Softirq,
			"steal":   t.Steal,
			"guest":   t.Guest,
			"nice":    t.Nice,
		}
		for mode, value := range modes {
			metrics = append(metrics, collector.NewMetric(
				"node.cpu.seconds", value, collector.MetricTypeCounter,
			).WithLabel("cpu", cpuLabel).
				WithLabel("mode", mode).
				WithUnit("seconds").
				WithDescription("CPU time in seconds"))
		}
	}

	// CPU frequency per core
	cpuInfos, err := cpu.InfoWithContext(ctx)
	if err == nil {
		for i, info := range cpuInfos {
			cpuLabel := fmt.Sprintf("%d", i)
			// Mhz → Hz
			metrics = append(metrics, collector.NewMetric(
				"node.cpu.frequency_hz", info.Mhz*1e6, collector.MetricTypeGauge,
			).WithLabel("cpu", cpuLabel).
				WithUnit("hertz").
				WithDescription("Current CPU frequency in hertz"))
		}
	}

	return metrics, nil
}
