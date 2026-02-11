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
