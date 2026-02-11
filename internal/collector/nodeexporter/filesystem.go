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
