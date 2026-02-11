//go:build !linux

package nodeexporter

import (
	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectLinux is a no-op on non-Linux platforms.
func (c *NodeExporterCollector) collectLinux() []collector.Metric {
	return nil
}

// collectARPPlatform is a no-op on non-Linux platforms.
func collectARPPlatform() ([]collector.Metric, error) {
	return nil, nil
}
