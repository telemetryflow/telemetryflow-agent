//go:build !linux

package ebpf

import (
	"context"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// loadPrograms is a no-op on non-Linux platforms.
func (c *EBPFCollector) loadPrograms() error {
	return nil
}

// closePrograms is a no-op on non-Linux platforms.
func (c *EBPFCollector) closePrograms() {}

// collectAll returns nil on non-Linux platforms.
func (c *EBPFCollector) collectAll(_ context.Context) []collector.Metric {
	return nil
}
