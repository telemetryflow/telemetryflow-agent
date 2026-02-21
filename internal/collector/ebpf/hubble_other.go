//go:build !linux

package ebpf

import (
	"context"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// hubbleClient is a stub on non-Linux platforms.
// Hubble/Cilium integration requires Linux kernel eBPF support.
type hubbleClient struct {
	cfg    config.CiliumCollectorConfig
	logger *zap.Logger
}

func newHubbleClient(cfg config.CiliumCollectorConfig, logger *zap.Logger) *hubbleClient {
	return &hubbleClient{cfg: cfg, logger: logger}
}

func (h *hubbleClient) connect(_ context.Context) error { return nil }
func (h *hubbleClient) close()                          {}
