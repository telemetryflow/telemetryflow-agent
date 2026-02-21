// Package ebpf provides an eBPF-based kernel-level metrics collector.
// When enabled, it attaches BPF programs to tracepoints and kprobes to collect
// syscall counts, TCP/UDP connections, file I/O, scheduler events, memory
// page faults, and TCP state transitions.
//
// Linux-only — non-Linux platforms return empty metrics via build-tagged stubs.
package ebpf

import (
	"fmt"
	"regexp"
	"runtime"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// collectorConfig holds parsed configuration for the eBPF collector.
type collectorConfig struct {
	raw config.EBPFCollectorConfig

	// Compiled process filter regexes
	processFilterRe  []*regexp.Regexp
	excludeProcessRe []*regexp.Regexp
}

// newCollectorConfig parses and validates the eBPF collector configuration.
func newCollectorConfig(cfg config.EBPFCollectorConfig, logger *zap.Logger) *collectorConfig {
	cc := &collectorConfig{raw: cfg}

	// Compile process filter patterns
	for _, p := range cfg.ProcessFilter {
		re, err := regexp.Compile(p)
		if err != nil {
			logger.Warn("Invalid process filter pattern, skipping",
				zap.String("pattern", p),
				zap.Error(err),
			)
			continue
		}
		cc.processFilterRe = append(cc.processFilterRe, re)
	}

	// Compile exclude process patterns
	for _, p := range cfg.ExcludeProcesses {
		re, err := regexp.Compile("^" + regexp.QuoteMeta(p) + "$")
		if err != nil {
			logger.Warn("Invalid exclude process pattern, skipping",
				zap.String("pattern", p),
				zap.Error(err),
			)
			continue
		}
		cc.excludeProcessRe = append(cc.excludeProcessRe, re)
	}

	return cc
}

// isLinux returns true if running on Linux.
func isLinux() bool {
	return runtime.GOOS == "linux"
}

// validate checks that the eBPF collector configuration is valid.
func (cc *collectorConfig) validate() error {
	if cc.raw.SampleRate < 1 || cc.raw.SampleRate > 100 {
		return fmt.Errorf("ebpf: sample_rate must be between 1 and 100, got %d", cc.raw.SampleRate)
	}
	if cc.raw.RingBufferSize < 0 {
		return fmt.Errorf("ebpf: ring_buffer_size must be non-negative, got %d", cc.raw.RingBufferSize)
	}
	if cc.raw.PerfBufferSize < 0 {
		return fmt.Errorf("ebpf: perf_buffer_size must be non-negative, got %d", cc.raw.PerfBufferSize)
	}
	return nil
}

// hasAnySubCollector returns true if at least one sub-collector is enabled.
func (cc *collectorConfig) hasAnySubCollector() bool {
	return cc.raw.CollectSyscalls ||
		cc.raw.CollectNetwork ||
		cc.raw.CollectFileIO ||
		cc.raw.CollectScheduler ||
		cc.raw.CollectMemory ||
		cc.raw.CollectTCPEvents ||
		cc.raw.Cilium.Enabled
}
