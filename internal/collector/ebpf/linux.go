//go:build linux

// Package ebpf implements a kernel-level metrics collector using eBPF programs
// attached to tracepoints and kprobes. It captures syscall counts, TCP/UDP
// connections, file I/O, scheduler events, memory page faults, and — optionally
// — Cilium Hubble network-flow data. On non-Linux platforms the collector is a
// no-op stub.
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
package ebpf

import (
	"context"
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// loadPrograms loads and attaches eBPF programs on Linux.
func (c *EBPFCollector) loadPrograms() error {
	return c.loadProgramsLinux()
}

// closePrograms detaches and closes all eBPF programs on Linux.
func (c *EBPFCollector) closePrograms() {
	c.closeProgramsLinux()
}

// collectAll dispatches to each enabled sub-collector and aggregates metrics.
func (c *EBPFCollector) collectAll(ctx context.Context) []collector.Metric {
	var metrics []collector.Metric

	if c.cfg.raw.CollectSyscalls {
		if m, err := c.collectSyscalls(ctx); err != nil {
			c.logger.Debug("Syscall sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.CollectNetwork {
		if m, err := c.collectNetwork(ctx); err != nil {
			c.logger.Debug("Network sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.CollectFileIO {
		if m, err := c.collectFileIO(ctx); err != nil {
			c.logger.Debug("FileIO sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.CollectScheduler {
		if m, err := c.collectScheduler(ctx); err != nil {
			c.logger.Debug("Scheduler sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.CollectMemory {
		if m, err := c.collectMemory(ctx); err != nil {
			c.logger.Debug("Memory sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.CollectTCPEvents {
		if m, err := c.collectTCPState(ctx); err != nil {
			c.logger.Debug("TCP state sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	if c.cfg.raw.Cilium.Enabled {
		if m, err := c.collectHubble(ctx); err != nil {
			c.logger.Debug("Hubble sub-collector error", zap.Error(err))
		} else {
			metrics = append(metrics, m...)
		}
	}

	return metrics
}

// =========================================================================
// Sub-collector implementations
// =========================================================================

// collectSyscalls reads syscall statistics from BPF maps and converts to metrics.
func (c *EBPFCollector) collectSyscalls(_ context.Context) ([]collector.Metric, error) {
	if programs == nil || programs.syscallStats == nil {
		return nil, nil
	}

	var metrics []collector.Metric
	var key syscallKey
	var val syscallVal

	iter := programs.syscallStats.Iterate()
	for iter.Next(&key, &val) {
		comm := commToString(val.Comm)
		if !c.cfg.shouldIncludeProcess(comm) {
			continue
		}

		pidStr := strconv.FormatUint(uint64(key.PID), 10)
		sysName := syscallName(key.SyscallNr)

		labels := map[string]string{
			"pid":     pidStr,
			"comm":    comm,
			"syscall": sysName,
		}

		metrics = append(metrics,
			collector.NewMetric("ebpf.syscall.count", float64(val.Count), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.syscall.latency_ns", float64(val.TotalNs), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.syscall.errors", float64(val.Errors), collector.MetricTypeCounter).
				WithLabels(labels),
		)
	}

	return metrics, iter.Err()
}

// collectNetwork reads TCP/UDP connection metrics from BPF maps.
func (c *EBPFCollector) collectNetwork(_ context.Context) ([]collector.Metric, error) {
	var metrics []collector.Metric

	// TCP stats
	if programs != nil && programs.tcpStats != nil {
		var key netKey
		var val tcpVal

		iter := programs.tcpStats.Iterate()
		for iter.Next(&key, &val) {
			comm := commToString(val.Comm)
			if !c.cfg.shouldIncludeProcess(comm) {
				continue
			}

			labels := map[string]string{
				"pid":  strconv.FormatUint(uint64(key.PID), 10),
				"comm": comm,
			}

			metrics = append(metrics,
				collector.NewMetric("ebpf.tcp.connections", float64(val.Connections), collector.MetricTypeCounter).
					WithLabels(labels),
				collector.NewMetric("ebpf.tcp.bytes_sent", float64(val.BytesSent), collector.MetricTypeCounter).
					WithLabels(labels),
				collector.NewMetric("ebpf.tcp.bytes_recv", float64(val.BytesRecv), collector.MetricTypeCounter).
					WithLabels(labels),
				collector.NewMetric("ebpf.tcp.retransmits", float64(val.Retransmits), collector.MetricTypeCounter).
					WithLabels(labels),
			)

			if val.RttNs > 0 {
				metrics = append(metrics,
					collector.NewMetric("ebpf.tcp.rtt_ns", float64(val.RttNs), collector.MetricTypeGauge).
						WithLabels(labels),
				)
			}
		}
		if err := iter.Err(); err != nil {
			return metrics, fmt.Errorf("iterate tcp_stats: %w", err)
		}
	}

	// UDP stats
	if programs != nil && programs.udpStats != nil {
		var key netKey
		var val udpVal

		iter := programs.udpStats.Iterate()
		for iter.Next(&key, &val) {
			comm := commToString(val.Comm)
			if !c.cfg.shouldIncludeProcess(comm) {
				continue
			}

			labels := map[string]string{
				"pid":  strconv.FormatUint(uint64(key.PID), 10),
				"comm": comm,
			}

			metrics = append(metrics,
				collector.NewMetric("ebpf.udp.packets_sent", float64(val.PacketsSent), collector.MetricTypeCounter).
					WithLabels(labels),
				collector.NewMetric("ebpf.udp.packets_recv", float64(val.PacketsRecv), collector.MetricTypeCounter).
					WithLabels(labels),
			)
		}
		if err := iter.Err(); err != nil {
			return metrics, fmt.Errorf("iterate udp_stats: %w", err)
		}
	}

	return metrics, nil
}

// collectFileIO reads VFS operation metrics from BPF maps.
func (c *EBPFCollector) collectFileIO(_ context.Context) ([]collector.Metric, error) {
	if programs == nil || programs.fileioStats == nil {
		return nil, nil
	}

	var metrics []collector.Metric
	var key fileioKey
	var val fileioVal

	iter := programs.fileioStats.Iterate()
	for iter.Next(&key, &val) {
		comm := commToString(val.Comm)
		if !c.cfg.shouldIncludeProcess(comm) {
			continue
		}

		labels := map[string]string{
			"pid":       strconv.FormatUint(uint64(key.PID), 10),
			"comm":      comm,
			"operation": fileioOperationName(key.Operation),
		}

		metrics = append(metrics,
			collector.NewMetric("ebpf.fileio.operations", float64(val.Count), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.fileio.bytes", float64(val.Bytes), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.fileio.latency_ns", float64(val.TotalNs), collector.MetricTypeCounter).
				WithLabels(labels),
		)
	}

	return metrics, iter.Err()
}

// collectScheduler reads scheduler metrics from BPF maps.
func (c *EBPFCollector) collectScheduler(_ context.Context) ([]collector.Metric, error) {
	if programs == nil || programs.schedStats == nil {
		return nil, nil
	}

	var metrics []collector.Metric
	var key schedKey
	var val schedVal

	iter := programs.schedStats.Iterate()
	for iter.Next(&key, &val) {
		comm := commToString(val.Comm)
		if !c.cfg.shouldIncludeProcess(comm) {
			continue
		}

		labels := map[string]string{
			"pid":  strconv.FormatUint(uint64(key.PID), 10),
			"comm": comm,
		}

		metrics = append(metrics,
			collector.NewMetric("ebpf.sched.context_switches", float64(val.ContextSwitches), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.sched.runq_latency_ns", float64(val.RunqLatencyNs), collector.MetricTypeGauge).
				WithLabels(labels),
			collector.NewMetric("ebpf.sched.oncpu_ns", float64(val.OncpuNs), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.sched.migrations", float64(val.Migrations), collector.MetricTypeCounter).
				WithLabels(labels),
		)
	}

	return metrics, iter.Err()
}

// collectMemory reads memory event metrics from BPF maps.
func (c *EBPFCollector) collectMemory(_ context.Context) ([]collector.Metric, error) {
	if programs == nil || programs.memStats == nil {
		return nil, nil
	}

	var metrics []collector.Metric
	var key memKey
	var val memVal

	iter := programs.memStats.Iterate()
	for iter.Next(&key, &val) {
		comm := commToString(val.Comm)
		if !c.cfg.shouldIncludeProcess(comm) {
			continue
		}

		labels := map[string]string{
			"pid":  strconv.FormatUint(uint64(key.PID), 10),
			"comm": comm,
		}

		metrics = append(metrics,
			collector.NewMetric("ebpf.memory.page_faults", float64(val.PageFaults), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.memory.major_faults", float64(val.MajorFaults), collector.MetricTypeCounter).
				WithLabels(labels),
			collector.NewMetric("ebpf.memory.minor_faults", float64(val.MinorFaults), collector.MetricTypeCounter).
				WithLabels(labels),
		)
	}

	return metrics, iter.Err()
}

// collectTCPState reads TCP state transition metrics from BPF maps.
func (c *EBPFCollector) collectTCPState(_ context.Context) ([]collector.Metric, error) {
	if programs == nil || programs.tcpstateStats == nil {
		return nil, nil
	}

	var metrics []collector.Metric
	var key tcpstateKey
	var val tcpstateVal

	iter := programs.tcpstateStats.Iterate()
	for iter.Next(&key, &val) {
		labels := map[string]string{
			"pid":       strconv.FormatUint(uint64(key.PID), 10),
			"old_state": tcpStateName(key.OldState),
			"new_state": tcpStateName(key.NewState),
		}

		metrics = append(metrics,
			collector.NewMetric("ebpf.tcp.state_transitions", float64(val.Count), collector.MetricTypeCounter).
				WithLabels(labels),
		)
	}

	return metrics, iter.Err()
}

// collectHubble reads metrics from Cilium Hubble gRPC client.
func (c *EBPFCollector) collectHubble(_ context.Context) ([]collector.Metric, error) {
	if c.hubble == nil {
		return nil, nil
	}

	if !c.hubble.isConnected() {
		return nil, nil
	}

	return c.hubble.collectMetrics(), nil
}
