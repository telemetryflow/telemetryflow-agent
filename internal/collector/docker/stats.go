package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	containertypes "github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectContainerStats fetches stats for a single running container and
// returns all enabled metric categories.
func (d *DockerCollector) collectContainerStats(ctx context.Context, ctr containertypes.Summary) ([]collector.Metric, error) {
	resp, err := d.client.ContainerStats(ctx, ctr.ID, dockerclient.ContainerStatsOptions{Stream: false})
	if err != nil {
		return nil, fmt.Errorf("stats one-shot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var stats containertypes.StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("stats decode: %w", err)
	}

	name := cleanContainerName(ctr.Names)
	shortID := ctr.ID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	labels := containerLabels(shortID, name, ctr.Image, string(ctr.State))

	var metrics []collector.Metric

	if d.cfg.raw.CollectCPU {
		metrics = append(metrics, collectCPUMetrics(&stats, labels)...)
	}
	if d.cfg.raw.CollectMemory {
		metrics = append(metrics, collectMemoryMetrics(&stats, labels)...)
	}
	if d.cfg.raw.CollectNetwork {
		metrics = append(metrics, collectNetworkMetrics(&stats, labels)...)
	}
	if d.cfg.raw.CollectDiskIO {
		metrics = append(metrics, collectDiskIOMetrics(&stats, labels)...)
	}
	if d.cfg.raw.CollectPIDs {
		metrics = append(metrics, collector.NewMetric(
			"container.pids.current", float64(stats.PidsStats.Current), collector.MetricTypeGauge,
		).WithLabels(labels).WithDescription("Current number of PIDs"))
	}

	return metrics, nil
}

// collectCPUMetrics computes CPU usage percentage using the PreCPUStats
// delta provided by Docker's stats API.
// Formula: (cpuDelta / systemDelta) * numCPUs * 100
func collectCPUMetrics(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric

	cpuUsage := stats.CPUStats.CPUUsage.TotalUsage
	preCPUUsage := stats.PreCPUStats.CPUUsage.TotalUsage
	systemUsage := stats.CPUStats.SystemUsage
	preSystemUsage := stats.PreCPUStats.SystemUsage

	numCPUs := uint64(stats.CPUStats.OnlineCPUs)
	if numCPUs == 0 {
		numCPUs = uint64(len(stats.CPUStats.CPUUsage.PercpuUsage))
	}
	if numCPUs == 0 {
		numCPUs = 1
	}

	// Delta-based CPU percentage using PreCPUStats
	cpuDelta := float64(cpuUsage - preCPUUsage)
	systemDelta := float64(systemUsage - preSystemUsage)
	if systemDelta > 0 && cpuDelta >= 0 {
		cpuPercent := (cpuDelta / systemDelta) * float64(numCPUs) * 100.0
		metrics = append(metrics, collector.NewMetric(
			"container.cpu.usage_percent", cpuPercent, collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("percent").WithDescription("Container CPU usage percentage"))
	}

	// Absolute counters
	metrics = append(metrics,
		collector.NewMetric(
			"container.cpu.usage_total", float64(cpuUsage), collector.MetricTypeCounter,
		).WithLabels(labels).WithUnit("nanoseconds").WithDescription("Total CPU time consumed"),
		collector.NewMetric(
			"container.cpu.user", float64(stats.CPUStats.CPUUsage.UsageInUsermode), collector.MetricTypeCounter,
		).WithLabels(labels).WithUnit("nanoseconds").WithDescription("CPU time in user mode"),
		collector.NewMetric(
			"container.cpu.kernel", float64(stats.CPUStats.CPUUsage.UsageInKernelmode), collector.MetricTypeCounter,
		).WithLabels(labels).WithUnit("nanoseconds").WithDescription("CPU time in kernel mode"),
		collector.NewMetric(
			"container.cpu.online_cpus", float64(numCPUs), collector.MetricTypeGauge,
		).WithLabels(labels).WithDescription("Number of online CPUs"),
	)

	// Throttling
	metrics = append(metrics,
		collector.NewMetric(
			"container.cpu.throttled_periods", float64(stats.CPUStats.ThrottlingData.ThrottledPeriods), collector.MetricTypeCounter,
		).WithLabels(labels).WithDescription("Number of throttled periods"),
		collector.NewMetric(
			"container.cpu.throttled_time", float64(stats.CPUStats.ThrottlingData.ThrottledTime), collector.MetricTypeCounter,
		).WithLabels(labels).WithUnit("nanoseconds").WithDescription("Total throttled time"),
	)

	return metrics
}

// collectMemoryMetrics extracts memory-related metrics from container stats.
func collectMemoryMetrics(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	mem := stats.MemoryStats

	// Working set = usage - inactive_file (matches kubectl top)
	inactiveFile := mem.Stats["inactive_file"]
	workingSet := mem.Usage
	if mem.Usage > inactiveFile {
		workingSet = mem.Usage - inactiveFile
	}

	metrics := []collector.Metric{
		collector.NewMetric(
			"container.memory.usage", float64(mem.Usage), collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("bytes").WithDescription("Current memory usage including cache"),
		collector.NewMetric(
			"container.memory.working_set", float64(workingSet), collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("bytes").WithDescription("Working set memory (usage minus inactive file cache)"),
		collector.NewMetric(
			"container.memory.limit", float64(mem.Limit), collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("bytes").WithDescription("Memory limit"),
		collector.NewMetric(
			"container.memory.max_usage", float64(mem.MaxUsage), collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("bytes").WithDescription("Maximum memory usage recorded"),
	}

	if rss, ok := mem.Stats["rss"]; ok {
		metrics = append(metrics, collector.NewMetric(
			"container.memory.rss", float64(rss), collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("bytes").WithDescription("Resident set size"))
	}
	if cache, ok := mem.Stats["cache"]; ok {
		metrics = append(metrics, collector.NewMetric(
			"container.memory.cache", float64(cache), collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("bytes").WithDescription("Page cache memory"))
	}

	// Memory usage percentage
	if mem.Limit > 0 {
		usagePercent := float64(workingSet) / float64(mem.Limit) * 100.0
		metrics = append(metrics, collector.NewMetric(
			"container.memory.usage_percent", usagePercent, collector.MetricTypeGauge,
		).WithLabels(labels).WithUnit("percent").WithDescription("Memory usage as percentage of limit"))
	}

	return metrics
}

// collectNetworkMetrics extracts per-interface network metrics.
func collectNetworkMetrics(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	var metrics []collector.Metric

	for iface, net := range stats.Networks {
		ifLabels := make(map[string]string, len(labels)+1)
		for k, v := range labels {
			ifLabels[k] = v
		}
		ifLabels["interface"] = iface

		metrics = append(metrics,
			collector.NewMetric("container.network.rx_bytes", float64(net.RxBytes), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithUnit("bytes").WithDescription("Bytes received"),
			collector.NewMetric("container.network.tx_bytes", float64(net.TxBytes), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithUnit("bytes").WithDescription("Bytes transmitted"),
			collector.NewMetric("container.network.rx_packets", float64(net.RxPackets), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithDescription("Packets received"),
			collector.NewMetric("container.network.tx_packets", float64(net.TxPackets), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithDescription("Packets transmitted"),
			collector.NewMetric("container.network.rx_errors", float64(net.RxErrors), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithDescription("Receive errors"),
			collector.NewMetric("container.network.tx_errors", float64(net.TxErrors), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithDescription("Transmit errors"),
			collector.NewMetric("container.network.rx_dropped", float64(net.RxDropped), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithDescription("Received packets dropped"),
			collector.NewMetric("container.network.tx_dropped", float64(net.TxDropped), collector.MetricTypeCounter).
				WithLabels(ifLabels).WithDescription("Transmitted packets dropped"),
		)
	}

	return metrics
}

// collectDiskIOMetrics extracts block I/O metrics from container stats.
func collectDiskIOMetrics(stats *containertypes.StatsResponse, labels map[string]string) []collector.Metric {
	var readBytes, writeBytes, readOps, writeOps uint64

	for _, entry := range stats.BlkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(entry.Op) {
		case "read":
			readBytes += entry.Value
		case "write":
			writeBytes += entry.Value
		}
	}
	for _, entry := range stats.BlkioStats.IoServicedRecursive {
		switch strings.ToLower(entry.Op) {
		case "read":
			readOps += entry.Value
		case "write":
			writeOps += entry.Value
		}
	}

	return []collector.Metric{
		collector.NewMetric("container.diskio.read_bytes", float64(readBytes), collector.MetricTypeCounter).
			WithLabels(labels).WithUnit("bytes").WithDescription("Total bytes read from disk"),
		collector.NewMetric("container.diskio.write_bytes", float64(writeBytes), collector.MetricTypeCounter).
			WithLabels(labels).WithUnit("bytes").WithDescription("Total bytes written to disk"),
		collector.NewMetric("container.diskio.read_ops", float64(readOps), collector.MetricTypeCounter).
			WithLabels(labels).WithDescription("Total read operations"),
		collector.NewMetric("container.diskio.write_ops", float64(writeOps), collector.MetricTypeCounter).
			WithLabels(labels).WithDescription("Total write operations"),
	}
}
