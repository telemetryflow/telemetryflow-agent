// Package system collects comprehensive host-level telemetry — CPU, memory,
// disk, network interfaces, and process statistics — using gopsutil for
// cross-platform compatibility.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
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
package system

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/version"
)

// agentStartTime records when the agent started (for uptime calculation)
var agentStartTime = time.Now()

// HostCollector collects host system metrics
type HostCollector struct {
	config HostCollectorConfig
	logger *zap.Logger

	mu        sync.RWMutex
	running   bool
	stopChan  chan struct{}
	metrics   []collector.Metric
	lastStats *systemStats
}

// HostCollectorConfig contains host collector configuration
type HostCollectorConfig struct {
	Interval    time.Duration
	CollectCPU  bool
	CollectMem  bool
	CollectDisk bool
	CollectNet  bool
	DiskPaths   []string
	Logger      *zap.Logger
}

type systemStats struct {
	netBytesSent uint64
	netBytesRecv uint64
	timestamp    time.Time
}

// NewHostCollector creates a new host metrics collector
func NewHostCollector(cfg HostCollectorConfig) *HostCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	return &HostCollector{
		config:   cfg,
		logger:   cfg.Logger,
		stopChan: make(chan struct{}),
	}
}

// Name returns the collector name
func (c *HostCollector) Name() string {
	return "system.host"
}

// Start starts the collector
func (c *HostCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	c.logger.Info("Starting host collector",
		zap.Duration("interval", c.config.Interval),
		zap.Bool("cpu", c.config.CollectCPU),
		zap.Bool("memory", c.config.CollectMem),
		zap.Bool("disk", c.config.CollectDisk),
		zap.Bool("network", c.config.CollectNet),
	)

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	// Initial collection
	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopChan:
			return nil
		case <-ticker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("Collection failed", zap.Error(err))
			}
		}
	}
}

// Stop stops the collector
func (c *HostCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.running = false
	c.logger.Info("Host collector stopped")
	return nil
}

// IsRunning returns whether the collector is running
func (c *HostCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Collect performs a single collection cycle
func (c *HostCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	var metrics []collector.Metric
	now := time.Now()

	// CPU metrics
	if c.config.CollectCPU {
		cpuMetrics, err := c.collectCPU(ctx)
		if err != nil {
			c.logger.Debug("CPU collection error", zap.Error(err))
		} else {
			metrics = append(metrics, cpuMetrics...)
		}
	}

	// Memory metrics
	if c.config.CollectMem {
		memMetrics, err := c.collectMemory()
		if err != nil {
			c.logger.Debug("Memory collection error", zap.Error(err))
		} else {
			metrics = append(metrics, memMetrics...)
		}
	}

	// Disk metrics
	if c.config.CollectDisk {
		diskMetrics, err := c.collectDisk()
		if err != nil {
			c.logger.Debug("Disk collection error", zap.Error(err))
		} else {
			metrics = append(metrics, diskMetrics...)
		}
	}

	// Network metrics
	if c.config.CollectNet {
		netMetrics, err := c.collectNetwork(now)
		if err != nil {
			c.logger.Debug("Network collection error", zap.Error(err))
		} else {
			metrics = append(metrics, netMetrics...)
		}
	}

	c.mu.Lock()
	c.metrics = metrics
	c.mu.Unlock()

	c.logger.Debug("Collected metrics", zap.Int("count", len(metrics)))
	return metrics, nil
}

// collectCPU collects CPU metrics
func (c *HostCollector) collectCPU(ctx context.Context) ([]collector.Metric, error) {
	var metrics []collector.Metric

	// CPU usage percentage
	percentages, err := cpu.PercentWithContext(ctx, time.Second, false)
	if err != nil {
		return nil, err
	}

	if len(percentages) > 0 {
		metrics = append(metrics, collector.NewMetric(
			"system.cpu.usage",
			percentages[0],
			collector.MetricTypeGauge,
		).WithUnit("percent").WithDescription("CPU usage percentage"))
	}

	// CPU cores
	cores, err := cpu.CountsWithContext(ctx, true)
	if err == nil {
		metrics = append(metrics, collector.NewMetric(
			"system.cpu.cores",
			float64(cores),
			collector.MetricTypeGauge,
		).WithDescription("Number of CPU cores"))
	}

	return metrics, nil
}

// collectMemory collects memory metrics
func (c *HostCollector) collectMemory() ([]collector.Metric, error) {
	var metrics []collector.Metric

	v, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	metrics = append(metrics,
		collector.NewMetric("system.memory.total", float64(v.Total), collector.MetricTypeGauge).
			WithUnit("bytes").WithDescription("Total memory"),
		collector.NewMetric("system.memory.used", float64(v.Used), collector.MetricTypeGauge).
			WithUnit("bytes").WithDescription("Used memory"),
		collector.NewMetric("system.memory.available", float64(v.Available), collector.MetricTypeGauge).
			WithUnit("bytes").WithDescription("Available memory"),
		collector.NewMetric("system.memory.usage", v.UsedPercent, collector.MetricTypeGauge).
			WithUnit("percent").WithDescription("Memory usage percentage"),
	)

	return metrics, nil
}

// collectDisk collects disk metrics
func (c *HostCollector) collectDisk() ([]collector.Metric, error) {
	var metrics []collector.Metric

	paths := c.config.DiskPaths
	if len(paths) == 0 {
		paths = []string{"/"}
		if runtime.GOOS == "windows" {
			paths = []string{"C:"}
		}
	}

	for _, path := range paths {
		usage, err := disk.Usage(path)
		if err != nil {
			c.logger.Debug("Disk usage error", zap.String("path", path), zap.Error(err))
			continue
		}

		labels := map[string]string{"path": path}

		metrics = append(metrics,
			collector.NewMetric("system.disk.total", float64(usage.Total), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").WithDescription("Total disk space"),
			collector.NewMetric("system.disk.used", float64(usage.Used), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").WithDescription("Used disk space"),
			collector.NewMetric("system.disk.free", float64(usage.Free), collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("bytes").WithDescription("Free disk space"),
			collector.NewMetric("system.disk.usage", usage.UsedPercent, collector.MetricTypeGauge).
				WithLabels(labels).WithUnit("percent").WithDescription("Disk usage percentage"),
		)
	}

	return metrics, nil
}

// collectNetwork collects network metrics
func (c *HostCollector) collectNetwork(now time.Time) ([]collector.Metric, error) {
	var metrics []collector.Metric

	counters, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}

	if len(counters) == 0 {
		return metrics, nil
	}

	total := counters[0]

	metrics = append(metrics,
		collector.NewMetric("system.network.bytes_sent", float64(total.BytesSent), collector.MetricTypeCounter).
			WithUnit("bytes").WithDescription("Total bytes sent"),
		collector.NewMetric("system.network.bytes_recv", float64(total.BytesRecv), collector.MetricTypeCounter).
			WithUnit("bytes").WithDescription("Total bytes received"),
		collector.NewMetric("system.network.packets_sent", float64(total.PacketsSent), collector.MetricTypeCounter).
			WithDescription("Total packets sent"),
		collector.NewMetric("system.network.packets_recv", float64(total.PacketsRecv), collector.MetricTypeCounter).
			WithDescription("Total packets received"),
		collector.NewMetric("system.network.errors_in", float64(total.Errin), collector.MetricTypeCounter).
			WithDescription("Total input errors"),
		collector.NewMetric("system.network.errors_out", float64(total.Errout), collector.MetricTypeCounter).
			WithDescription("Total output errors"),
	)

	// Calculate rates if we have previous stats
	c.mu.Lock()
	if c.lastStats != nil {
		elapsed := now.Sub(c.lastStats.timestamp).Seconds()
		if elapsed > 0 {
			bytesSentRate := float64(total.BytesSent-c.lastStats.netBytesSent) / elapsed
			bytesRecvRate := float64(total.BytesRecv-c.lastStats.netBytesRecv) / elapsed

			metrics = append(metrics,
				collector.NewMetric("system.network.bytes_sent_rate", bytesSentRate, collector.MetricTypeGauge).
					WithUnit("bytes/s").WithDescription("Bytes sent per second"),
				collector.NewMetric("system.network.bytes_recv_rate", bytesRecvRate, collector.MetricTypeGauge).
					WithUnit("bytes/s").WithDescription("Bytes received per second"),
			)
		}
	}
	c.lastStats = &systemStats{
		netBytesSent: total.BytesSent,
		netBytesRecv: total.BytesRecv,
		timestamp:    now,
	}
	c.mu.Unlock()

	return metrics, nil
}

// systemInfoCache provides internal caching for reliability
type systemInfoCache struct {
	mu        sync.RWMutex
	info      *collector.SystemInfo
	timestamp time.Time
	ttl       time.Duration

	// Network rate tracking
	prevNetBytesSent uint64
	prevNetBytesRecv uint64
	prevNetTimestamp time.Time
}

var infoCache = &systemInfoCache{
	ttl: 5 * time.Second, // Cache TTL for reliability during transient failures
}

// getCached returns cached info if still valid
func (c *systemInfoCache) getCached() *collector.SystemInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.info != nil && time.Since(c.timestamp) < c.ttl {
		return c.info
	}
	return nil
}

// setCache updates the cache
func (c *systemInfoCache) setCache(info *collector.SystemInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.info = info
	c.timestamp = time.Now()
}

// GetSystemInfo returns current system information for heartbeat
func (c *HostCollector) GetSystemInfo() (*collector.SystemInfo, error) {
	startTime := time.Now()
	info := &collector.SystemInfo{}

	// ==========================================================================
	// Host Information
	// ==========================================================================
	hostInfo, err := host.Info()
	if err == nil {
		info.Hostname = hostInfo.Hostname
		info.OS = hostInfo.OS
		info.OSVersion = hostInfo.PlatformVersion
		info.Platform = hostInfo.Platform
		info.PlatformFamily = hostInfo.PlatformFamily
		info.KernelVersion = hostInfo.KernelVersion
		info.Architecture = hostInfo.KernelArch
		info.Uptime = hostInfo.Uptime
		info.BootTime = hostInfo.BootTime
		info.HostID = hostInfo.HostID
	}

	// Timezone
	if tz, err := time.LoadLocation("Local"); err == nil {
		info.Timezone = tz.String()
	}

	// ==========================================================================
	// CPU Information
	// ==========================================================================
	cpuInfo, err := cpu.Info()
	if err == nil && len(cpuInfo) > 0 {
		info.CPUModel = cpuInfo[0].ModelName
		info.CPUVendor = cpuInfo[0].VendorID
		info.CPUFamily = cpuInfo[0].Family
		info.CPUMhz = cpuInfo[0].Mhz
		info.CPUCacheSize = cpuInfo[0].CacheSize
	}

	// CPU cores
	logicalCores, err := cpu.Counts(true)
	if err == nil {
		info.CPUCores = logicalCores
		info.CPULogicalCores = logicalCores
	}
	physicalCores, err := cpu.Counts(false)
	if err == nil {
		info.CPUPhysicalCores = physicalCores
	}

	// CPU usage with time breakdown
	cpuTimes, err := cpu.Times(false)
	if err == nil && len(cpuTimes) > 0 {
		total := cpuTimes[0].User + cpuTimes[0].System + cpuTimes[0].Idle +
			cpuTimes[0].Nice + cpuTimes[0].Iowait + cpuTimes[0].Irq +
			cpuTimes[0].Softirq + cpuTimes[0].Steal + cpuTimes[0].Guest
		if total > 0 {
			info.CPUUserPercent = (cpuTimes[0].User / total) * 100
			info.CPUSystemPercent = (cpuTimes[0].System / total) * 100
			info.CPUIdlePercent = (cpuTimes[0].Idle / total) * 100
			info.CPUIOWaitPercent = (cpuTimes[0].Iowait / total) * 100
			info.CPUStealPercent = (cpuTimes[0].Steal / total) * 100
			info.CPUGuestPercent = (cpuTimes[0].Guest / total) * 100
			info.CPUIrqPercent = (cpuTimes[0].Irq / total) * 100
			info.CPUSoftIrqPercent = (cpuTimes[0].Softirq / total) * 100
			info.CPUNicePercent = (cpuTimes[0].Nice / total) * 100
		}
	}

	// Total CPU usage
	percentages, err := cpu.Percent(time.Second, false)
	if err == nil && len(percentages) > 0 {
		info.CPUUsage = percentages[0]
	}

	// Per-core CPU usage
	perCorePercent, err := cpu.Percent(0, true)
	if err == nil {
		info.CPUPerCore = make([]collector.CPUCoreInfo, len(perCorePercent))
		for i, pct := range perCorePercent {
			info.CPUPerCore[i] = collector.CPUCoreInfo{
				CoreID: i,
				Usage:  pct,
			}
		}
	}

	// Load averages (Unix-like systems)
	loadAvg, err := load.Avg()
	if err == nil {
		info.LoadAvg1 = loadAvg.Load1
		info.LoadAvg5 = loadAvg.Load5
		info.LoadAvg15 = loadAvg.Load15
	}

	// ==========================================================================
	// Memory Information
	// ==========================================================================
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		info.MemoryTotal = memInfo.Total
		info.MemoryUsed = memInfo.Used
		info.MemoryAvailable = memInfo.Available
		info.MemoryFree = memInfo.Free
		info.MemoryUsage = memInfo.UsedPercent
		info.MemoryCached = memInfo.Cached
		info.MemoryBuffers = memInfo.Buffers
		info.MemoryActive = memInfo.Active
		info.MemoryInactive = memInfo.Inactive
		info.MemoryWired = memInfo.Wired
		info.MemoryShared = memInfo.Shared
		info.MemorySlab = memInfo.Slab
		info.MemoryPageTables = memInfo.PageTables
		info.MemoryCommitted = memInfo.CommittedAS
		info.MemoryCommitLimit = memInfo.CommitLimit
		info.MemoryDirty = memInfo.Dirty
		info.MemoryWriteback = memInfo.WriteBack
	}

	// Swap memory
	swapInfo, err := mem.SwapMemory()
	if err == nil {
		info.SwapTotal = swapInfo.Total
		info.SwapUsed = swapInfo.Used
		info.SwapFree = swapInfo.Free
		info.SwapUsage = swapInfo.UsedPercent
		info.SwapIn = swapInfo.Sin
		info.SwapOut = swapInfo.Sout
	}

	// Page faults from /proc/vmstat (Linux only)
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/vmstat"); err == nil {
			var totalFaults uint64
			for _, line := range strings.Split(string(data), "\n") {
				switch {
				case strings.HasPrefix(line, "pgmajfault "):
					info.PageFaultsMajor = parseUint64(strings.TrimPrefix(line, "pgmajfault "))
				case strings.HasPrefix(line, "pgfault "):
					totalFaults = parseUint64(strings.TrimPrefix(line, "pgfault "))
				}
			}
			// Minor faults = total faults - major faults
			if totalFaults > info.PageFaultsMajor {
				info.PageFaultsMinor = totalFaults - info.PageFaultsMajor
			}
		}
	}

	// ==========================================================================
	// Disk Information
	// ==========================================================================
	diskPath := "/"
	if runtime.GOOS == "windows" {
		diskPath = "C:"
	}
	diskInfo, err := disk.Usage(diskPath)
	if err == nil {
		info.DiskTotal = diskInfo.Total
		info.DiskUsed = diskInfo.Used
		info.DiskAvailable = diskInfo.Free
		info.DiskUsage = diskInfo.UsedPercent
		info.DiskInodes = diskInfo.InodesTotal
		info.DiskInodesFree = diskInfo.InodesFree
		info.DiskInodesUsed = diskInfo.InodesUsed
		info.DiskInodesUsage = diskInfo.InodesUsedPercent
	}

	// Disk I/O counters
	diskIOCounters, err := disk.IOCounters()
	if err == nil {
		var totalReadBytes, totalWriteBytes uint64
		var totalReadOps, totalWriteOps uint64
		var totalReadTime, totalWriteTime, totalIOTime uint64
		var totalWeightedIO, totalIOInProgress uint64

		for _, counter := range diskIOCounters {
			totalReadBytes += counter.ReadBytes
			totalWriteBytes += counter.WriteBytes
			totalReadOps += counter.ReadCount
			totalWriteOps += counter.WriteCount
			totalReadTime += counter.ReadTime
			totalWriteTime += counter.WriteTime
			totalIOTime += counter.IoTime
			totalWeightedIO += counter.WeightedIO
			totalIOInProgress += uint64(counter.IopsInProgress)
		}

		info.DiskReadBytes = totalReadBytes
		info.DiskWriteBytes = totalWriteBytes
		info.DiskReadOps = totalReadOps
		info.DiskWriteOps = totalWriteOps
		info.DiskReadTime = totalReadTime
		info.DiskWriteTime = totalWriteTime
		info.DiskIOTime = totalIOTime
		info.DiskWeightedIO = totalWeightedIO
		info.DiskIOInProgress = totalIOInProgress

		// Calculate IOPS and latency
		if totalReadOps > 0 && totalReadTime > 0 {
			info.DiskLatencyRead = float64(totalReadTime) / float64(totalReadOps)
		}
		if totalWriteOps > 0 && totalWriteTime > 0 {
			info.DiskLatencyWrite = float64(totalWriteTime) / float64(totalWriteOps)
		}

		// Calculate IOPS (operations per second based on IO time)
		// DiskIOTime is in milliseconds, represents time spent doing I/O
		totalOps := totalReadOps + totalWriteOps
		if totalOps > 0 && totalIOTime > 0 {
			// IOPS = total operations / (IO time in seconds)
			info.DiskIOPS = float64(totalOps) / (float64(totalIOTime) / 1000.0)
		}
	}

	// Per-partition disk info
	partitions, err := disk.Partitions(false)
	if err == nil {
		info.DiskPartitions = make([]collector.DiskPartitionInfo, 0, len(partitions))
		for _, p := range partitions {
			usage, err := disk.Usage(p.Mountpoint)
			if err != nil {
				continue
			}
			info.DiskPartitions = append(info.DiskPartitions, collector.DiskPartitionInfo{
				Device:      p.Device,
				Mountpoint:  p.Mountpoint,
				Fstype:      p.Fstype,
				Total:       usage.Total,
				Used:        usage.Used,
				Free:        usage.Free,
				Usage:       usage.UsedPercent,
				Inodes:      usage.InodesTotal,
				InodesFree:  usage.InodesFree,
				InodesUsage: usage.InodesUsedPercent,
			})
		}
	}

	// ==========================================================================
	// Network Information
	// ==========================================================================
	netCounters, err := net.IOCounters(false)
	if err == nil && len(netCounters) > 0 {
		total := netCounters[0]
		info.NetworkBytesSent = total.BytesSent
		info.NetworkBytesRecv = total.BytesRecv
		info.NetworkPacketsSent = total.PacketsSent
		info.NetworkPacketsRecv = total.PacketsRecv
		info.NetworkErrorsIn = total.Errin
		info.NetworkErrorsOut = total.Errout
		info.NetworkDropsIn = total.Dropin
		info.NetworkDropsOut = total.Dropout
		info.NetworkFifoIn = total.Fifoin
		info.NetworkFifoOut = total.Fifoout

		// Calculate network rates using cached previous values
		now := time.Now()
		infoCache.mu.Lock()
		if !infoCache.prevNetTimestamp.IsZero() {
			elapsed := now.Sub(infoCache.prevNetTimestamp).Seconds()
			if elapsed > 0 && total.BytesSent >= infoCache.prevNetBytesSent {
				info.NetworkBytesSentRate = float64(total.BytesSent-infoCache.prevNetBytesSent) / elapsed
			}
			if elapsed > 0 && total.BytesRecv >= infoCache.prevNetBytesRecv {
				info.NetworkBytesRecvRate = float64(total.BytesRecv-infoCache.prevNetBytesRecv) / elapsed
			}
		}
		// Update previous values for next calculation
		infoCache.prevNetBytesSent = total.BytesSent
		infoCache.prevNetBytesRecv = total.BytesRecv
		infoCache.prevNetTimestamp = now
		infoCache.mu.Unlock()
	}

	// TCP connection states
	connections, err := net.Connections("tcp")
	if err == nil {
		for _, conn := range connections {
			switch conn.Status {
			case "ESTABLISHED":
				info.TCPConnectionsEstablished++
			case "TIME_WAIT":
				info.TCPConnectionsTimeWait++
			case "CLOSE_WAIT":
				info.TCPConnectionsCloseWait++
			case "LISTEN":
				info.TCPConnectionsListen++
			case "SYN_SENT":
				info.TCPConnectionsSynSent++
			case "SYN_RECV":
				info.TCPConnectionsSynRecv++
			case "FIN_WAIT1":
				info.TCPConnectionsFinWait1++
			case "FIN_WAIT2":
				info.TCPConnectionsFinWait2++
			case "LAST_ACK":
				info.TCPConnectionsLastAck++
			case "CLOSING":
				info.TCPConnectionsClosing++
			}
		}
	}

	// TCP Retransmits from /proc/net/snmp (Linux only)
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/net/snmp"); err == nil {
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				// Find the Tcp: header line
				if strings.HasPrefix(line, "Tcp:") && strings.Contains(line, " ") {
					// Check if this is the header line (contains column names)
					if strings.Contains(line, "RtoAlgorithm") {
						// Next line contains values
						if i+1 < len(lines) {
							values := strings.Fields(lines[i+1])
							// RetransSegs is at index 12 (0-indexed)
							// Columns: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens
							//          AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs
							//          InErrs OutRsts InCsumErrors
							if len(values) > 12 {
								info.TCPRetransmits = parseUint64(values[12])
							}
						}
						break
					}
				}
			}
		}
	}

	// Per-interface network info
	netInterfaces, err := net.Interfaces()
	if err == nil {
		perIfaceCounters, _ := net.IOCounters(true)
		counterMap := make(map[string]net.IOCountersStat)
		for _, c := range perIfaceCounters {
			counterMap[c.Name] = c
		}

		info.NetworkInterfaces = make([]collector.NetworkInterfaceInfo, 0, len(netInterfaces))
		for _, iface := range netInterfaces {
			ifInfo := collector.NetworkInterfaceInfo{
				Name:       iface.Name,
				MacAddress: iface.HardwareAddr,
				MTU:        iface.MTU,
			}

			// Parse flags
			for _, flag := range iface.Flags {
				if flag == "up" {
					ifInfo.IsUp = true
				}
				if flag == "loopback" {
					ifInfo.IsLoopback = true
				}
			}

			// IP addresses
			ifInfo.IPAddresses = make([]string, len(iface.Addrs))
			for i, addr := range iface.Addrs {
				ifInfo.IPAddresses[i] = addr.Addr
			}

			// I/O counters
			if counter, ok := counterMap[iface.Name]; ok {
				ifInfo.BytesSent = counter.BytesSent
				ifInfo.BytesRecv = counter.BytesRecv
				ifInfo.PacketsSent = counter.PacketsSent
				ifInfo.PacketsRecv = counter.PacketsRecv
				ifInfo.ErrorsIn = counter.Errin
				ifInfo.ErrorsOut = counter.Errout
				ifInfo.DropsIn = counter.Dropin
				ifInfo.DropsOut = counter.Dropout
			}

			info.NetworkInterfaces = append(info.NetworkInterfaces, ifInfo)
		}
	}

	// ==========================================================================
	// Process Information
	// ==========================================================================
	procs, err := process.Processes()
	if err == nil {
		info.ProcessCount = uint64(len(procs))
		for _, p := range procs {
			status, err := p.Status()
			if err != nil {
				continue
			}
			for _, s := range status {
				switch s {
				case process.Running:
					info.ProcessRunning++
				case process.Sleep:
					info.ProcessSleeping++
				case process.Stop:
					info.ProcessStopped++
				case process.Zombie:
					info.ProcessZombie++
				case process.Wait:
					info.ProcessBlocked++
				}
			}
			// Count threads
			numThreads, err := p.NumThreads()
			if err == nil && numThreads >= 0 {
				info.ThreadCount += uint64(numThreads)
			}
		}
	}

	// ==========================================================================
	// System Resources (Linux-specific)
	// ==========================================================================
	if runtime.GOOS == "linux" {
		// File descriptors
		if data, err := os.ReadFile("/proc/sys/fs/file-nr"); err == nil {
			parts := strings.Fields(string(data))
			if len(parts) >= 3 {
				info.OpenFileDescriptors = parseUint64(parts[0])
				info.MaxFileDescriptors = parseUint64(parts[2])
				if info.MaxFileDescriptors > 0 {
					info.FileDescriptorsUsage = float64(info.OpenFileDescriptors) / float64(info.MaxFileDescriptors) * 100
				}
			}
		}

		// Entropy available
		if data, err := os.ReadFile("/proc/sys/kernel/random/entropy_avail"); err == nil {
			info.EntropyAvailable = parseUint64(strings.TrimSpace(string(data)))
		}

		// Context switches, interrupts, and soft interrupts from /proc/stat
		if data, err := os.ReadFile("/proc/stat"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				switch {
				case strings.HasPrefix(line, "ctxt "):
					// Context switches: ctxt <count>
					info.ContextSwitches = parseUint64(strings.TrimPrefix(line, "ctxt "))
				case strings.HasPrefix(line, "intr "):
					// Interrupts: intr <total> <per-irq...>
					parts := strings.Fields(line)
					if len(parts) > 1 {
						info.Interrupts = parseUint64(parts[1])
					}
				case strings.HasPrefix(line, "softirq "):
					// Soft interrupts: softirq <total> <per-softirq...>
					parts := strings.Fields(line)
					if len(parts) > 1 {
						info.SoftInterrupts = parseUint64(parts[1])
					}
				}
			}
		}

		// System calls - aggregate from all processes' /proc/[pid]/io
		// This counts read (syscr) and write (syscw) system calls
		for _, p := range procs {
			ioCounters, err := p.IOCounters()
			if err == nil {
				info.SystemCalls += ioCounters.ReadCount + ioCounters.WriteCount
			}
		}
	}

	// ==========================================================================
	// Container/Virtualization Detection
	// ==========================================================================
	info.IsContainer = detectContainer()
	if info.IsContainer {
		info.ContainerID = getContainerID()
		info.ContainerRuntime = detectContainerRuntime()
		info.ContainerName = getContainerName()
		info.ContainerImage = getContainerImage()
	}

	info.IsVirtualized, info.VirtualizationType = detectVirtualization()

	// Kubernetes provider detection
	info.IsKubernetes, info.K8sProvider = detectK8sProvider()

	// Cloud metadata
	info.CloudProvider, info.CloudInstanceID, info.CloudInstanceType,
		info.CloudRegion, info.CloudZone = detectCloudMetadata()

	// ==========================================================================
	// Agent Metadata
	// ==========================================================================
	info.AgentVersion = version.Version
	// Safe conversion with bounds checking to prevent integer overflow (gosec G115)
	if unixTime := agentStartTime.Unix(); unixTime >= 0 {
		info.AgentStartTime = uint64(unixTime)
	}
	if uptime := time.Since(agentStartTime).Seconds(); uptime >= 0 {
		info.AgentUptime = uint64(uptime)
	}
	info.CollectionTime = time.Now().Unix()
	info.CollectionDuration = time.Since(startTime).Nanoseconds()

	// Update cache for reliability
	infoCache.setCache(info)

	return info, nil
}

// parseUint64 safely parses a string to uint64
func parseUint64(s string) uint64 {
	var v uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + uint64(c-'0')
		}
	}
	return v
}

// detectK8sProvider detects whether the agent is running in a Kubernetes
// environment and returns the specific distribution/provider. The returned
// provider matches K8sProviderEnum values on the platform backend:
// eks, gke, aks, ack, cce, k3s, kind, minikube, rancher, openshift, okd,
// microshift, kubesphere, self-managed. Returns (false, "") when no
// Kubernetes environment is detected.
//
// Detection priority:
//  1. Managed cloud providers (env vars injected by the cloud control plane)
//  2. OpenShift variants (MicroShift → OpenShift → OKD)
//  3. Lightweight/local distributions (k3s → Rancher → minikube → KIND)
//  4. Platform distributions (KubeSphere)
//  5. Generic in-cluster fallback via KUBERNETES_SERVICE_HOST
func detectK8sProvider() (isK8s bool, provider string) {
	// hostRoot is the host filesystem mount point used when running as a
	// DaemonSet (e.g. /hostfs). Falls back to empty string so that paths
	// are checked directly when running outside a container.
	hostRoot := os.Getenv("TELEMETRYFLOW_HOST_ROOT")

	hostStat := func(path string) bool {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if hostRoot != "" {
			if _, err := os.Stat(hostRoot + path); err == nil {
				return true
			}
		}
		return false
	}

	// === Managed Cloud Providers ===

	// EKS (Amazon Elastic Kubernetes Service)
	if os.Getenv("AWS_REGION") != "" || os.Getenv("EKS_CLUSTER_NAME") != "" {
		return true, "eks"
	}
	// GKE (Google Kubernetes Engine)
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" || os.Getenv("GKE_CLUSTER_NAME") != "" {
		return true, "gke"
	}
	// AKS (Azure Kubernetes Service)
	if os.Getenv("AKS_CLUSTER_NAME") != "" || os.Getenv("AZURE_SUBSCRIPTION_ID") != "" {
		return true, "aks"
	}
	// ACK (Alibaba Cloud Container Service for Kubernetes)
	if os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID") != "" || os.Getenv("ACK_CLUSTER_ID") != "" {
		return true, "ack"
	}
	// CCE (Huawei Cloud Container Engine)
	if os.Getenv("HUAWEICLOUD_SDK_TYPE") != "" || os.Getenv("CCE_CLUSTER_ID") != "" {
		return true, "cce"
	}

	// === OpenShift Variants (MicroShift first — it's a subset of OpenShift) ===

	if hostStat("/var/lib/microshift") {
		return true, "microshift"
	}
	if os.Getenv("OPENSHIFT_BUILD_NAMESPACE") != "" || os.Getenv("OPENSHIFT_DEPLOYMENT_NAME") != "" ||
		hostStat("/etc/openshift") {
		return true, "openshift"
	}
	// OKD (community OpenShift)
	if os.Getenv("OKD_CLUSTER") != "" || hostStat("/etc/okd") {
		return true, "okd"
	}

	// === Lightweight / Local Distributions ===

	// k3s (must be checked before generic Rancher — k3s lives under /var/lib/rancher/k3s)
	if hostStat("/var/lib/rancher/k3s") {
		return true, "k3s"
	}
	// Rancher (RKE / RKE2) — CATTLE_* vars are injected by Rancher into pods
	if os.Getenv("CATTLE_CLUSTER_AGENT_PORT") != "" || os.Getenv("CATTLE_SERVER") != "" ||
		hostStat("/var/lib/rancher/rke2") || hostStat("/var/lib/rancher") {
		return true, "rancher"
	}
	// minikube
	if os.Getenv("MINIKUBE_ACTIVE_DOCKERD") != "" || os.Getenv("MINIKUBE_HOME") != "" {
		return true, "minikube"
	}
	// KIND (Kubernetes IN Docker)
	if os.Getenv("KIND_CLUSTER_NAME") != "" {
		return true, "kind"
	}

	// === Platform Distributions ===

	if os.Getenv("KUBESPHERE_NAMESPACE") != "" {
		return true, "kubesphere"
	}

	// === Generic in-cluster fallback ===
	// KUBERNETES_SERVICE_HOST is injected by the kubelet into every pod.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true, "self-managed"
	}

	return false, ""
}

// detectContainer checks if running inside a container
func detectContainer() bool {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check cgroup for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "containerd") ||
			strings.Contains(content, "cri-o") {
			return true
		}
	}

	// Check for Kubernetes
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	return false
}

// getContainerID returns the container ID if running in a container
func getContainerID() string {
	// Try to get from cgroup
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				// Container IDs are typically 64-char hex strings
				if len(last) == 64 {
					return last
				}
				// Docker format: docker-<id>.scope
				if strings.HasPrefix(last, "docker-") {
					return strings.TrimSuffix(strings.TrimPrefix(last, "docker-"), ".scope")
				}
			}
		}
	}

	// Try hostname (often container ID in Docker)
	if hostname, err := os.Hostname(); err == nil && len(hostname) == 12 {
		return hostname
	}

	return ""
}

// detectContainerRuntime detects the container runtime
func detectContainerRuntime() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}

	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "containerd") {
			return "containerd"
		}
		if strings.Contains(content, "cri-o") {
			return "cri-o"
		}
		if strings.Contains(content, "docker") {
			return "docker"
		}
	}

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes"
	}

	return ""
}

// detectVirtualization detects if running in a VM and the type
func detectVirtualization() (bool, string) {
	// Check DMI/SMBIOS info on Linux
	if runtime.GOOS == "linux" {
		paths := []string{
			"/sys/class/dmi/id/product_name",
			"/sys/class/dmi/id/sys_vendor",
			"/sys/class/dmi/id/board_vendor",
		}

		for _, path := range paths {
			// #nosec G304 -- paths are hardcoded system paths for virtualization detection
			if data, err := os.ReadFile(path); err == nil {
				content := strings.ToLower(string(data))
				if strings.Contains(content, "vmware") {
					return true, "vmware"
				}
				if strings.Contains(content, "virtualbox") {
					return true, "virtualbox"
				}
				if strings.Contains(content, "kvm") || strings.Contains(content, "qemu") {
					return true, "kvm"
				}
				if strings.Contains(content, "xen") {
					return true, "xen"
				}
				if strings.Contains(content, "hyper-v") || strings.Contains(content, "microsoft") {
					return true, "hyper-v"
				}
				if strings.Contains(content, "amazon ec2") {
					return true, "aws"
				}
				if strings.Contains(content, "google") {
					return true, "gcp"
				}
			}
		}

		// Check for hypervisor flag in /proc/cpuinfo
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			if strings.Contains(string(data), "hypervisor") {
				return true, "unknown"
			}
		}
	}

	return false, ""
}

// imdsClient is a short-timeout HTTP client for cloud metadata services.
var imdsClient = &http.Client{Timeout: 2 * time.Second}

// imdsGet fetches a single metadata value. Returns empty string on any failure.
func imdsGet(url string, headers map[string]string) string {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := imdsClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// fetchAWSIMDS queries EC2 Instance Metadata Service (IMDSv2 with fallback to v1).
func fetchAWSIMDS() (instanceID, instanceType, region, zone string) {
	// Try IMDSv2 first (token-based)
	tokenReq, _ := http.NewRequest(http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if tokenReq != nil {
		tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
		tokenResp, err := imdsClient.Do(tokenReq)
		var headers map[string]string
		if err == nil && tokenResp.StatusCode == http.StatusOK {
			tokenBody, _ := io.ReadAll(io.LimitReader(tokenResp.Body, 256))
			_ = tokenResp.Body.Close()
			token := strings.TrimSpace(string(tokenBody))
			headers = map[string]string{"X-aws-ec2-metadata-token": token}
		} else {
			if tokenResp != nil {
				_ = tokenResp.Body.Close()
			}
			// Fall back to IMDSv1 (no token header)
			headers = nil
		}

		const base = "http://169.254.169.254/latest/meta-data/"
		instanceID = imdsGet(base+"instance-id", headers)
		instanceType = imdsGet(base+"instance-type", headers)
		zone = imdsGet(base+"placement/availability-zone", headers)
		if zone != "" && len(zone) > 1 {
			// Region = zone minus the trailing letter (e.g. us-east-2a → us-east-2)
			region = zone[:len(zone)-1]
		}
	}
	return
}

// fetchGCPIMDS queries Google Compute Engine metadata server.
func fetchGCPIMDS() (instanceID, instanceType, region, zone string) {
	headers := map[string]string{"Metadata-Flavor": "Google"}
	const base = "http://metadata.google.internal/computeMetadata/v1/instance/"

	instanceID = imdsGet(base+"id", headers)
	// Returns e.g. "projects/123/machineTypes/e2-medium" — extract last segment
	machineType := imdsGet(base+"machine-type", headers)
	if parts := strings.Split(machineType, "/"); len(parts) > 0 {
		instanceType = parts[len(parts)-1]
	}
	// Returns e.g. "projects/123/zones/us-central1-a" — extract last segment
	fullZone := imdsGet(base+"zone", headers)
	if parts := strings.Split(fullZone, "/"); len(parts) > 0 {
		zone = parts[len(parts)-1]
	}
	if zone != "" {
		// Region = zone minus last "-X" segment (e.g. us-central1-a → us-central1)
		if idx := strings.LastIndex(zone, "-"); idx > 0 {
			region = zone[:idx]
		}
	}
	return
}

// azureInstanceMetadata holds the subset of Azure IMDS response we need.
type azureInstanceMetadata struct {
	Compute struct {
		VMId     string `json:"vmId"`
		VMSize   string `json:"vmSize"`
		Location string `json:"location"`
		Zone     string `json:"zone"`
	} `json:"compute"`
}

// fetchAzureIMDS queries Azure Instance Metadata Service.
func fetchAzureIMDS() (instanceID, instanceType, region, zone string) {
	url := "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Metadata", "true")
	resp, err := imdsClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return
	}
	var meta azureInstanceMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return
	}
	instanceID = meta.Compute.VMId
	instanceType = meta.Compute.VMSize
	region = meta.Compute.Location
	zone = fmt.Sprintf("%s-%s", meta.Compute.Location, meta.Compute.Zone)
	if meta.Compute.Zone == "" {
		zone = ""
	}
	return
}

// fetchAlibabaIMDS queries Alibaba Cloud (Aliyun) ECS metadata server.
// Endpoint: 100.100.100.200 (different from the standard 169.254.169.254 link-local).
func fetchAlibabaIMDS() (instanceID, instanceType, region, zone string) {
	const base = "http://100.100.100.200/latest/meta-data/"
	instanceID = imdsGet(base+"instance-id", nil)
	instanceType = imdsGet(base+"instance/instance-type", nil)
	region = imdsGet(base+"region-id", nil)
	zone = imdsGet(base+"zone-id", nil)
	return
}

// fetchHuaweiIMDS queries Huawei Cloud ECS metadata server (OpenStack-compatible).
func fetchHuaweiIMDS() (instanceID, instanceType, region, zone string) {
	const base = "http://169.254.169.254/openstack/latest/meta_data.json"
	req, err := http.NewRequest(http.MethodGet, base, nil)
	if err != nil {
		return
	}
	resp, err := imdsClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return
	}
	var meta struct {
		UUID             string `json:"uuid"`
		AvailabilityZone string `json:"availability_zone"`
		Meta             struct {
			MeteringInstanceType string `json:"metering.instance_type"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return
	}
	instanceID = meta.UUID
	instanceType = meta.Meta.MeteringInstanceType
	zone = meta.AvailabilityZone
	// Huawei zone format: "xx-xxxx-N[a]" (e.g. cn-north-4a) — region = zone minus trailing letter
	if zone != "" {
		region = zone
		last := zone[len(zone)-1]
		if last >= 'a' && last <= 'z' {
			region = zone[:len(zone)-1]
		}
	}
	return
}

// fetchDigitalOceanIMDS queries DigitalOcean Droplet metadata service.
func fetchDigitalOceanIMDS() (instanceID, instanceType, region, zone string) {
	const base = "http://169.254.169.254/metadata/v1/"
	instanceID = imdsGet(base+"id", nil)
	// DO calls it "size" (e.g. "s-1vcpu-1gb", "s-2vcpu-4gb")
	instanceType = imdsGet(base+"dns/hostname", nil)
	doRegion := imdsGet(base+"region", nil)
	region = doRegion
	zone = doRegion // DO regions are single-zone (e.g. "nyc1", "sfo3")

	// Prefer the slug from interfaces/public/0/type or the size field
	if size := imdsGet(base+"size", nil); size != "" {
		instanceType = size
	}
	return
}

// detectCloudMetadata attempts to detect cloud provider and instance metadata
// by checking host filesystem markers and querying the provider's IMDS endpoint.
func detectCloudMetadata() (provider, instanceID, instanceType, region, zone string) {
	// hostRoot is the mount point for the host filesystem inside the container.
	// DaemonSet mounts host / → /host/root and sets TELEMETRYFLOW_HOST_ROOT=/host/root.
	// k8s-collector Deployment mounts host / → /hostfs and sets TELEMETRYFLOW_HOST_ROOT=/hostfs.
	// Falls back to empty string (direct paths) when running outside a container.
	hostRoot := os.Getenv("TELEMETRYFLOW_HOST_ROOT")

	// hostStat checks the path directly and, if that fails, prefixed by hostRoot.
	hostStat := func(path string) bool {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if hostRoot != "" {
			if _, err := os.Stat(hostRoot + path); err == nil {
				return true
			}
		}
		return false
	}

	// ---- Rancher / RKE / RKE2 / k3s detection (no IMDS) ----
	// CATTLE_* vars are injected by Rancher into pods in the cattle-system namespace.
	if os.Getenv("CATTLE_CLUSTER_AGENT_PORT") != "" || os.Getenv("CATTLE_SERVER") != "" {
		provider = "rancher"
		return
	}
	if hostStat("/var/lib/rancher/k3s") {
		provider = "k3s"
		return
	}
	if hostStat("/var/lib/rancher/rke2") {
		provider = "rancher"
		return
	}
	if hostStat("/var/lib/rancher") {
		provider = "rancher"
		return
	}

	// ---- AWS detection + IMDS ----
	isAWS := false
	if hostStat("/sys/hypervisor/uuid") {
		if data, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil {
			if strings.HasPrefix(strings.ToLower(string(data)), "ec2") {
				isAWS = true
			}
		}
	}
	if os.Getenv("AWS_REGION") != "" {
		isAWS = true
	}
	if isAWS {
		provider = "aws"
		instanceID, instanceType, region, zone = fetchAWSIMDS()
		// Fallback region from env if IMDS didn't return one
		if region == "" {
			region = os.Getenv("AWS_REGION")
		}
		return
	}

	// ---- GCP detection + IMDS ----
	isGCP := false
	for _, p := range []string{"/sys/class/dmi/id/product_name", hostRoot + "/sys/class/dmi/id/product_name"} {
		if data, err := os.ReadFile(p); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "google") {
				isGCP = true
			}
			break
		}
	}
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" {
		isGCP = true
	}
	if isGCP {
		provider = "gcp"
		instanceID, instanceType, region, zone = fetchGCPIMDS()
		return
	}

	// ---- Azure detection + IMDS ----
	isAzure := false
	for _, p := range []string{"/sys/class/dmi/id/sys_vendor", hostRoot + "/sys/class/dmi/id/sys_vendor"} {
		if data, err := os.ReadFile(p); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "microsoft") {
				isAzure = true
			}
			break
		}
	}
	if isAzure {
		provider = "azure"
		instanceID, instanceType, region, zone = fetchAzureIMDS()
		return
	}

	// ---- Alibaba Cloud (Aliyun) detection + IMDS ----
	// Alibaba ECS uses a unique IMDS IP: 100.100.100.200.
	// DMI product_name contains "Alibaba" on ECS instances.
	isAlibaba := false
	for _, p := range []string{"/sys/class/dmi/id/product_name", hostRoot + "/sys/class/dmi/id/product_name"} {
		if data, err := os.ReadFile(p); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "alibaba") {
				isAlibaba = true
			}
			break
		}
	}
	if os.Getenv("ALIBABA_CLOUD_REGION_ID") != "" || os.Getenv("ALICLOUD_REGION") != "" {
		isAlibaba = true
	}
	if isAlibaba {
		provider = "alibaba"
		instanceID, instanceType, region, zone = fetchAlibabaIMDS()
		if region == "" {
			region = os.Getenv("ALIBABA_CLOUD_REGION_ID")
			if region == "" {
				region = os.Getenv("ALICLOUD_REGION")
			}
		}
		return
	}

	// ---- Huawei Cloud detection + IMDS ----
	// Huawei ECS sys_vendor contains "HUAWEI".
	isHuawei := false
	for _, p := range []string{"/sys/class/dmi/id/sys_vendor", hostRoot + "/sys/class/dmi/id/sys_vendor"} {
		if data, err := os.ReadFile(p); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "huawei") {
				isHuawei = true
			}
			break
		}
	}
	if os.Getenv("HUAWEICLOUD_REGION") != "" {
		isHuawei = true
	}
	if isHuawei {
		provider = "huawei"
		instanceID, instanceType, region, zone = fetchHuaweiIMDS()
		if region == "" {
			region = os.Getenv("HUAWEICLOUD_REGION")
		}
		return
	}

	// ---- DigitalOcean detection + IMDS ----
	// DO Droplets have sys_vendor "DigitalOcean".
	isDO := false
	for _, p := range []string{"/sys/class/dmi/id/sys_vendor", hostRoot + "/sys/class/dmi/id/sys_vendor"} {
		if data, err := os.ReadFile(p); err == nil {
			if strings.Contains(strings.ToLower(string(data)), "digitalocean") {
				isDO = true
			}
			break
		}
	}
	if os.Getenv("DIGITALOCEAN_TOKEN") != "" || os.Getenv("DO_REGION") != "" {
		isDO = true
	}
	if isDO {
		provider = "digitalocean"
		instanceID, instanceType, region, zone = fetchDigitalOceanIMDS()
		return
	}

	return
}

// GetSystemInfoStatic is a package-level function to get system info without a collector
// Uses internal cache for reliability during transient collection failures
func GetSystemInfoStatic() (*collector.SystemInfo, error) {
	// Try to get from cache first for reliability
	if cached := infoCache.getCached(); cached != nil {
		return cached, nil
	}

	c := NewHostCollector(HostCollectorConfig{})
	info, err := c.GetSystemInfo()
	if err != nil {
		// On error, try to return stale cache if available
		if cached := infoCache.info; cached != nil {
			return cached, nil
		}
		return nil, err
	}
	return info, nil
}

// GetSystemInfoWithFallback returns system info with cache fallback on error
func GetSystemInfoWithFallback() *collector.SystemInfo {
	info, err := GetSystemInfoStatic()
	if err != nil || info == nil {
		// Return cached even if stale
		if infoCache.info != nil {
			return infoCache.info
		}
		// Return minimal info on complete failure
		return &collector.SystemInfo{
			Hostname: getHostnameFallback(),
		}
	}
	return info
}

// getHostnameFallback gets hostname with fallback
func getHostnameFallback() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}

// getContainerName returns the container name from environment variables
func getContainerName() string {
	// Check common environment variables for container name
	// Kubernetes sets HOSTNAME to pod name
	if name := os.Getenv("CONTAINER_NAME"); name != "" {
		return name
	}
	// Docker Compose sets COMPOSE_PROJECT_NAME and service name
	if project := os.Getenv("COMPOSE_PROJECT_NAME"); project != "" {
		if service := os.Getenv("COMPOSE_SERVICE"); service != "" {
			return project + "_" + service
		}
	}
	// Kubernetes pod name
	if podName := os.Getenv("POD_NAME"); podName != "" {
		return podName
	}
	// Try to get from Docker environment
	if name := os.Getenv("DOCKER_CONTAINER_NAME"); name != "" {
		return name
	}
	return ""
}

// getContainerImage returns the container image from environment variables
func getContainerImage() string {
	// Check common environment variables for container image
	if image := os.Getenv("CONTAINER_IMAGE"); image != "" {
		return image
	}
	// Kubernetes commonly uses this downward API field
	if image := os.Getenv("POD_IMAGE"); image != "" {
		return image
	}
	// Docker environment variable
	if image := os.Getenv("DOCKER_IMAGE"); image != "" {
		return image
	}
	return ""
}
