// Package system provides comprehensive system metrics collection.
package system

import (
	"context"
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
	}

	// ==========================================================================
	// Container/Virtualization Detection
	// ==========================================================================
	info.IsContainer = detectContainer()
	if info.IsContainer {
		info.ContainerID = getContainerID()
		info.ContainerRuntime = detectContainerRuntime()
	}

	info.IsVirtualized, info.VirtualizationType = detectVirtualization()

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

// detectCloudMetadata attempts to detect cloud provider and instance metadata
func detectCloudMetadata() (provider, instanceID, instanceType, region, zone string) {
	// AWS detection
	if _, err := os.Stat("/sys/hypervisor/uuid"); err == nil {
		if data, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil {
			if strings.HasPrefix(strings.ToLower(string(data)), "ec2") {
				provider = "aws"
			}
		}
	}
	if os.Getenv("AWS_REGION") != "" {
		provider = "aws"
		region = os.Getenv("AWS_REGION")
	}

	// GCP detection
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "google") {
			provider = "gcp"
		}
	}
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" {
		provider = "gcp"
	}

	// Azure detection
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "microsoft") {
			provider = "azure"
		}
	}

	return provider, instanceID, instanceType, region, zone
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
