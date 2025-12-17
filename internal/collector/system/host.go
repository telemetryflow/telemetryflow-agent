// Package system provides system metrics collection.
package system

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

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

// GetSystemInfo returns current system information for heartbeat
func (c *HostCollector) GetSystemInfo() (*collector.SystemInfo, error) {
	info := &collector.SystemInfo{}

	// Host info
	hostInfo, err := host.Info()
	if err == nil {
		info.Hostname = hostInfo.Hostname
		info.OS = hostInfo.OS
		info.OSVersion = hostInfo.PlatformVersion
		info.KernelVersion = hostInfo.KernelVersion
		info.Architecture = hostInfo.KernelArch
		info.Uptime = hostInfo.Uptime
	}

	// CPU info
	cpuInfo, err := cpu.Info()
	if err == nil && len(cpuInfo) > 0 {
		info.CPUModel = cpuInfo[0].ModelName
	}
	cores, err := cpu.Counts(true)
	if err == nil {
		info.CPUCores = cores
	}
	percentages, err := cpu.Percent(time.Second, false)
	if err == nil && len(percentages) > 0 {
		info.CPUUsage = percentages[0]
	}

	// Memory info
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		info.MemoryTotal = memInfo.Total
		info.MemoryUsed = memInfo.Used
		info.MemoryAvailable = memInfo.Available
		info.MemoryUsage = memInfo.UsedPercent
	}

	// Disk info (root partition)
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
	}

	// Network info
	netCounters, err := net.IOCounters(false)
	if err == nil && len(netCounters) > 0 {
		info.NetworkBytesSent = netCounters[0].BytesSent
		info.NetworkBytesRecv = netCounters[0].BytesRecv
	}

	return info, nil
}

// GetSystemInfoStatic is a package-level function to get system info without a collector
func GetSystemInfoStatic() (*collector.SystemInfo, error) {
	c := NewHostCollector(HostCollectorConfig{})
	return c.GetSystemInfo()
}
