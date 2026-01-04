// Package collector defines the interface for telemetry collectors.
package collector

import (
	"context"
	"time"
)

// Collector is the interface that all collectors must implement
type Collector interface {
	// Name returns the collector name
	Name() string

	// Start starts the collector and begins collecting metrics
	Start(ctx context.Context) error

	// Stop gracefully stops the collector
	Stop() error

	// Collect performs a single collection cycle
	Collect(ctx context.Context) ([]Metric, error)

	// IsRunning returns whether the collector is running
	IsRunning() bool
}

// Metric represents a collected metric
type Metric struct {
	// Name is the metric name
	Name string `json:"name"`

	// Description is a human-readable description
	Description string `json:"description,omitempty"`

	// Type is the metric type (gauge, counter, histogram)
	Type MetricType `json:"type"`

	// Value is the metric value
	Value float64 `json:"value"`

	// Timestamp is when the metric was collected
	Timestamp time.Time `json:"timestamp"`

	// Labels are key-value pairs for dimensions
	Labels map[string]string `json:"labels,omitempty"`

	// Unit is the metric unit (bytes, percent, seconds, etc.)
	Unit string `json:"unit,omitempty"`
}

// MetricType represents the type of metric
type MetricType string

const (
	// MetricTypeGauge is a gauge metric (can go up or down)
	MetricTypeGauge MetricType = "gauge"

	// MetricTypeCounter is a counter metric (monotonically increasing)
	MetricTypeCounter MetricType = "counter"

	// MetricTypeHistogram is a histogram metric
	MetricTypeHistogram MetricType = "histogram"

	// MetricTypeSummary is a summary metric
	MetricTypeSummary MetricType = "summary"
)

// SystemInfo contains comprehensive system information for heartbeat
type SystemInfo struct {
	// ==========================================================================
	// Host Information
	// ==========================================================================
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	OSVersion      string `json:"osVersion,omitempty"`
	Platform       string `json:"platform,omitempty"`       // linux, darwin, windows
	PlatformFamily string `json:"platformFamily,omitempty"` // debian, rhel, etc.
	KernelVersion  string `json:"kernelVersion,omitempty"`
	Architecture   string `json:"architecture"`
	Uptime         uint64 `json:"uptime"`
	BootTime       uint64 `json:"bootTime,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	HostID         string `json:"hostId,omitempty"` // Unique host identifier

	// ==========================================================================
	// CPU Information
	// ==========================================================================
	CPUCores          int     `json:"cpuCores"`
	CPULogicalCores   int     `json:"cpuLogicalCores,omitempty"`
	CPUPhysicalCores  int     `json:"cpuPhysicalCores,omitempty"`
	CPUModel          string  `json:"cpuModel,omitempty"`
	CPUVendor         string  `json:"cpuVendor,omitempty"`
	CPUFamily         string  `json:"cpuFamily,omitempty"`
	CPUMhz            float64 `json:"cpuMhz,omitempty"`
	CPUCacheSize      int32   `json:"cpuCacheSize,omitempty"` // KB
	CPUUsage          float64 `json:"cpuUsage"`               // Total CPU usage %
	CPUUserPercent    float64 `json:"cpuUserPercent,omitempty"`
	CPUSystemPercent  float64 `json:"cpuSystemPercent,omitempty"`
	CPUIdlePercent    float64 `json:"cpuIdlePercent,omitempty"`
	CPUIOWaitPercent  float64 `json:"cpuIowaitPercent,omitempty"`  // Linux only
	CPUStealPercent   float64 `json:"cpuStealPercent,omitempty"`   // Virtualized env
	CPUGuestPercent   float64 `json:"cpuGuestPercent,omitempty"`   // VM host
	CPUIrqPercent     float64 `json:"cpuIrqPercent,omitempty"`     // Hardware IRQ
	CPUSoftIrqPercent float64 `json:"cpuSoftirqPercent,omitempty"` // Software IRQ
	CPUNicePercent    float64 `json:"cpuNicePercent,omitempty"`    // Nice priority

	// Load averages (Unix-like systems)
	LoadAvg1  float64 `json:"loadAvg1,omitempty"`
	LoadAvg5  float64 `json:"loadAvg5,omitempty"`
	LoadAvg15 float64 `json:"loadAvg15,omitempty"`

	// CPU Per-Core (optional detailed breakdown)
	CPUPerCore []CPUCoreInfo `json:"cpuPerCore,omitempty"`

	// ==========================================================================
	// Memory Information
	// ==========================================================================
	MemoryTotal       uint64  `json:"memoryTotal"`
	MemoryUsed        uint64  `json:"memoryUsed"`
	MemoryAvailable   uint64  `json:"memoryAvailable"`
	MemoryFree        uint64  `json:"memoryFree,omitempty"`
	MemoryUsage       float64 `json:"memoryUsage"`
	MemoryCached      uint64  `json:"memoryCached,omitempty"`      // Linux page cache
	MemoryBuffers     uint64  `json:"memoryBuffers,omitempty"`     // Linux buffers
	MemoryActive      uint64  `json:"memoryActive,omitempty"`      // Recently used
	MemoryInactive    uint64  `json:"memoryInactive,omitempty"`    // Not recently used
	MemoryWired       uint64  `json:"memoryWired,omitempty"`       // macOS wired
	MemoryShared      uint64  `json:"memoryShared,omitempty"`      // Shared memory
	MemorySlab        uint64  `json:"memorySlab,omitempty"`        // Kernel slab
	MemoryPageTables  uint64  `json:"memoryPageTables,omitempty"`  // Page table entries
	MemoryCommitted   uint64  `json:"memoryCommitted,omitempty"`   // Committed AS
	MemoryCommitLimit uint64  `json:"memoryCommitLimit,omitempty"` // Commit limit
	MemoryDirty       uint64  `json:"memoryDirty,omitempty"`       // Dirty pages
	MemoryWriteback   uint64  `json:"memoryWriteback,omitempty"`   // Pages being written

	// Swap/Virtual Memory
	SwapTotal uint64  `json:"swapTotal,omitempty"`
	SwapUsed  uint64  `json:"swapUsed,omitempty"`
	SwapFree  uint64  `json:"swapFree,omitempty"`
	SwapUsage float64 `json:"swapUsage,omitempty"`
	SwapIn    uint64  `json:"swapIn,omitempty"`  // Pages swapped in
	SwapOut   uint64  `json:"swapOut,omitempty"` // Pages swapped out

	// Page faults
	PageFaultsMajor uint64 `json:"pageFaultsMajor,omitempty"` // Disk access required
	PageFaultsMinor uint64 `json:"pageFaultsMinor,omitempty"` // No disk access

	// ==========================================================================
	// Disk Information
	// ==========================================================================
	DiskTotal       uint64  `json:"diskTotal"`
	DiskUsed        uint64  `json:"diskUsed"`
	DiskAvailable   uint64  `json:"diskAvailable"`
	DiskUsage       float64 `json:"diskUsage"`
	DiskInodes      uint64  `json:"diskInodes,omitempty"`
	DiskInodesFree  uint64  `json:"diskInodesFree,omitempty"`
	DiskInodesUsed  uint64  `json:"diskInodesUsed,omitempty"`
	DiskInodesUsage float64 `json:"diskInodesUsage,omitempty"`

	// Disk I/O metrics
	DiskReadBytes    uint64  `json:"diskReadBytes,omitempty"`
	DiskWriteBytes   uint64  `json:"diskWriteBytes,omitempty"`
	DiskReadOps      uint64  `json:"diskReadOps,omitempty"`      // Read operations
	DiskWriteOps     uint64  `json:"diskWriteOps,omitempty"`     // Write operations
	DiskReadTime     uint64  `json:"diskReadTime,omitempty"`     // Time spent reading (ms)
	DiskWriteTime    uint64  `json:"diskWriteTime,omitempty"`    // Time spent writing (ms)
	DiskIOTime       uint64  `json:"diskIoTime,omitempty"`       // Time spent in I/O (ms)
	DiskWeightedIO   uint64  `json:"diskWeightedIo,omitempty"`   // Weighted I/O time
	DiskIOInProgress uint64  `json:"diskIoInProgress,omitempty"` // Current I/O operations
	DiskIOPS         float64 `json:"diskIops,omitempty"`         // Calculated IOPS
	DiskLatencyRead  float64 `json:"diskLatencyRead,omitempty"`  // Avg read latency (ms)
	DiskLatencyWrite float64 `json:"diskLatencyWrite,omitempty"` // Avg write latency (ms)

	// Per-partition metrics
	DiskPartitions []DiskPartitionInfo `json:"diskPartitions,omitempty"`

	// ==========================================================================
	// Network Information
	// ==========================================================================
	NetworkBytesSent     uint64  `json:"networkBytesSent,omitempty"`
	NetworkBytesRecv     uint64  `json:"networkBytesRecv,omitempty"`
	NetworkPacketsSent   uint64  `json:"networkPacketsSent,omitempty"`
	NetworkPacketsRecv   uint64  `json:"networkPacketsRecv,omitempty"`
	NetworkErrorsIn      uint64  `json:"networkErrorsIn,omitempty"`
	NetworkErrorsOut     uint64  `json:"networkErrorsOut,omitempty"`
	NetworkDropsIn       uint64  `json:"networkDropsIn,omitempty"`
	NetworkDropsOut      uint64  `json:"networkDropsOut,omitempty"`
	NetworkFifoIn        uint64  `json:"networkFifoIn,omitempty"`
	NetworkFifoOut       uint64  `json:"networkFifoOut,omitempty"`
	NetworkBytesSentRate float64 `json:"networkBytesSentRate,omitempty"` // bytes/sec
	NetworkBytesRecvRate float64 `json:"networkBytesRecvRate,omitempty"` // bytes/sec

	// TCP Connection States
	TCPConnectionsEstablished uint32 `json:"tcpConnectionsEstablished,omitempty"`
	TCPConnectionsTimeWait    uint32 `json:"tcpConnectionsTimeWait,omitempty"`
	TCPConnectionsCloseWait   uint32 `json:"tcpConnectionsCloseWait,omitempty"`
	TCPConnectionsListen      uint32 `json:"tcpConnectionsListen,omitempty"`
	TCPConnectionsSynSent     uint32 `json:"tcpConnectionsSynSent,omitempty"`
	TCPConnectionsSynRecv     uint32 `json:"tcpConnectionsSynRecv,omitempty"`
	TCPConnectionsFinWait1    uint32 `json:"tcpConnectionsFinWait1,omitempty"`
	TCPConnectionsFinWait2    uint32 `json:"tcpConnectionsFinWait2,omitempty"`
	TCPConnectionsLastAck     uint32 `json:"tcpConnectionsLastAck,omitempty"`
	TCPConnectionsClosing     uint32 `json:"tcpConnectionsClosing,omitempty"`
	TCPRetransmits            uint64 `json:"tcpRetransmits,omitempty"`

	// Per-interface metrics
	NetworkInterfaces []NetworkInterfaceInfo `json:"networkInterfaces,omitempty"`

	// ==========================================================================
	// Process Information
	// ==========================================================================
	ProcessCount    uint64 `json:"processCount,omitempty"`
	ProcessRunning  uint64 `json:"processRunning,omitempty"`
	ProcessSleeping uint64 `json:"processSleeping,omitempty"`
	ProcessStopped  uint64 `json:"processStopped,omitempty"`
	ProcessZombie   uint64 `json:"processZombie,omitempty"`
	ProcessBlocked  uint64 `json:"processBlocked,omitempty"`
	ThreadCount     uint64 `json:"threadCount,omitempty"`
	ContextSwitches uint64 `json:"contextSwitches,omitempty"`
	Interrupts      uint64 `json:"interrupts,omitempty"`
	SoftInterrupts  uint64 `json:"softInterrupts,omitempty"`
	SystemCalls     uint64 `json:"systemCalls,omitempty"`

	// ==========================================================================
	// System Resources
	// ==========================================================================
	OpenFileDescriptors  uint64  `json:"openFileDescriptors,omitempty"`
	MaxFileDescriptors   uint64  `json:"maxFileDescriptors,omitempty"`
	FileDescriptorsUsage float64 `json:"fileDescriptorsUsage,omitempty"`
	EntropyAvailable     uint64  `json:"entropyAvailable,omitempty"` // /proc/sys/kernel/random/entropy_avail

	// ==========================================================================
	// Container/Virtualization Detection
	// ==========================================================================
	IsContainer        bool   `json:"isContainer,omitempty"`
	ContainerID        string `json:"containerId,omitempty"`
	ContainerRuntime   string `json:"containerRuntime,omitempty"` // docker, containerd, cri-o
	ContainerName      string `json:"containerName,omitempty"`
	ContainerImage     string `json:"containerImage,omitempty"`
	IsVirtualized      bool   `json:"isVirtualized,omitempty"`
	VirtualizationType string `json:"virtualizationType,omitempty"` // kvm, vmware, xen, etc.
	CloudProvider      string `json:"cloudProvider,omitempty"`      // aws, gcp, azure, etc.
	CloudInstanceID    string `json:"cloudInstanceId,omitempty"`
	CloudInstanceType  string `json:"cloudInstanceType,omitempty"`
	CloudRegion        string `json:"cloudRegion,omitempty"`
	CloudZone          string `json:"cloudZone,omitempty"`

	// ==========================================================================
	// Agent Metadata
	// ==========================================================================
	AgentVersion       string `json:"agentVersion,omitempty"`
	AgentStartTime     uint64 `json:"agentStartTime,omitempty"`
	AgentUptime        uint64 `json:"agentUptime,omitempty"`
	CollectionTime     int64  `json:"collectionTime,omitempty"`     // Unix timestamp
	CollectionDuration int64  `json:"collectionDuration,omitempty"` // Nanoseconds
}

// CPUCoreInfo contains per-core CPU information
type CPUCoreInfo struct {
	CoreID        int     `json:"coreId"`
	Usage         float64 `json:"usage"`
	UserPercent   float64 `json:"userPercent,omitempty"`
	SystemPercent float64 `json:"systemPercent,omitempty"`
	IdlePercent   float64 `json:"idlePercent,omitempty"`
}

// DiskPartitionInfo contains per-partition disk information
type DiskPartitionInfo struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	Usage       float64 `json:"usage"`
	Inodes      uint64  `json:"inodes,omitempty"`
	InodesFree  uint64  `json:"inodesFree,omitempty"`
	InodesUsage float64 `json:"inodesUsage,omitempty"`
}

// NetworkInterfaceInfo contains per-interface network information
type NetworkInterfaceInfo struct {
	Name        string   `json:"name"`
	MacAddress  string   `json:"macAddress,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
	Speed       uint64   `json:"speed,omitempty"` // Mbps
	IsUp        bool     `json:"isUp"`
	IsLoopback  bool     `json:"isLoopback"`
	BytesSent   uint64   `json:"bytesSent"`
	BytesRecv   uint64   `json:"bytesRecv"`
	PacketsSent uint64   `json:"packetsSent"`
	PacketsRecv uint64   `json:"packetsRecv"`
	ErrorsIn    uint64   `json:"errorsIn"`
	ErrorsOut   uint64   `json:"errorsOut"`
	DropsIn     uint64   `json:"dropsIn"`
	DropsOut    uint64   `json:"dropsOut"`
}

// MetricBatch represents a batch of metrics for export
type MetricBatch struct {
	// Metrics is the list of metrics
	Metrics []Metric `json:"metrics"`

	// CollectedAt is when the batch was created
	CollectedAt time.Time `json:"collectedAt"`

	// AgentID is the agent that collected the metrics
	AgentID string `json:"agentId"`

	// Hostname is the host where metrics were collected
	Hostname string `json:"hostname"`
}

// NewMetric creates a new metric with current timestamp
func NewMetric(name string, value float64, metricType MetricType) Metric {
	return Metric{
		Name:      name,
		Type:      metricType,
		Value:     value,
		Timestamp: time.Now(),
		Labels:    make(map[string]string),
	}
}

// WithLabels adds labels to a metric
func (m Metric) WithLabels(labels map[string]string) Metric {
	for k, v := range labels {
		m.Labels[k] = v
	}
	return m
}

// WithLabel adds a single label to a metric
func (m Metric) WithLabel(key, value string) Metric {
	if m.Labels == nil {
		m.Labels = make(map[string]string)
	}
	m.Labels[key] = value
	return m
}

// WithUnit sets the unit for a metric
func (m Metric) WithUnit(unit string) Metric {
	m.Unit = unit
	return m
}

// WithDescription sets the description for a metric
func (m Metric) WithDescription(desc string) Metric {
	m.Description = desc
	return m
}
