// Package exporter provides telemetry data export functionality.
package exporter

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

// HeartbeatClient defines the interface for sending heartbeats
type HeartbeatClient interface {
	Heartbeat(ctx context.Context, agentID string, sysInfo *api.SystemInfoPayload) error
}

// Heartbeat manages periodic heartbeat to the TelemetryFlow backend
type Heartbeat struct {
	config HeartbeatConfig
	logger *zap.Logger

	mu           sync.RWMutex
	running      bool
	stopChan     chan struct{}
	lastSent     time.Time
	lastError    error
	errorCount   int
	successCount int
}

// HeartbeatConfig contains heartbeat configuration
type HeartbeatConfig struct {
	// AgentID is the unique agent identifier
	AgentID string

	// Hostname is the agent hostname
	Hostname string

	// Interval is the heartbeat interval
	Interval time.Duration

	// Timeout is the request timeout
	Timeout time.Duration

	// IncludeSystemInfo includes system metrics in heartbeat
	IncludeSystemInfo bool

	// Client is the API client (implements HeartbeatClient interface)
	Client HeartbeatClient

	// Logger is the logger instance
	Logger *zap.Logger
}

// NewHeartbeat creates a new heartbeat exporter
func NewHeartbeat(cfg HeartbeatConfig) *Heartbeat {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	return &Heartbeat{
		config:   cfg,
		logger:   cfg.Logger,
		stopChan: make(chan struct{}),
	}
}

// Start starts the heartbeat loop
func (h *Heartbeat) Start(ctx context.Context) error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return nil
	}
	h.running = true
	h.stopChan = make(chan struct{})
	h.mu.Unlock()

	h.logger.Info("Starting heartbeat",
		zap.String("agentId", h.config.AgentID),
		zap.Duration("interval", h.config.Interval),
	)

	// Send initial heartbeat
	if err := h.sendHeartbeat(ctx); err != nil {
		h.logger.Warn("Initial heartbeat failed", zap.Error(err))
	}

	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.stopChan:
			return nil
		case <-ticker.C:
			if err := h.sendHeartbeat(ctx); err != nil {
				h.mu.Lock()
				h.lastError = err
				h.errorCount++
				errCount := h.errorCount
				h.mu.Unlock()
				h.logger.Warn("Heartbeat failed",
					zap.Error(err),
					zap.Int("errorCount", errCount),
				)
			} else {
				h.mu.Lock()
				h.lastSent = time.Now()
				h.successCount++
				h.lastError = nil
				h.mu.Unlock()
			}
		}
	}
}

// Stop stops the heartbeat loop
func (h *Heartbeat) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	close(h.stopChan)
	h.running = false
	h.logger.Info("Heartbeat stopped",
		zap.Int("successCount", h.successCount),
		zap.Int("errorCount", h.errorCount),
	)
	return nil
}

// IsRunning returns whether heartbeat is running
func (h *Heartbeat) IsRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

// Stats returns heartbeat statistics
func (h *Heartbeat) Stats() HeartbeatStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return HeartbeatStats{
		Running:      h.running,
		LastSent:     h.lastSent,
		LastError:    h.lastError,
		SuccessCount: h.successCount,
		ErrorCount:   h.errorCount,
	}
}

// HeartbeatStats contains heartbeat statistics
type HeartbeatStats struct {
	Running      bool      `json:"running"`
	LastSent     time.Time `json:"lastSent"`
	LastError    error     `json:"lastError,omitempty"`
	SuccessCount int       `json:"successCount"`
	ErrorCount   int       `json:"errorCount"`
}

// sendHeartbeat sends a single heartbeat
func (h *Heartbeat) sendHeartbeat(ctx context.Context) error {
	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, h.config.Timeout)
	defer cancel()

	var sysInfo *api.SystemInfoPayload

	// Collect system info if enabled
	if h.config.IncludeSystemInfo {
		info, err := system.GetSystemInfoStatic()
		if err != nil {
			h.logger.Debug("Failed to collect system info", zap.Error(err))
		} else {
			sysInfo = mapSystemInfoToPayload(info)
		}
	}

	// Send heartbeat
	err := h.config.Client.Heartbeat(ctx, h.config.AgentID, sysInfo)
	if err != nil {
		return err
	}

	h.logger.Debug("Heartbeat sent successfully",
		zap.String("agentId", h.config.AgentID),
	)

	return nil
}

// SendNow sends an immediate heartbeat
func (h *Heartbeat) SendNow(ctx context.Context) error {
	return h.sendHeartbeat(ctx)
}

// mapSystemInfoToPayload converts collector.SystemInfo to api.SystemInfoPayload
func mapSystemInfoToPayload(info *collector.SystemInfo) *api.SystemInfoPayload {
	if info == nil {
		return nil
	}

	payload := &api.SystemInfoPayload{
		// Host Information
		Hostname:       info.Hostname,
		OS:             info.OS,
		OSVersion:      info.OSVersion,
		Platform:       info.Platform,
		PlatformFamily: info.PlatformFamily,
		KernelVersion:  info.KernelVersion,
		Architecture:   info.Architecture,
		Uptime:         info.Uptime,
		BootTime:       info.BootTime,
		Timezone:       info.Timezone,
		HostID:         info.HostID,

		// CPU Information
		CPUCores:          info.CPUCores,
		CPULogicalCores:   info.CPULogicalCores,
		CPUPhysicalCores:  info.CPUPhysicalCores,
		CPUModel:          info.CPUModel,
		CPUVendor:         info.CPUVendor,
		CPUFamily:         info.CPUFamily,
		CPUMhz:            info.CPUMhz,
		CPUCacheSize:      info.CPUCacheSize,
		CPUUsage:          info.CPUUsage,
		CPUUserPercent:    info.CPUUserPercent,
		CPUSystemPercent:  info.CPUSystemPercent,
		CPUIdlePercent:    info.CPUIdlePercent,
		CPUIOWaitPercent:  info.CPUIOWaitPercent,
		CPUStealPercent:   info.CPUStealPercent,
		CPUGuestPercent:   info.CPUGuestPercent,
		CPUIrqPercent:     info.CPUIrqPercent,
		CPUSoftIrqPercent: info.CPUSoftIrqPercent,
		CPUNicePercent:    info.CPUNicePercent,
		LoadAvg1:          info.LoadAvg1,
		LoadAvg5:          info.LoadAvg5,
		LoadAvg15:         info.LoadAvg15,

		// Memory Information
		MemoryTotal:       info.MemoryTotal,
		MemoryUsed:        info.MemoryUsed,
		MemoryAvailable:   info.MemoryAvailable,
		MemoryFree:        info.MemoryFree,
		MemoryUsage:       info.MemoryUsage,
		MemoryCached:      info.MemoryCached,
		MemoryBuffers:     info.MemoryBuffers,
		MemoryActive:      info.MemoryActive,
		MemoryInactive:    info.MemoryInactive,
		MemoryWired:       info.MemoryWired,
		MemoryShared:      info.MemoryShared,
		MemorySlab:        info.MemorySlab,
		MemoryPageTables:  info.MemoryPageTables,
		MemoryCommitted:   info.MemoryCommitted,
		MemoryCommitLimit: info.MemoryCommitLimit,
		MemoryDirty:       info.MemoryDirty,
		MemoryWriteback:   info.MemoryWriteback,
		SwapTotal:         info.SwapTotal,
		SwapUsed:          info.SwapUsed,
		SwapFree:          info.SwapFree,
		SwapUsage:         info.SwapUsage,
		SwapIn:            info.SwapIn,
		SwapOut:           info.SwapOut,
		PageFaultsMajor:   info.PageFaultsMajor,
		PageFaultsMinor:   info.PageFaultsMinor,

		// Disk Information
		DiskTotal:        info.DiskTotal,
		DiskUsed:         info.DiskUsed,
		DiskAvailable:    info.DiskAvailable,
		DiskUsage:        info.DiskUsage,
		DiskInodes:       info.DiskInodes,
		DiskInodesFree:   info.DiskInodesFree,
		DiskInodesUsed:   info.DiskInodesUsed,
		DiskInodesUsage:  info.DiskInodesUsage,
		DiskReadBytes:    info.DiskReadBytes,
		DiskWriteBytes:   info.DiskWriteBytes,
		DiskReadOps:      info.DiskReadOps,
		DiskWriteOps:     info.DiskWriteOps,
		DiskReadTime:     info.DiskReadTime,
		DiskWriteTime:    info.DiskWriteTime,
		DiskIOTime:       info.DiskIOTime,
		DiskWeightedIO:   info.DiskWeightedIO,
		DiskIOInProgress: info.DiskIOInProgress,
		DiskIOPS:         info.DiskIOPS,
		DiskLatencyRead:  info.DiskLatencyRead,
		DiskLatencyWrite: info.DiskLatencyWrite,

		// Network Information
		NetworkBytesSent:     info.NetworkBytesSent,
		NetworkBytesRecv:     info.NetworkBytesRecv,
		NetworkPacketsSent:   info.NetworkPacketsSent,
		NetworkPacketsRecv:   info.NetworkPacketsRecv,
		NetworkErrorsIn:      info.NetworkErrorsIn,
		NetworkErrorsOut:     info.NetworkErrorsOut,
		NetworkDropsIn:       info.NetworkDropsIn,
		NetworkDropsOut:      info.NetworkDropsOut,
		NetworkFifoIn:        info.NetworkFifoIn,
		NetworkFifoOut:       info.NetworkFifoOut,
		NetworkBytesSentRate: info.NetworkBytesSentRate,
		NetworkBytesRecvRate: info.NetworkBytesRecvRate,

		// TCP Connection States
		TCPConnectionsEstablished: info.TCPConnectionsEstablished,
		TCPConnectionsTimeWait:    info.TCPConnectionsTimeWait,
		TCPConnectionsCloseWait:   info.TCPConnectionsCloseWait,
		TCPConnectionsListen:      info.TCPConnectionsListen,
		TCPConnectionsSynSent:     info.TCPConnectionsSynSent,
		TCPConnectionsSynRecv:     info.TCPConnectionsSynRecv,
		TCPConnectionsFinWait1:    info.TCPConnectionsFinWait1,
		TCPConnectionsFinWait2:    info.TCPConnectionsFinWait2,
		TCPConnectionsLastAck:     info.TCPConnectionsLastAck,
		TCPConnectionsClosing:     info.TCPConnectionsClosing,
		TCPRetransmits:            info.TCPRetransmits,

		// Process Information
		ProcessCount:    info.ProcessCount,
		ProcessRunning:  info.ProcessRunning,
		ProcessSleeping: info.ProcessSleeping,
		ProcessStopped:  info.ProcessStopped,
		ProcessZombie:   info.ProcessZombie,
		ProcessBlocked:  info.ProcessBlocked,
		ThreadCount:     info.ThreadCount,
		ContextSwitches: info.ContextSwitches,
		Interrupts:      info.Interrupts,
		SoftInterrupts:  info.SoftInterrupts,
		SystemCalls:     info.SystemCalls,

		// System Resources
		OpenFileDescriptors:  info.OpenFileDescriptors,
		MaxFileDescriptors:   info.MaxFileDescriptors,
		FileDescriptorsUsage: info.FileDescriptorsUsage,
		EntropyAvailable:     info.EntropyAvailable,

		// Container/Virtualization Detection
		IsContainer:        info.IsContainer,
		ContainerID:        info.ContainerID,
		ContainerRuntime:   info.ContainerRuntime,
		ContainerName:      info.ContainerName,
		ContainerImage:     info.ContainerImage,
		IsVirtualized:      info.IsVirtualized,
		VirtualizationType: info.VirtualizationType,
		CloudProvider:      info.CloudProvider,
		CloudInstanceID:    info.CloudInstanceID,
		CloudInstanceType:  info.CloudInstanceType,
		CloudRegion:        info.CloudRegion,
		CloudZone:          info.CloudZone,

		// Agent Metadata
		AgentVersion:       info.AgentVersion,
		AgentStartTime:     info.AgentStartTime,
		AgentUptime:        info.AgentUptime,
		CollectionTime:     info.CollectionTime,
		CollectionDuration: info.CollectionDuration,
	}

	// Map CPU per-core info
	if len(info.CPUPerCore) > 0 {
		payload.CPUPerCore = make([]api.CPUCoreInfoPayload, len(info.CPUPerCore))
		for i, core := range info.CPUPerCore {
			payload.CPUPerCore[i] = api.CPUCoreInfoPayload{
				CoreID:        core.CoreID,
				Usage:         core.Usage,
				UserPercent:   core.UserPercent,
				SystemPercent: core.SystemPercent,
				IdlePercent:   core.IdlePercent,
			}
		}
	}

	// Map disk partitions
	if len(info.DiskPartitions) > 0 {
		payload.DiskPartitions = make([]api.DiskPartitionInfoPayload, len(info.DiskPartitions))
		for i, part := range info.DiskPartitions {
			payload.DiskPartitions[i] = api.DiskPartitionInfoPayload{
				Device:      part.Device,
				Mountpoint:  part.Mountpoint,
				Fstype:      part.Fstype,
				Total:       part.Total,
				Used:        part.Used,
				Free:        part.Free,
				Usage:       part.Usage,
				Inodes:      part.Inodes,
				InodesFree:  part.InodesFree,
				InodesUsage: part.InodesUsage,
			}
		}
	}

	// Map network interfaces
	if len(info.NetworkInterfaces) > 0 {
		payload.NetworkInterfaces = make([]api.NetworkInterfaceInfoPayload, len(info.NetworkInterfaces))
		for i, iface := range info.NetworkInterfaces {
			payload.NetworkInterfaces[i] = api.NetworkInterfaceInfoPayload{
				Name:        iface.Name,
				MacAddress:  iface.MacAddress,
				IPAddresses: iface.IPAddresses,
				MTU:         iface.MTU,
				Speed:       iface.Speed,
				IsUp:        iface.IsUp,
				IsLoopback:  iface.IsLoopback,
				BytesSent:   iface.BytesSent,
				BytesRecv:   iface.BytesRecv,
				PacketsSent: iface.PacketsSent,
				PacketsRecv: iface.PacketsRecv,
				ErrorsIn:    iface.ErrorsIn,
				ErrorsOut:   iface.ErrorsOut,
				DropsIn:     iface.DropsIn,
				DropsOut:    iface.DropsOut,
			}
		}
	}

	return payload
}
