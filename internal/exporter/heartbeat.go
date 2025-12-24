// Package exporter provides telemetry data export functionality.
package exporter

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

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
				h.mu.Unlock()
				h.logger.Warn("Heartbeat failed",
					zap.Error(err),
					zap.Int("errorCount", h.errorCount),
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
			sysInfo = &api.SystemInfoPayload{
				Hostname:        info.Hostname,
				OS:              info.OS,
				OSVersion:       info.OSVersion,
				KernelVersion:   info.KernelVersion,
				Architecture:    info.Architecture,
				Uptime:          info.Uptime,
				CPUCores:        info.CPUCores,
				CPUModel:        info.CPUModel,
				CPUUsage:        info.CPUUsage,
				MemoryTotal:     info.MemoryTotal,
				MemoryUsed:      info.MemoryUsed,
				MemoryAvailable: info.MemoryAvailable,
				MemoryUsage:     info.MemoryUsage,
				DiskTotal:       info.DiskTotal,
				DiskUsed:        info.DiskUsed,
				DiskAvailable:   info.DiskAvailable,
				DiskUsage:       info.DiskUsage,
			}
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
