// Package agent provides the core agent lifecycle management.
package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/pkg/api"
)

// Agent is the main telemetry agent
type Agent struct {
	id     string
	config *config.Config
	logger *zap.Logger

	// Components
	client     *api.Client
	heartbeat  *exporter.Heartbeat
	collectors []collector.Collector

	// State
	mu      sync.RWMutex
	running bool
	started time.Time
}

// New creates a new agent instance
func New(cfg *config.Config, logger *zap.Logger) (*Agent, error) {
	// Generate agent ID if not provided
	agentID := cfg.Agent.ID
	if agentID == "" {
		agentID = uuid.New().String()
		logger.Info("Generated new agent ID", zap.String("id", agentID))
	}

	// Create API client using helper methods (prefer TelemetryFlow config over legacy API)
	tlsConfig := cfg.GetEffectiveTLSConfig()
	client := api.NewClient(api.ClientConfig{
		BaseURL:       cfg.GetEffectiveEndpoint(),
		APIKeyID:      cfg.GetEffectiveAPIKeyID(),
		APIKeySecret:  cfg.GetEffectiveAPIKeySecret(),
		WorkspaceID:   cfg.GetEffectiveWorkspaceID(),
		TenantID:      cfg.GetEffectiveTenantID(),
		Timeout:       cfg.GetEffectiveTimeout(),
		RetryAttempts: cfg.GetEffectiveRetryAttempts(),
		RetryDelay:    cfg.GetEffectiveRetryDelay(),
		TLSConfig: api.TLSConfig{
			Enabled:    tlsConfig.Enabled,
			SkipVerify: tlsConfig.SkipVerify,
			CertFile:   tlsConfig.CertFile,
			KeyFile:    tlsConfig.KeyFile,
			CAFile:     tlsConfig.CAFile,
		},
		Logger: logger,
	})

	// Create heartbeat exporter
	heartbeat := exporter.NewHeartbeat(exporter.HeartbeatConfig{
		AgentID:           agentID,
		Hostname:          cfg.Agent.Hostname,
		Interval:          cfg.Heartbeat.Interval,
		Timeout:           cfg.Heartbeat.Timeout,
		IncludeSystemInfo: cfg.Heartbeat.IncludeSystemInfo,
		Client:            client,
		Logger:            logger,
	})

	// Create collectors
	var collectors []collector.Collector

	// Add system collector if enabled
	if cfg.Collector.System.Enabled {
		sysCollector := system.NewHostCollector(system.HostCollectorConfig{
			Interval:    cfg.Collector.System.Interval,
			CollectCPU:  cfg.Collector.System.CPU,
			CollectMem:  cfg.Collector.System.Memory,
			CollectDisk: cfg.Collector.System.Disk,
			CollectNet:  cfg.Collector.System.Network,
			DiskPaths:   cfg.Collector.System.DiskPaths,
			Logger:      logger,
		})
		collectors = append(collectors, sysCollector)
	}

	return &Agent{
		id:         agentID,
		config:     cfg,
		logger:     logger,
		client:     client,
		heartbeat:  heartbeat,
		collectors: collectors,
	}, nil
}

// ID returns the agent ID
func (a *Agent) ID() string {
	return a.id
}

// Run starts the agent and blocks until context is cancelled
func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent is already running")
	}
	a.running = true
	a.started = time.Now()
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()

	a.logger.Info("Agent starting",
		zap.String("id", a.id),
		zap.String("hostname", a.config.Agent.Hostname),
		zap.Int("collectors", len(a.collectors)),
	)

	// Create error channel for component errors
	errChan := make(chan error, 1+len(a.collectors))

	// Start heartbeat
	go func() {
		if err := a.heartbeat.Start(ctx); err != nil && err != context.Canceled {
			errChan <- fmt.Errorf("heartbeat error: %w", err)
		}
	}()

	// Start collectors
	for _, c := range a.collectors {
		c := c // capture
		go func() {
			if err := c.Start(ctx); err != nil && err != context.Canceled {
				errChan <- fmt.Errorf("collector %s error: %w", c.Name(), err)
			}
		}()
	}

	a.logger.Info("Agent started successfully")

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		a.logger.Info("Agent shutdown requested")
		return a.shutdown()
	case err := <-errChan:
		a.logger.Error("Component error, initiating shutdown", zap.Error(err))
		return err
	}
}

// shutdown gracefully stops all components
func (a *Agent) shutdown() error {
	a.logger.Info("Shutting down agent components")

	var wg sync.WaitGroup
	var errs []error
	var errMu sync.Mutex

	// Stop heartbeat
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.heartbeat.Stop(); err != nil {
			errMu.Lock()
			errs = append(errs, fmt.Errorf("heartbeat stop: %w", err))
			errMu.Unlock()
		}
	}()

	// Stop collectors
	for _, c := range a.collectors {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Stop(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("collector %s stop: %w", c.Name(), err))
				errMu.Unlock()
			}
		}()
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		a.logger.Info("All components stopped")
	case <-time.After(10 * time.Second):
		a.logger.Warn("Shutdown timeout, some components may not have stopped cleanly")
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	a.mu.RLock()
	uptime := time.Since(a.started)
	a.mu.RUnlock()
	a.logger.Info("Agent shutdown complete", zap.Duration("uptime", uptime))
	return nil
}

// IsRunning returns whether the agent is running
func (a *Agent) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// Uptime returns the agent uptime
func (a *Agent) Uptime() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.running {
		return 0
	}
	return time.Since(a.started)
}

// Stats returns agent statistics
func (a *Agent) Stats() AgentStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var uptime time.Duration
	if a.running {
		uptime = time.Since(a.started)
	}

	return AgentStats{
		ID:             a.id,
		Hostname:       a.config.Agent.Hostname,
		Running:        a.running,
		Started:        a.started,
		Uptime:         uptime,
		CollectorCount: len(a.collectors),
	}
}

// AgentStats contains agent statistics
type AgentStats struct {
	ID             string        `json:"id"`
	Hostname       string        `json:"hostname"`
	Running        bool          `json:"running"`
	Started        time.Time     `json:"started"`
	Uptime         time.Duration `json:"uptime"`
	CollectorCount int           `json:"collectorCount"`
}
