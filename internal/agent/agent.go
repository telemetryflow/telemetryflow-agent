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
	cadvisorcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/cadvisor"
	dockercollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/docker"
	ebpfcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/ebpf"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nodeexporter"
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
	client           *api.Client
	heartbeat        *exporter.Heartbeat
	collectors       []collector.Collector
	prometheusServer *exporter.PrometheusServer

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
		Tags:              cfg.Agent.Tags,
		Labels:            cfg.Agent.Labels,
		Client:            client,
		Logger:            logger,
	})

	// Create collectors (alphabetical order)
	var collectors []collector.Collector

	// Add cAdvisor collector if enabled
	if cfg.Collector.CAdvisor.Enabled {
		cadvisorCol := cadvisorcollector.NewCAdvisorCollector(cfg.Collector.CAdvisor, logger)
		collectors = append(collectors, cadvisorCol)
		logger.Info("cAdvisor collector enabled",
			zap.Duration("interval", cfg.Collector.CAdvisor.Interval),
			zap.String("endpoint", cfg.Collector.CAdvisor.Endpoint),
		)
	}

	// Add Docker collector if enabled
	if cfg.Collector.Docker.Enabled {
		dockerCol, err := dockercollector.NewDockerCollector(cfg.Collector.Docker, logger)
		if err != nil {
			logger.Warn("Failed to create Docker collector, skipping",
				zap.Error(err),
			)
		} else {
			collectors = append(collectors, dockerCol)
			logger.Info("Docker collector enabled",
				zap.Duration("interval", cfg.Collector.Docker.Interval),
				zap.String("socket", cfg.Collector.Docker.SocketPath),
			)
		}
	}

	// Add eBPF collector if enabled
	if cfg.Collector.EBPF.Enabled {
		ebpfCol, err := ebpfcollector.NewEBPFCollector(cfg.Collector.EBPF, logger)
		if err != nil {
			logger.Warn("Failed to create eBPF collector, skipping",
				zap.Error(err),
			)
		} else {
			collectors = append(collectors, ebpfCol)
			logger.Info("eBPF collector enabled",
				zap.Duration("interval", cfg.Collector.EBPF.Interval),
			)
		}
	}

	// Add Kubernetes collector if enabled
	if cfg.Collector.Kubernetes.Enabled {
		k8sCollector, err := kubernetes.NewKubernetesCollector(cfg.Collector.Kubernetes, logger)
		if err != nil {
			logger.Warn("Failed to create Kubernetes collector, skipping",
				zap.Error(err),
			)
		} else {
			collectors = append(collectors, k8sCollector)
			logger.Info("Kubernetes collector enabled",
				zap.String("cluster", cfg.Collector.Kubernetes.ClusterName),
			)
		}
	}

	// Add Node Exporter collector if enabled
	if cfg.Collector.NodeExporter.Enabled {
		neCollector := nodeexporter.NewNodeExporterCollector(cfg.Collector.NodeExporter, logger)
		collectors = append(collectors, neCollector)
		logger.Info("Node exporter collector enabled",
			zap.Duration("interval", cfg.Collector.NodeExporter.Interval),
		)
	}

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

	// Create Prometheus metrics server if enabled
	var promServer *exporter.PrometheusServer
	if cfg.PrometheusServer.Enabled {
		promServer = exporter.NewPrometheusServer(cfg.PrometheusServer, logger)
		logger.Info("Prometheus metrics server enabled",
			zap.Int("port", cfg.PrometheusServer.Port),
			zap.String("path", cfg.PrometheusServer.Path),
		)
	}

	return &Agent{
		id:               agentID,
		config:           cfg,
		logger:           logger,
		client:           client,
		heartbeat:        heartbeat,
		collectors:       collectors,
		prometheusServer: promServer,
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
	// Buffer: heartbeat + collectors + prometheus server
	chanSize := 2 + len(a.collectors)
	errChan := make(chan error, chanSize)

	// Start Prometheus metrics server
	if a.prometheusServer != nil {
		go func() {
			if err := a.prometheusServer.Start(ctx); err != nil && err != context.Canceled {
				errChan <- fmt.Errorf("prometheus server error: %w", err)
			}
		}()
	}

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

	// Stop Prometheus server
	if a.prometheusServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.prometheusServer.Stop(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("prometheus server stop: %w", err))
				errMu.Unlock()
			}
		}()
	}

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
