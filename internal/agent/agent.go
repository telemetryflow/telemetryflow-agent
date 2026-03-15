// Package agent implements the core TelemetryFlow Agent lifecycle.
// It orchestrates all collectors, exporters, the API client, Kubernetes
// sync, heartbeat, and the optional Prometheus /metrics endpoint.
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
package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	cadvisorcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/cadvisor"
	dockercollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/docker"
	ebpfcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/ebpf"
	fluentbitcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/fluentbit"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
	logcollector "github.com/telemetryflow/telemetryflow-agent/internal/collector/log"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nodeexporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/scraper"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/system"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
	"github.com/telemetryflow/telemetryflow-agent/internal/receiver/remotewrite"
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
	k8sSync          *exporter.KubernetesSync
	k8sCollector     *kubernetes.KubernetesCollector // kept for registration retry
	collectors       []collector.Collector
	prometheusServer *exporter.PrometheusServer

	// State
	mu      sync.RWMutex
	running bool
	started time.Time
}

// New creates a new agent instance
func New(cfg *config.Config, logger *zap.Logger) (*Agent, error) {
	// Resolve a stable agent ID — deterministic via host fingerprint when not explicitly set.
	agentID := ResolveAgentID(cfg.Agent.ID, cfg.Agent.Hostname, logger)

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

	// Auto-detect Kubernetes: enable collector + sync when running inside a K8s cluster.
	// KUBERNETES_SERVICE_HOST is injected by the kubelet into every pod.
	// Skip auto-detection if K8s was explicitly disabled via TELEMETRYFLOW_K8S_ENABLED=false
	// (e.g. DaemonSet pods that only run node_exporter).
	k8sExplicitlyDisabled := strings.EqualFold(os.Getenv("TELEMETRYFLOW_K8S_ENABLED"), "false")
	if !cfg.Collector.Kubernetes.Enabled && !k8sExplicitlyDisabled && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		cfg.Collector.Kubernetes.Enabled = true
		if !cfg.Collector.Kubernetes.SyncToBackend {
			cfg.Collector.Kubernetes.SyncToBackend = true
		}
		logger.Info("Kubernetes environment auto-detected, enabling K8s collector")
	}

	// Add Kubernetes collector if enabled
	var k8sSync *exporter.KubernetesSync
	var k8sCollector *kubernetes.KubernetesCollector
	if cfg.Collector.Kubernetes.Enabled {
		col, err := kubernetes.NewKubernetesCollector(cfg.Collector.Kubernetes, logger)
		if err != nil {
			logger.Warn("Failed to create Kubernetes collector, skipping",
				zap.Error(err),
			)
		} else {
			k8sCollector = col
			collectors = append(collectors, k8sCollector)
			logger.Info("Kubernetes collector enabled",
				zap.String("cluster", k8sCollector.ClusterName()),
				zap.String("provider", k8sCollector.ClusterProvider()),
			)

			// Auto-register cluster with backend if ClusterID is not pre-configured.
			if cfg.Collector.Kubernetes.SyncToBackend && cfg.Collector.Kubernetes.ClusterID == "" {
				regCtx, regCancel := context.WithTimeout(context.Background(), 30*time.Second)
				regResp, regErr := client.AgentRegisterCluster(regCtx, &api.AgentRegisterClusterRequest{
					Name:     k8sCollector.ClusterName(),
					Provider: k8sCollector.ClusterProvider(),
				})
				regCancel()
				if regErr != nil {
					logger.Warn("Failed to auto-register Kubernetes cluster, will retry in background",
						zap.Error(regErr),
						zap.String("cluster", k8sCollector.ClusterName()),
					)
				} else {
					cfg.Collector.Kubernetes.ClusterID = regResp.ID
					logger.Info("Kubernetes cluster auto-registered",
						zap.String("clusterID", regResp.ID),
						zap.String("name", regResp.Name),
						zap.Bool("isNew", regResp.IsNew),
					)
				}
			}

			// Create K8s state sync exporter when sync_to_backend is enabled
			if cfg.Collector.Kubernetes.SyncToBackend && cfg.Collector.Kubernetes.ClusterID != "" {
				syncInterval := cfg.Collector.Kubernetes.SyncInterval
				if syncInterval == 0 {
					syncInterval = 60 * time.Second
				}
				k8sSync = exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
					ClusterID: cfg.Collector.Kubernetes.ClusterID,
					Interval:  syncInterval,
					Collector: k8sCollector,
					Client:    client,
					Logger:    logger,
				})
				logger.Info("Kubernetes state sync enabled",
					zap.String("clusterID", cfg.Collector.Kubernetes.ClusterID),
					zap.Duration("interval", syncInterval),
				)
			}
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

	// Add log collector: Fluent Bit (preferred) or native (fallback).
	// Mutual exclusion — Fluent Bit replaces native when both are enabled.
	if cfg.Collector.FluentBit.Enabled {
		fbCol, err := fluentbitcollector.NewFluentBitCollector(
			cfg.Collector.FluentBit,
			cfg.TelemetryFlow,
			agentID,
			logger,
		)
		if err != nil {
			logger.Warn("Failed to create Fluent Bit collector, falling back to native log collector",
				zap.Error(err),
			)
			// Fall back to native log collector
			if cfg.Collector.Logs.Enabled {
				logCol := logcollector.NewLogCollector(cfg.Collector.Logs, agentID, logger)
				collectors = append(collectors, logCol)
				logger.Info("Native log collector enabled (Fluent Bit fallback)")
			}
		} else {
			collectors = append(collectors, fbCol)
			logger.Info("Fluent Bit log collector enabled",
				zap.String("binary", cfg.Collector.FluentBit.BinaryPath),
				zap.Bool("kubernetes", cfg.Collector.FluentBit.Kubernetes.Enabled),
				zap.Bool("systemd", cfg.Collector.FluentBit.Systemd.Enabled),
				zap.Int("tail_paths", len(cfg.Collector.FluentBit.Tail.Paths)),
			)
		}
	} else if cfg.Collector.Logs.Enabled {
		logCol := logcollector.NewLogCollector(cfg.Collector.Logs, agentID, logger)
		collectors = append(collectors, logCol)
		logger.Info("Native log collector enabled",
			zap.Int("paths", len(cfg.Collector.Logs.Paths)),
			zap.Bool("journald", cfg.Collector.Logs.Journald.Enabled),
		)
	}

	// Add Prometheus Scraper collector if enabled
	if cfg.Collector.PrometheusScraper.Enabled {
		scraperCfg := scraper.ScraperConfig{
			Enabled: cfg.Collector.PrometheusScraper.Enabled,
		}
		for _, j := range cfg.Collector.PrometheusScraper.ScrapeJobs {
			job := scraper.ScrapeJobConfig{
				JobName:         j.JobName,
				Enabled:         j.Enabled,
				Targets:         j.StaticTargets,
				ScrapeInterval:  j.ScrapeInterval,
				ScrapePath:      j.ScrapePath,
				ScrapeTimeout:   j.ScrapeTimeout,
				HonorLabels:     j.HonorLabels,
				BearerToken:     j.BearerToken,
				BearerTokenFile: j.BearerTokenFile,
				TLSConfig: scraper.TLSConfig{
					InsecureSkipVerify: j.TLSConfig.SkipVerify,
					CAFile:             j.TLSConfig.CAFile,
					CertFile:           j.TLSConfig.CertFile,
					KeyFile:            j.TLSConfig.KeyFile,
				},
			}
			if j.BasicAuth != nil {
				job.BasicAuth = &scraper.BasicAuthConfig{
					Username: j.BasicAuth.Username,
					Password: j.BasicAuth.Password,
				}
			}
			for _, r := range j.RelabelConfigs {
				job.RelabelConfigs = append(job.RelabelConfigs, scraper.RelabelConfig{
					SourceLabels: r.SourceLabels,
					Regex:        r.Regex,
					TargetLabel:  r.TargetLabel,
					Replacement:  r.Replacement,
					Action:       r.Action,
				})
			}
			scraperCfg.Jobs = append(scraperCfg.Jobs, job)
		}
		scraperCollector := scraper.NewPrometheusScraperCollector(scraperCfg, logger)
		collectors = append(collectors, scraperCollector)
		logger.Info("Prometheus scraper collector enabled",
			zap.Int("jobs", len(scraperCfg.Jobs)),
		)
	}

	// Add Remote Write Receiver collector if enabled
	if cfg.Collector.RemoteWriteReceiver.Enabled {
		rwCfg := remotewrite.RemoteWriteReceiverConfig{
			Enabled:    cfg.Collector.RemoteWriteReceiver.Enabled,
			Port:       cfg.Collector.RemoteWriteReceiver.Port,
			BufferSize: cfg.Collector.RemoteWriteReceiver.BufferSize,
		}
		if cfg.Collector.RemoteWriteReceiver.BasicAuth != nil {
			rwCfg.BasicAuth = &remotewrite.BasicAuthConfig{
				Username: cfg.Collector.RemoteWriteReceiver.BasicAuth.Username,
				Password: cfg.Collector.RemoteWriteReceiver.BasicAuth.Password,
			}
		}
		if cfg.Collector.RemoteWriteReceiver.TLS != nil {
			rwCfg.TLS = &remotewrite.TLSConfig{
				InsecureSkipVerify: cfg.Collector.RemoteWriteReceiver.TLS.SkipVerify,
				CAFile:             cfg.Collector.RemoteWriteReceiver.TLS.CAFile,
				CertFile:           cfg.Collector.RemoteWriteReceiver.TLS.CertFile,
				KeyFile:            cfg.Collector.RemoteWriteReceiver.TLS.KeyFile,
			}
		}
		rwReceiver := remotewrite.NewRemoteWriteReceiver(rwCfg, logger)
		collectors = append(collectors, rwReceiver)
		logger.Info("Remote write receiver enabled",
			zap.Int("port", rwCfg.Port),
		)
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
		k8sSync:          k8sSync,
		k8sCollector:     k8sCollector,
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
	// Buffer: heartbeat + k8sSync + collectors + prometheus server
	chanSize := 2 + len(a.collectors)
	if a.k8sSync != nil {
		chanSize++
	}
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

	// Start Kubernetes state sync (no-op if not configured)
	if a.k8sSync != nil {
		go func() {
			if err := a.k8sSync.Start(ctx); err != nil && err != context.Canceled {
				errChan <- fmt.Errorf("kubernetes sync error: %w", err)
			}
		}()
	} else if a.k8sCollector != nil && a.config.Collector.Kubernetes.SyncToBackend {
		// Registration failed at startup — retry with exponential backoff in background.
		go func() {
			backoff := 15 * time.Second
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
				regResp, regErr := a.client.AgentRegisterCluster(regCtx, &api.AgentRegisterClusterRequest{
					Name:     a.k8sCollector.ClusterName(),
					Provider: a.k8sCollector.ClusterProvider(),
				})
				regCancel()
				if regErr != nil {
					if backoff < 5*time.Minute {
						backoff *= 2
					}
					a.logger.Warn("K8s cluster registration retry failed",
						zap.Error(regErr),
						zap.Duration("next_retry", backoff),
					)
					continue
				}
				a.config.Collector.Kubernetes.ClusterID = regResp.ID
				a.logger.Info("Kubernetes cluster registered (retry succeeded)",
					zap.String("clusterID", regResp.ID),
					zap.String("name", regResp.Name),
				)
				syncInterval := a.config.Collector.Kubernetes.SyncInterval
				if syncInterval == 0 {
					syncInterval = 60 * time.Second
				}
				a.mu.Lock()
				a.k8sSync = exporter.NewKubernetesSync(exporter.KubernetesSyncConfig{
					ClusterID: regResp.ID,
					Interval:  syncInterval,
					Collector: a.k8sCollector,
					Client:    a.client,
					Logger:    a.logger,
				})
				sync := a.k8sSync
				a.mu.Unlock()
				if err := sync.Start(ctx); err != nil && err != context.Canceled {
					a.logger.Error("Kubernetes sync stopped", zap.Error(err))
				}
				return
			}
		}()
	}

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

	// Stop Kubernetes state sync
	if a.k8sSync != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.k8sSync.Stop(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("kubernetes sync stop: %w", err))
				errMu.Unlock()
			}
		}()
	}

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
