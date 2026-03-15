// Package exporter contains all outbound data-path components: OTLP metric/
// trace/log export, periodic heartbeat to the TelemetryFlow backend, Kubernetes
// cluster-state sync, and the self-observability Prometheus registry and
// HTTP /metrics server.
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
package exporter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/kubernetes"
)

// KubernetesSyncClient defines the interface for posting cluster state to the backend.
type KubernetesSyncClient interface {
	SyncKubernetesState(ctx context.Context, clusterID string, payload interface{}) error
}

// KubernetesSync periodically syncs Kubernetes cluster state to the TFO Platform backend.
type KubernetesSync struct {
	config KubernetesSyncConfig
	logger *zap.Logger

	mu           sync.RWMutex
	running      bool
	stopChan     chan struct{}
	lastSent     time.Time
	lastError    error
	errorCount   int
	successCount int
}

// KubernetesSyncConfig holds all dependencies for KubernetesSync.
type KubernetesSyncConfig struct {
	// ClusterID is the UUID returned by TFO Platform when the cluster was registered.
	// Required — if empty, Start() returns immediately with a warning.
	ClusterID string

	// Interval is how often to push state (default: 60s).
	Interval time.Duration

	// Timeout is the per-request deadline (default: 30s).
	Timeout time.Duration

	// Collector is the running Kubernetes collector; LastClusterState() is called
	// each tick to obtain the snapshot to push.
	Collector *kubernetes.KubernetesCollector

	// Client implements SyncKubernetesState (satisfied by *api.Client).
	Client KubernetesSyncClient

	// Logger is the logger instance.
	Logger *zap.Logger
}

// NewKubernetesSync creates a new KubernetesSync exporter.
func NewKubernetesSync(cfg KubernetesSyncConfig) *KubernetesSync {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	return &KubernetesSync{
		config:   cfg,
		logger:   cfg.Logger,
		stopChan: make(chan struct{}),
	}
}

// Start runs the periodic sync loop until ctx is cancelled or Stop is called.
func (ks *KubernetesSync) Start(ctx context.Context) error {
	if ks.config.ClusterID == "" {
		ks.logger.Warn("Kubernetes sync disabled: cluster_id not configured in collectors.kubernetes")
		return nil
	}

	ks.mu.Lock()
	if ks.running {
		ks.mu.Unlock()
		return nil
	}
	ks.running = true
	ks.stopChan = make(chan struct{})
	ks.mu.Unlock()

	ks.logger.Info("Starting Kubernetes state sync",
		zap.String("clusterID", ks.config.ClusterID),
		zap.Duration("interval", ks.config.Interval),
	)

	ticker := time.NewTicker(ks.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ks.stopChan:
			return nil
		case <-ticker.C:
			if err := ks.sendSync(ctx); err != nil {
				ks.mu.Lock()
				ks.lastError = err
				ks.errorCount++
				errCount := ks.errorCount
				ks.mu.Unlock()
				ks.logger.Warn("Kubernetes state sync failed",
					zap.Error(err),
					zap.Int("errorCount", errCount),
				)
			} else {
				ks.mu.Lock()
				ks.lastSent = time.Now()
				ks.successCount++
				ks.lastError = nil
				ks.mu.Unlock()
			}
		}
	}
}

// Stop gracefully stops the sync loop.
func (ks *KubernetesSync) Stop() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.running {
		return nil
	}

	close(ks.stopChan)
	ks.running = false
	ks.logger.Info("Kubernetes state sync stopped",
		zap.Int("successCount", ks.successCount),
		zap.Int("errorCount", ks.errorCount),
	)
	return nil
}

// IsRunning returns whether the sync loop is active.
func (ks *KubernetesSync) IsRunning() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.running
}

// sendSync fetches the latest ClusterState and posts it to the backend.
func (ks *KubernetesSync) sendSync(ctx context.Context) error {
	state := ks.config.Collector.LastClusterState()
	if state == nil {
		ks.logger.Debug("No cluster state available yet, skipping sync")
		return nil
	}

	syncCtx, cancel := context.WithTimeout(ctx, ks.config.Timeout)
	defer cancel()

	if err := ks.config.Client.SyncKubernetesState(syncCtx, ks.config.ClusterID, state); err != nil {
		return fmt.Errorf("cluster %s: %w", ks.config.ClusterID, err)
	}

	ks.logger.Debug("Kubernetes state synced",
		zap.String("clusterID", ks.config.ClusterID),
		zap.Int("nodes", len(state.Nodes)),
		zap.Int("pods", len(state.Pods)),
		zap.Int("namespaces", len(state.Namespaces)),
		zap.Int("deployments", len(state.Deployments)),
		zap.Int("pvs", len(state.PVs)),
		zap.Int("pvcs", len(state.PVCs)),
		zap.Bool("apiserver_metrics", state.ApiServerMetrics != nil),
		zap.Bool("coredns_metrics", state.CoreDNSMetrics != nil),
	)
	return nil
}

// KubernetesSyncStats contains runtime statistics for KubernetesSync.
type KubernetesSyncStats struct {
	Running      bool      `json:"running"`
	LastSent     time.Time `json:"lastSent"`
	LastError    error     `json:"lastError,omitempty"`
	SuccessCount int       `json:"successCount"`
	ErrorCount   int       `json:"errorCount"`
}

// Stats returns a snapshot of sync statistics.
func (ks *KubernetesSync) Stats() KubernetesSyncStats {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return KubernetesSyncStats{
		Running:      ks.running,
		LastSent:     ks.lastSent,
		LastError:    ks.lastError,
		SuccessCount: ks.successCount,
		ErrorCount:   ks.errorCount,
	}
}
