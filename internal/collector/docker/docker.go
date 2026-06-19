// Package docker collects per-container CPU, memory, network, and block-I/O
// metrics by querying the Docker Engine API, implementing the collector.Collector
// interface for seamless pipeline integration.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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
package docker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	containertypes "github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "docker"

// DockerCollector collects per-container metrics using the Docker Engine API.
// It implements the collector.Collector interface.
type DockerCollector struct {
	cfg    *collectorConfig
	logger *zap.Logger
	client dockerclient.APIClient

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewDockerCollector creates a new Docker container metrics collector.
// Returns an error if the Docker daemon is unreachable.
func NewDockerCollector(cfg config.DockerCollectorConfig, logger *zap.Logger) (*DockerCollector, error) {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = "/var/run/docker.sock"
	}

	cc := newCollectorConfig(cfg, logger)

	// Create Docker client
	opts := []dockerclient.Opt{
		dockerclient.WithHost("unix://" + cfg.SocketPath),
	}
	cli, err := dockerclient.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("docker collector: failed to create client: %w", err)
	}

	// Validate connectivity with a ping
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.Ping(ctx, dockerclient.PingOptions{}); err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("docker collector: daemon unreachable at %s: %w", cfg.SocketPath, err)
	}

	return &DockerCollector{
		cfg:      cc,
		logger:   logger.Named(collectorName),
		client:   cli,
		stopChan: make(chan struct{}),
	}, nil
}

// Name returns the collector name.
func (d *DockerCollector) Name() string {
	return collectorName
}

// Start starts the Docker collector with a ticker-based collection loop.
func (d *DockerCollector) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = true
	d.stopChan = make(chan struct{})
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	d.logger.Info("Starting Docker collector",
		zap.Duration("interval", d.cfg.raw.Interval),
		zap.String("socket", d.cfg.raw.SocketPath),
		zap.Bool("cpu", d.cfg.raw.CollectCPU),
		zap.Bool("memory", d.cfg.raw.CollectMemory),
		zap.Bool("network", d.cfg.raw.CollectNetwork),
		zap.Bool("diskio", d.cfg.raw.CollectDiskIO),
	)

	select {
	case <-d.stopChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop gracefully stops the collector and closes the Docker client.
func (d *DockerCollector) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return nil
	}

	close(d.stopChan)
	d.running = false

	if d.client != nil {
		_ = d.client.Close()
	}

	d.logger.Info("Docker collector stopped")
	return nil
}

// IsRunning returns whether the collector is running.
func (d *DockerCollector) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

// Collect performs a single collection cycle across all containers.
func (d *DockerCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	listOpts := dockerclient.ContainerListOptions{All: d.cfg.raw.IncludeStopped}
	result, err := d.client.ContainerList(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("docker: container list: %w", err)
	}

	containers := result.Items

	var allMetrics []collector.Metric

	// Container state summary metrics
	allMetrics = append(allMetrics, d.collectStateSummary(containers)...)

	// Per-container stats
	for _, ctr := range containers {
		name := cleanContainerName(ctr.Names)
		if !d.cfg.shouldIncludeContainer(name) {
			continue
		}

		// Only fetch stats for running containers
		if ctr.State != "running" {
			continue
		}

		metrics, err := d.collectContainerStats(ctx, ctr)
		if err != nil {
			d.logger.Debug("Failed to collect stats for container",
				zap.String("name", name), zap.Error(err))
			continue
		}
		allMetrics = append(allMetrics, metrics...)
	}

	d.logger.Debug("Docker collected metrics",
		zap.Int("containers", len(containers)),
		zap.Int("metrics", len(allMetrics)),
	)
	return allMetrics, nil
}

// collectStateSummary counts containers by state.
func (d *DockerCollector) collectStateSummary(containers []containertypes.Summary) []collector.Metric {
	var running, stopped, paused, restarting int
	for _, ctr := range containers {
		switch ctr.State {
		case "running":
			running++
		case "exited", "dead":
			stopped++
		case "paused":
			paused++
		case "restarting":
			restarting++
		}
	}

	return []collector.Metric{
		collector.NewMetric("container.state.running", float64(running), collector.MetricTypeGauge).
			WithDescription("Number of running containers"),
		collector.NewMetric("container.state.stopped", float64(stopped), collector.MetricTypeGauge).
			WithDescription("Number of stopped containers"),
		collector.NewMetric("container.state.paused", float64(paused), collector.MetricTypeGauge).
			WithDescription("Number of paused containers"),
		collector.NewMetric("container.state.restarting", float64(restarting), collector.MetricTypeGauge).
			WithDescription("Number of restarting containers"),
		collector.NewMetric("container.state.total", float64(len(containers)), collector.MetricTypeGauge).
			WithDescription("Total number of containers"),
	}
}

// cleanContainerName strips the leading slash from Docker container names.
func cleanContainerName(names []string) string {
	if len(names) == 0 {
		return "unknown"
	}
	return strings.TrimPrefix(names[0], "/")
}
