// Package scraper implements a Prometheus pull-based scraper that periodically
// fetches metrics from configured HTTP targets, parses Prometheus text-format
// exposition, and applies relabeling rules before forwarding to exporters.
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
package scraper

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

const (
	collectorName   = "prometheus_scraper"
	metricsChBuffer = 1000
)

// PrometheusScraperCollector implements collector.Collector.
// It manages N ScrapeJob goroutines, one per configured job.
type PrometheusScraperCollector struct {
	cfg     ScraperConfig
	jobs    []*ScrapeJob
	mu      sync.RWMutex
	metrics chan []collector.Metric // buffered channel; Collect() drains it
	logger  *zap.Logger
	running atomic.Bool
}

// NewPrometheusScraperCollector creates a new PrometheusScraperCollector.
func NewPrometheusScraperCollector(cfg ScraperConfig, logger *zap.Logger) *PrometheusScraperCollector {
	return &PrometheusScraperCollector{
		cfg:    cfg,
		logger: logger.Named(collectorName),
	}
}

// Name returns the collector name.
func (c *PrometheusScraperCollector) Name() string {
	return collectorName
}

// Start creates the metrics channel, starts all enabled ScrapeJobs, and sets running=true.
func (c *PrometheusScraperCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running.Load() {
		return nil
	}

	c.metrics = make(chan []collector.Metric, metricsChBuffer)
	c.jobs = c.jobs[:0]

	for _, jobCfg := range c.cfg.Jobs {
		if !jobCfg.Enabled {
			continue
		}

		job, err := newScrapeJob(jobCfg, c.metrics, c.logger)
		if err != nil {
			return fmt.Errorf("prometheus_scraper: create job %q: %w", jobCfg.JobName, err)
		}

		job.Start(ctx)
		c.jobs = append(c.jobs, job)
	}

	c.running.Store(true)
	c.logger.Info("prometheus scraper collector started", zap.Int("jobs", len(c.jobs)))
	return nil
}

// Stop stops all scrape jobs and sets running=false.
func (c *PrometheusScraperCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running.Load() {
		return nil
	}

	for _, job := range c.jobs {
		job.Stop()
	}

	c.running.Store(false)
	c.logger.Info("prometheus scraper collector stopped")
	return nil
}

// Collect drains the internal metrics channel and returns all accumulated metrics.
func (c *PrometheusScraperCollector) Collect(_ context.Context) ([]collector.Metric, error) {
	var result []collector.Metric

	for {
		select {
		case batch, ok := <-c.metrics:
			if !ok {
				return result, nil
			}
			result = append(result, batch...)
		default:
			return result, nil
		}
	}
}

// IsRunning returns whether the collector is currently running.
func (c *PrometheusScraperCollector) IsRunning() bool {
	return c.running.Load()
}
