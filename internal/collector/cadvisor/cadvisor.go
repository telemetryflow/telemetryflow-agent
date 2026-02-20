// Package cadvisor provides a cAdvisor metrics scraper that collects container
// metrics from a running cAdvisor instance's Prometheus /metrics endpoint.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform (CEOP)
// Copyright (c) 2024-2026 DevOpsCorner Indonesia. All rights reserved.
package cadvisor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "cadvisor"

// CAdvisorCollector scrapes container metrics from a cAdvisor Prometheus endpoint.
// It implements the collector.Collector interface.
type CAdvisorCollector struct {
	cfg    config.CAdvisorCollectorConfig
	logger *zap.Logger
	client *http.Client

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewCAdvisorCollector creates a new cAdvisor scraper collector.
func NewCAdvisorCollector(cfg config.CAdvisorCollectorConfig, logger *zap.Logger) *CAdvisorCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "http://localhost:8080"
	}
	if cfg.MetricsPath == "" {
		cfg.MetricsPath = "/metrics"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &CAdvisorCollector{
		cfg:    cfg,
		logger: logger.Named(collectorName),
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		stopChan: make(chan struct{}),
	}
}

// Name returns the collector name.
func (c *CAdvisorCollector) Name() string {
	return collectorName
}

// Start starts the cAdvisor collector with a ticker-based collection loop.
func (c *CAdvisorCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	c.logger.Info("Starting cAdvisor collector",
		zap.Duration("interval", c.cfg.Interval),
		zap.String("endpoint", c.cfg.Endpoint),
		zap.String("metrics_path", c.cfg.MetricsPath),
	)

	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	// Initial collection
	if _, err := c.Collect(ctx); err != nil {
		c.logger.Warn("Initial cAdvisor collection failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopChan:
			return nil
		case <-ticker.C:
			if _, err := c.Collect(ctx); err != nil {
				c.logger.Warn("cAdvisor collection failed", zap.Error(err))
			}
		}
	}
}

// Stop gracefully stops the collector.
func (c *CAdvisorCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.running = false
	c.logger.Info("cAdvisor collector stopped")
	return nil
}

// IsRunning returns whether the collector is running.
func (c *CAdvisorCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// Collect scrapes the cAdvisor Prometheus endpoint and converts metrics.
func (c *CAdvisorCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	url := strings.TrimRight(c.cfg.Endpoint, "/") + c.cfg.MetricsPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("cadvisor: create request: %w", err)
	}
	req.Header.Set("Accept", string(expfmt.NewFormat(expfmt.TypeTextPlain)))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cadvisor: scrape %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("cadvisor: unexpected status %d from %s: %s", resp.StatusCode, url, string(body))
	}

	families, err := parsePrometheusText(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cadvisor: parse metrics: %w", err)
	}

	metrics := c.convertFamilies(families)

	c.logger.Debug("cAdvisor collected metrics",
		zap.Int("families", len(families)),
		zap.Int("metrics", len(metrics)),
	)

	return metrics, nil
}

// parsePrometheusText parses Prometheus text format from a reader.
func parsePrometheusText(r io.Reader) (map[string]*dto.MetricFamily, error) {
	var parser expfmt.TextParser
	return parser.TextToMetricFamilies(r)
}

// convertFamilies converts Prometheus metric families to collector.Metric.
func (c *CAdvisorCollector) convertFamilies(families map[string]*dto.MetricFamily) []collector.Metric {
	var metrics []collector.Metric

	for name, family := range families {
		// Only include container_* and machine_* metrics from cAdvisor
		if !c.shouldIncludeMetric(name) {
			continue
		}

		for _, m := range family.Metric {
			labels := promLabelsToMap(m.GetLabel())

			// Add custom labels from config
			for k, v := range c.cfg.Labels {
				labels[k] = v
			}

			switch family.GetType() {
			case dto.MetricType_COUNTER:
				if m.Counter != nil {
					metrics = append(metrics, collector.NewMetric(
						name, m.Counter.GetValue(), collector.MetricTypeCounter,
					).WithLabels(labels).WithDescription(family.GetHelp()))
				}
			case dto.MetricType_GAUGE:
				if m.Gauge != nil {
					metrics = append(metrics, collector.NewMetric(
						name, m.Gauge.GetValue(), collector.MetricTypeGauge,
					).WithLabels(labels).WithDescription(family.GetHelp()))
				}
			case dto.MetricType_UNTYPED:
				if m.Untyped != nil {
					metrics = append(metrics, collector.NewMetric(
						name, m.Untyped.GetValue(), collector.MetricTypeGauge,
					).WithLabels(labels).WithDescription(family.GetHelp()))
				}
			case dto.MetricType_SUMMARY:
				if m.Summary != nil {
					metrics = append(metrics, collector.NewMetric(
						name+"_sum", m.Summary.GetSampleSum(), collector.MetricTypeCounter,
					).WithLabels(labels).WithDescription(family.GetHelp()))
					metrics = append(metrics, collector.NewMetric(
						name+"_count", float64(m.Summary.GetSampleCount()), collector.MetricTypeCounter,
					).WithLabels(labels).WithDescription(family.GetHelp()))
				}
			case dto.MetricType_HISTOGRAM:
				if m.Histogram != nil {
					metrics = append(metrics, collector.NewMetric(
						name+"_sum", m.Histogram.GetSampleSum(), collector.MetricTypeCounter,
					).WithLabels(labels).WithDescription(family.GetHelp()))
					metrics = append(metrics, collector.NewMetric(
						name+"_count", float64(m.Histogram.GetSampleCount()), collector.MetricTypeCounter,
					).WithLabels(labels).WithDescription(family.GetHelp()))
					for _, bucket := range m.Histogram.GetBucket() {
						bLabels := make(map[string]string, len(labels)+1)
						for k, v := range labels {
							bLabels[k] = v
						}
						bLabels["le"] = fmt.Sprintf("%g", bucket.GetUpperBound())
						metrics = append(metrics, collector.NewMetric(
							name+"_bucket", float64(bucket.GetCumulativeCount()), collector.MetricTypeCounter,
						).WithLabels(bLabels).WithDescription(family.GetHelp()))
					}
				}
			}
		}
	}

	return metrics
}

// shouldIncludeMetric checks if a metric name should be collected based on
// configured prefix and metric filters.
func (c *CAdvisorCollector) shouldIncludeMetric(name string) bool {
	// If specific metrics are configured, only include those
	if len(c.cfg.MetricNames) > 0 {
		for _, allowed := range c.cfg.MetricNames {
			if name == allowed {
				return true
			}
		}
		return false
	}

	// Default: include standard cAdvisor metric prefixes
	for _, prefix := range []string{
		"container_",
		"machine_",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// promLabelsToMap converts Prometheus label pairs to a map.
func promLabelsToMap(pairs []*dto.LabelPair) map[string]string {
	labels := make(map[string]string, len(pairs))
	for _, lp := range pairs {
		labels[lp.GetName()] = lp.GetValue()
	}
	return labels
}
