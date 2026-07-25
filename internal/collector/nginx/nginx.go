// Package nginx implements a TelemetryFlow Agent collector for Nginx OSS
// instances. It scrapes the http_stub_status_module (stub_status) endpoint and
// emits metrics under the web.nginx.* namespace. No external client library is
// required.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package nginx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "nginx"

// defaultTimeout is used when an instance leaves Timeout empty.
const defaultTimeout = 5 * time.Second

// stub_status line regexes. The accepts/handled/requests line is matched in
// multiline mode so the anchors bind to a line consisting solely of three
// integers (the header line "server accepts handled requests" is rejected).
var (
	reActive  = regexp.MustCompile(`Active connections:\s+(\d+)`)
	reAHReq   = regexp.MustCompile(`(?m)^\s*(\d+)\s+(\d+)\s+(\d+)\s*$`)
	reReading = regexp.MustCompile(`Reading:\s+(\d+)\s+Writing:\s+(\d+)\s+Waiting:\s+(\d+)`)
)

// NginxCollector monitors one or more Nginx OSS instances via stub_status.
type NginxCollector struct {
	cfg    config.NginxCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewNginxCollector creates a new NginxCollector.
func NewNginxCollector(cfg config.NginxCollectorConfig, logger *zap.Logger) *NginxCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	return &NginxCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *NginxCollector) Name() string { return collectorName }

func (c *NginxCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *NginxCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("nginx collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("Nginx collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("interval", c.cfg.Interval),
	)
	return nil
}

func (c *NginxCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances.
func (c *NginxCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		all = append(all, c.collectInstance(ctx, inst)...)
	}
	return all, nil
}

// collectInstance scrapes one stub_status endpoint. Transport failures,
// non-2xx responses, and parse failures all produce a state=0 metric rather
// than an error so the pipeline never crashes on a broken instance.
func (c *NginxCollector) collectInstance(ctx context.Context, inst config.NginxInstance) []collector.Metric {
	labels := instanceLabels(inst)
	now := time.Now()
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string) collector.Metric {
		m := collector.Metric{
			Name: name, Type: typ, Value: v, Timestamp: now,
			Unit: unit, Description: desc,
			Labels: make(map[string]string, len(labels)),
		}
		for k, val := range labels {
			m.Labels[k] = val
		}
		return m
	}

	if inst.URL == "" {
		c.logger.Warn("Nginx instance missing url", zap.String("instance", inst.Name))
		return []collector.Metric{mk("web.nginx.state", 0, collector.MetricTypeGauge, "", "Stub_status scrape state: 1=ok, 0=fail")}
	}

	body, err := c.scrape(ctx, inst)
	if err != nil {
		c.logger.Debug("Nginx stub_status scrape failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return []collector.Metric{mk("web.nginx.state", 0, collector.MetricTypeGauge, "", "Stub_status scrape state: 1=ok, 0=fail")}
	}

	stats, ok := parseStubStatus(body)
	if !ok {
		c.logger.Debug("Nginx stub_status parse failed",
			zap.String("instance", inst.Name))
		return []collector.Metric{mk("web.nginx.state", 0, collector.MetricTypeGauge, "", "Stub_status scrape state: 1=ok, 0=fail")}
	}

	return BuildNginxMetrics(labels, stats, now)
}

// scrape issues the HTTP GET against the stub_status endpoint.
func (c *NginxCollector) scrape(ctx context.Context, inst config.NginxInstance) (string, error) {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: inst.TLSSkipVerify},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, inst.URL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	for k, v := range inst.Headers {
		req.Header.Set(k, v)
	}
	if inst.Username != "" || inst.Password != "" {
		req.SetBasicAuth(inst.Username, inst.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	return string(body), nil
}

// stubStats holds the seven counters/gauges extracted from stub_status.
type stubStats struct {
	active   int64
	accepts  int64
	handled  int64
	requests int64
	reading  int64
	writing  int64
	waiting  int64
}

// parseStubStatus extracts the seven stub_status metrics from the plain-text
// body. Returns ok=false if any required line is missing or malformed.
func parseStubStatus(body string) (stubStats, bool) {
	var s stubStats
	if m := reActive.FindStringSubmatch(body); m != nil {
		s.active = parseInt64(m[1])
	} else {
		return stubStats{}, false
	}
	if m := reAHReq.FindStringSubmatch(body); m != nil {
		s.accepts = parseInt64(m[1])
		s.handled = parseInt64(m[2])
		s.requests = parseInt64(m[3])
	} else {
		return stubStats{}, false
	}
	if m := reReading.FindStringSubmatch(body); m != nil {
		s.reading = parseInt64(m[1])
		s.writing = parseInt64(m[2])
		s.waiting = parseInt64(m[3])
	} else {
		return stubStats{}, false
	}
	return s, true
}

func parseInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

// instanceLabels builds the standard label set for an instance, parsing
// nginx_host and nginx_port out of the configured URL.
func instanceLabels(inst config.NginxInstance) map[string]string {
	host, port := splitHostPort(inst.URL)
	return map[string]string{
		"nginx_instance": inst.Name,
		"nginx_host":     host,
		"nginx_port":     port,
		"web_system":     "nginx",
	}
}

// splitHostPort extracts host and port from a URL string. Returns ("", "") on
// parse failure so the label set is always well-formed.
func splitHostPort(rawURL string) (host, port string) {
	if rawURL == "" {
		return "", ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", ""
	}
	host = u.Hostname()
	port = u.Port()
	return host, port
}

// BuildNginxMetrics maps a parsed stubStats into collector.Metric under the
// web.nginx.* namespace. Exported for external test coverage.
func BuildNginxMetrics(labels map[string]string, s stubStats, now time.Time) []collector.Metric {
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string) collector.Metric {
		m := collector.Metric{
			Name: name, Type: typ, Value: v, Timestamp: now,
			Unit: unit, Description: desc,
			Labels: make(map[string]string, len(labels)),
		}
		for k, val := range labels {
			m.Labels[k] = val
		}
		return m
	}
	gauge := func(suffix string, v float64, unit, desc string) collector.Metric {
		return mk("web.nginx."+suffix, v, collector.MetricTypeGauge, unit, desc)
	}
	counter := func(suffix string, v float64, unit, desc string) collector.Metric {
		return mk("web.nginx."+suffix, v, collector.MetricTypeCounter, unit, desc)
	}
	return []collector.Metric{
		gauge("state", 1, "", "Stub_status scrape state: 1=ok, 0=fail"),
		gauge("connections_active", float64(s.active), "", "Active client connections"),
		counter("connections_accepted_total", float64(s.accepts), "", "Total accepted connections"),
		counter("connections_handled_total", float64(s.handled), "", "Total handled connections"),
		counter("requests_total", float64(s.requests), "", "Total client requests"),
		gauge("connections_reading", float64(s.reading), "", "Connections reading request headers"),
		gauge("connections_writing", float64(s.writing), "", "Connections writing response to client"),
		gauge("connections_waiting", float64(s.waiting), "", "Idle long-poll waiting connections"),
	}
}
