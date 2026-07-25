// Package apache implements a TelemetryFlow Agent collector that scrapes the
// Apache HTTPD server-status endpoint (mod_status with ?auto) and emits metrics
// under the web.apache.* namespace. It uses the Go standard library only.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package apache

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "apache"

// scoreboardStates maps a single Apache scoreboard character to the metric
// suffix used for web.apache.scoreboard_<state>. See mod_status documentation
// for the full character set.
var scoreboardStates = map[byte]string{
	'_': "waiting",
	'S': "starting",
	'R': "reading",
	'W': "sending",
	'K': "keepalive",
	'D': "dns_lookup",
	'C': "closing",
	'L': "logging",
	'G': "finishing",
	'I': "idle_cleanup",
	'.': "open_slot",
}

// ApacheCollector monitors one or more Apache HTTPD instances via server-status.
type ApacheCollector struct {
	cfg      config.ApacheCollectorConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewApacheCollector constructs a new Apache server-status collector.
func NewApacheCollector(cfg config.ApacheCollectorConfig, logger *zap.Logger) *ApacheCollector {
	return &ApacheCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *ApacheCollector) Name() string { return collectorName }

func (c *ApacheCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *ApacheCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("apache collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.logger.Info("Apache collector starting", zap.Int("instances", len(c.cfg.Instances)))
	return nil
}

func (c *ApacheCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	c.running = false
	close(c.stopChan)
	return nil
}

// Collect performs one collection cycle across all configured instances,
// honoring context cancellation between instances.
func (c *ApacheCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
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

// collectInstance scrapes a single Apache server-status endpoint and returns
// the resulting metrics. Transport-level failures and non-200 responses yield a
// state=0 metric set rather than an error so that the agent keeps cycling.
func (c *ApacheCollector) collectInstance(ctx context.Context, inst config.ApacheInstance) []collector.Metric {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	labels := instanceLabels(inst)
	now := time.Now()
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string) collector.Metric {
		m := collector.Metric{
			Name:        name,
			Type:        typ,
			Value:       v,
			Timestamp:   now,
			Unit:        unit,
			Description: desc,
			Labels:      make(map[string]string, len(labels)),
		}
		for k, val := range labels {
			m.Labels[k] = val
		}
		return m
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: inst.TLSSkipVerify,
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, inst.URL, nil)
	if err != nil {
		c.logger.Warn("Apache request build failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(mk)
	}
	if inst.Username != "" || inst.Password != "" {
		req.SetBasicAuth(inst.Username, inst.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debug("Apache scrape request failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(mk)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("Apache scrape non-200",
			zap.String("instance", inst.Name), zap.Int("status", resp.StatusCode))
		return failureMetrics(mk)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug("Apache scrape read failed",
			zap.String("instance", inst.Name), zap.Error(err))
		return failureMetrics(mk)
	}

	stats, scoreboard, ok := parseServerStatus(string(body))
	if !ok {
		c.logger.Debug("Apache scrape malformed body",
			zap.String("instance", inst.Name))
		return failureMetrics(mk)
	}
	return BuildApacheMetrics(stats, scoreboard, mk)
}

// parseServerStatus parses the plain-text server-status?auto response into a
// key/value map and the raw Scoreboard string. The boolean return is false when
// the body does not look like a server-status response (no recognizable keys).
func parseServerStatus(body string) (stats map[string]string, scoreboard string, ok bool) {
	stats = make(map[string]string)
	recognized := 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "Scoreboard" {
			scoreboard = val
			recognized++
			continue
		}
		stats[key] = val
		recognized++
	}
	if recognized == 0 {
		return stats, scoreboard, false
	}
	return stats, scoreboard, true
}

// BuildApacheMetrics maps parsed server-status values to collector.Metric under
// the web.apache.* namespace. The mk closure supplies shared labels/timestamp.
func BuildApacheMetrics(stats map[string]string, scoreboard string, mk metricBuilder) []collector.Metric {
	var out []collector.Metric
	gauge := func(key, metric, unit, desc string) {
		if raw, found := stats[key]; found {
			out = append(out, mk("web.apache."+metric, toF(raw), collector.MetricTypeGauge, unit, desc))
		}
	}
	counter := func(key, metric, unit, desc string) {
		if raw, found := stats[key]; found {
			out = append(out, mk("web.apache."+metric, toF(raw), collector.MetricTypeCounter, unit, desc))
		}
	}

	out = append(out, mk("web.apache.state", 1, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail"))
	counter("Total Accesses", "requests_total", "", "Total access count")
	if raw, found := stats["Total kBytes"]; found {
		out = append(out, mk("web.apache.bytes_served_total", toF(raw)*1024, collector.MetricTypeCounter, "bytes", "Total bytes served"))
	}
	gauge("CPULoad", "cpu_load", "", "CPU load")
	gauge("Uptime", "uptime_seconds", "s", "Server uptime in seconds")
	gauge("ReqPerSec", "requests_per_second", "req/s", "Requests per second")
	gauge("BytesPerSec", "bytes_per_second", "bytes/s", "Bytes per second")
	gauge("BytesPerReq", "bytes_per_request", "bytes", "Bytes per request")
	gauge("BusyWorkers", "workers_busy", "", "Busy workers")
	gauge("IdleWorkers", "workers_idle", "", "Idle workers")

	counts := countScoreboard(scoreboard)
	for _, state := range scoreboardStates {
		out = append(out, mk("web.apache.scoreboard_"+state, float64(counts[state]), collector.MetricTypeGauge, "", "Scoreboard workers in "+state+" state"))
	}
	return out
}

// countScoreboard tallies each scoreboard character into the corresponding
// state name. Unknown characters are ignored.
func countScoreboard(scoreboard string) map[string]int {
	counts := make(map[string]int)
	for i := 0; i < len(scoreboard); i++ {
		if state, known := scoreboardStates[scoreboard[i]]; known {
			counts[state]++
		}
	}
	return counts
}

// failureMetrics is the state=0 metric set emitted when the scrape did not
// produce a usable server-status body.
func failureMetrics(mk metricBuilder) []collector.Metric {
	return []collector.Metric{
		mk("web.apache.state", 0, collector.MetricTypeGauge, "", "Scrape state: 1=ok, 0=fail"),
	}
}

// metricBuilder is the closure signature used to assemble metrics with shared
// labels and timestamp.
type metricBuilder func(name string, v float64, typ collector.MetricType, unit, desc string) collector.Metric

// instanceLabels builds the standard label set for an instance, deriving host
// and port from the URL when possible.
func instanceLabels(inst config.ApacheInstance) map[string]string {
	name := inst.Name
	if name == "" {
		name = inst.URL
	}
	host, port := "", ""
	if u, err := url.Parse(inst.URL); err == nil {
		host = u.Hostname()
		port = u.Port()
	}
	return map[string]string{
		"apache_instance": name,
		"apache_host":     host,
		"apache_port":     port,
	}
}

func toF(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
