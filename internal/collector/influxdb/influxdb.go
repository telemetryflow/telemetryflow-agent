// Package influxdb implements a TelemetryFlow Agent collector for InfluxDB v1/v2
// instances. It scrapes the /debug/vars runtime endpoint and emits each numeric
// subsystem field under the db.influxdb.* namespace. No external client library
// is required.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package influxdb

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "influxdb"

// InfluxDBCollector monitors one or more InfluxDB instances via /debug/vars.
type InfluxDBCollector struct {
	cfg    config.InfluxDBCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewInfluxDBCollector creates a new InfluxDBCollector.
func NewInfluxDBCollector(cfg config.InfluxDBCollectorConfig, logger *zap.Logger) *InfluxDBCollector {
	if cfg.Interval == 0 {
		cfg.Interval = 15 * time.Second
	}
	return &InfluxDBCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *InfluxDBCollector) Name() string { return collectorName }

func (c *InfluxDBCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *InfluxDBCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("influxdb collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("InfluxDB collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("interval", c.cfg.Interval),
	)
	return nil
}

func (c *InfluxDBCollector) Stop() error {
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
func (c *InfluxDBCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		all = append(all, c.collectInstance(ctx, inst)...)
	}
	return all, nil
}

// collectInstance scrapes a single InfluxDB instance. Transport-level or parse
// failures produce a single db.influxdb.state=0 metric rather than an error.
func (c *InfluxDBCollector) collectInstance(ctx context.Context, inst config.InfluxDBInstance) []collector.Metric {
	if inst.URL == "" {
		c.logger.Warn("InfluxDB instance missing URL", zap.String("instance", inst.Name))
		return nil
	}
	client := newClient(inst)
	version := client.pingVersion(ctx)
	labels := instanceLabels(inst, version)

	body, _, err := client.getDebugVars(ctx)
	if err != nil {
		c.logger.Warn("InfluxDB /debug/vars request failed",
			zap.String("instance", inst.Name),
			zap.Error(err),
		)
		return []collector.Metric{stateMetric(labels, 0)}
	}
	metrics, err := BuildInfluxDBMetrics(labels, body)
	if err != nil {
		c.logger.Warn("InfluxDB /debug/vars parse failed",
			zap.String("instance", inst.Name),
			zap.Error(err),
		)
		return []collector.Metric{stateMetric(labels, 0)}
	}
	return append([]collector.Metric{stateMetric(labels, 1)}, metrics...)
}

// instanceLabels builds the standard label set for an instance.
func instanceLabels(inst config.InfluxDBInstance, version string) map[string]string {
	host := inst.URL
	if u, err := url.Parse(inst.URL); err == nil && u.Host != "" {
		host = u.Host
	}
	if version == "" {
		version = "unknown"
	}
	return map[string]string{
		"influxdb_instance": inst.Name,
		"influxdb_host":     host,
		"influxdb_version":  version,
		"db_system":         "influxdb",
	}
}

// stateMetric emits the db.influxdb.state gauge (1=ok, 0=fail).
func stateMetric(labels map[string]string, state float64) collector.Metric {
	now := time.Now()
	m := collector.Metric{
		Name:        "db.influxdb.state",
		Type:        collector.MetricTypeGauge,
		Value:       state,
		Timestamp:   now,
		Description: "InfluxDB instance reachability: 1=ok, 0=fail",
		Labels:      make(map[string]string, len(labels)),
	}
	for k, v := range labels {
		m.Labels[k] = v
	}
	return m
}

// =====================================================================
// HTTP client
// =====================================================================

// httpClient is a minimal client for the InfluxDB /ping and /debug/vars endpoints.
type httpClient struct {
	baseURL string
	inst    config.InfluxDBInstance
	hc      *http.Client
}

func newClient(inst config.InfluxDBInstance) *httpClient {
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: inst.TLSSkipVerify},
	}
	return &httpClient{
		baseURL: strings.TrimRight(inst.URL, "/"),
		inst:    inst,
		hc:      &http.Client{Timeout: timeout, Transport: transport},
	}
}

func (c *httpClient) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", path, err)
	}
	// Auth: prefer v2 token, fall back to v1 basic auth.
	if c.inst.Token != "" {
		req.Header.Set("Authorization", "Token "+c.inst.Token)
	} else if c.inst.Username != "" || c.inst.Password != "" {
		req.SetBasicAuth(c.inst.Username, c.inst.Password)
	}
	return c.hc.Do(req)
}

// pingVersion returns the X-Influxdb-Version header from /ping, or "unknown"
// on any failure. It is best-effort and never blocks /debug/vars collection.
func (c *httpClient) pingVersion(ctx context.Context) string {
	resp, err := c.do(ctx, http.MethodGet, "/ping")
	if err != nil {
		return "unknown"
	}
	defer func() { _ = resp.Body.Close() }()
	if v := resp.Header.Get("X-Influxdb-Version"); v != "" {
		return v
	}
	return "unknown"
}

// getDebugVars fetches the /debug/vars document. A non-2xx status is reported
// as an error so the caller can emit state=0.
func (c *httpClient) getDebugVars(ctx context.Context) ([]byte, int, error) {
	resp, err := c.do(ctx, http.MethodGet, "/debug/vars")
	if err != nil {
		return nil, 0, fmt.Errorf("request /debug/vars: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, fmt.Errorf("/debug/vars: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read /debug/vars: %w", err)
	}
	return body, resp.StatusCode, nil
}

// =====================================================================
// Metric building
// =====================================================================

// BuildInfluxDBMetrics walks a /debug/vars JSON document and emits db.influxdb.*
// metrics. cmdline and memstats are skipped at the top level; selected memstats
// fields are re-emitted under db.influxdb.mem.*. Each numeric leaf in any other
// subsystem becomes db.influxdb.<subsystem>.<field_snake_case>.
func BuildInfluxDBMetrics(labels map[string]string, body []byte) ([]collector.Metric, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode /debug/vars: %w", err)
	}
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
	var out []collector.Metric

	// Selected memstats fields.
	if memRaw, ok := raw["memstats"]; ok {
		var mem map[string]any
		if err := json.Unmarshal(memRaw, &mem); err == nil {
			if v, ok := numFloat(mem["Alloc"]); ok {
				out = append(out, mk("db.influxdb.mem.alloc_bytes", v, collector.MetricTypeGauge, "bytes", "Runtime memory Alloc in bytes"))
			}
			if v, ok := numFloat(mem["Sys"]); ok {
				out = append(out, mk("db.influxdb.mem.sys_bytes", v, collector.MetricTypeGauge, "bytes", "Runtime memory Sys in bytes"))
			}
			if v, ok := numFloat(mem["NumGC"]); ok {
				out = append(out, mk("db.influxdb.mem.num_gc", v, collector.MetricTypeCounter, "", "Runtime GC cycle count"))
			}
		}
	}

	// Walk all other subsystems (skip cmdline and memstats).
	for subsystem, rawVal := range raw {
		if subsystem == "cmdline" || subsystem == "memstats" {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal(rawVal, &fields); err != nil {
			continue
		}
		for field, val := range fields {
			v, ok := numFloat(val)
			if !ok {
				continue
			}
			name := "db.influxdb." + subsystem + "." + toSnake(field)
			out = append(out, mk(name, v, collector.MetricTypeGauge, "", subsystem+" "+field))
		}
	}
	return out, nil
}

// numFloat reports whether v is a JSON number and returns its float64 value.
func numFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// toSnake converts a camelCase identifier to snake_case.
func toSnake(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) && !unicode.IsUpper(runes[i-1]) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
