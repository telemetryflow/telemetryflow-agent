// Package nats implements a TelemetryFlow Agent collector for NATS servers
// via the built-in HTTP monitoring API (/varz, /connz, /routez, /subsz, /jsz).
// Metrics are emitted under the messaging.nats.* namespace. No external
// client library is required.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package nats

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "nats"

// NATSCollector monitors one or more NATS servers via the monitoring API.
type NATSCollector struct {
	cfg    config.NATSCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewNATSCollector creates a new NATSCollector.
func NewNATSCollector(cfg config.NATSCollectorConfig, logger *zap.Logger) *NATSCollector {
	if cfg.StatsInterval == 0 {
		cfg.StatsInterval = 15 * time.Second
	}
	return &NATSCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *NATSCollector) Name() string { return collectorName }

func (c *NATSCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *NATSCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("nats collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("NATS collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("stats_interval", c.cfg.StatsInterval),
	)
	return nil
}

func (c *NATSCollector) Stop() error {
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
func (c *NATSCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		metrics, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("NATS collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *NATSCollector) collectInstance(ctx context.Context, inst config.NATSInstanceConfig) ([]collector.Metric, error) {
	if inst.URL == "" {
		return nil, fmt.Errorf("nats instance %q: url is required", inst.Name)
	}
	client := newMonitorClient(inst)

	var varz VarzResponse
	if err := client.getJSON(ctx, "/varz", &varz); err != nil {
		return nil, fmt.Errorf("varz: %w", err)
	}
	var connz ConnzResponse
	if err := client.getJSON(ctx, "/connz", &connz); err != nil {
		c.logger.Warn("NATS /connz failed", zap.String("instance", inst.Name), zap.Error(err))
	}
	var routez RoutezResponse
	if err := client.getJSON(ctx, "/routez", &routez); err != nil {
		c.logger.Warn("NATS /routez failed", zap.String("instance", inst.Name), zap.Error(err))
	}
	var subsz SubszResponse
	if err := client.getJSON(ctx, "/subsz", &subsz); err != nil {
		c.logger.Warn("NATS /subsz failed", zap.String("instance", inst.Name), zap.Error(err))
	}
	var jsz JSzResponse
	if inst.CollectJetStream {
		if err := client.getJSON(ctx, "/jsz", &jsz); err != nil {
			c.logger.Warn("NATS /jsz failed", zap.String("instance", inst.Name), zap.Error(err))
		}
	}

	labels := c.instanceLabels(inst)
	return BuildNATSMetrics(labels, varz, connz, routez, subsz, jsz), nil
}

func (c *NATSCollector) instanceLabels(inst config.NATSInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["nats_instance"] = inst.Name
	labels["messaging_system"] = "nats"
	return labels
}

// monitorClient is a minimal HTTP client for the NATS monitoring endpoints.
type monitorClient struct {
	baseURL string
	hc      *http.Client
}

func newMonitorClient(inst config.NATSInstanceConfig) *monitorClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: inst.TLSSkipVerify},
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	return &monitorClient{baseURL: inst.URL, hc: hc}
}

func (c *monitorClient) getJSON(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	// NATS monitoring supports basic auth optionally.
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// =====================================================================
// Monitoring API response types (only fields we expose as metrics).
// =====================================================================

// VarzResponse models the /varz document.
type VarzResponse struct {
	ServerID      string     `json:"server_id"`
	ServerName    string     `json:"server_name"`
	Version       string     `json:"version"`
	GoVersion     string     `json:"go"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	MaxPayload    int64      `json:"max_payload"`
	Proto         int        `json:"proto"`
	MaxConn       int        `json:"max_connections"`
	MaxSubs       int        `json:"max_subscriptions"`
	Now           *time.Time `json:"now"`
	Uptime        string     `json:"uptime"`
	Mem           int64      `json:"mem"`
	Cores         int        `json:"cores"`
	CPU           float64    `json:"cpu"`
	Connections   int        `json:"connections"`
	TotalConns    int        `json:"total_connections"`
	Subscriptions int        `json:"subscriptions"`
	Sent          Stats      `json:"sent"`
	Received      Stats      `json:"received"`
	SlowConsumers int        `json:"slow_consumers"`
	Routes        []any      `json:"routes"`
	Gateways      []any      `json:"gateways"`
}

// Stats is the {msgs, bytes} object used in /varz.
type Stats struct {
	Msgs  int64 `json:"msgs"`
	Bytes int64 `json:"bytes"`
}

// ConnzResponse models /connz.
type ConnzResponse struct {
	Now      *time.Time `json:"now"`
	NumConns int        `json:"num_connections"`
	Total    int        `json:"total"`
	Offset   int        `json:"offset"`
	Limit    int        `json:"limit"`
}

// RoutezResponse models /routez.
type RoutezResponse struct {
	Now       *time.Time `json:"now"`
	NumRoutes int        `json:"num_routes"`
}

// SubszResponse models /subsz.
type SubszResponse struct {
	NumSubscriptions int     `json:"num_subscriptions"`
	NumCache         int     `json:"num_cache"`
	NumInserts       int     `json:"num_inserts"`
	NumRemoves       int     `json:"num_removes"`
	MatchLen         int     `json:"match_len"`
	CacheHitRate     float64 `json:"cache_hit_rate"`
}

// JSzResponse models /jsz (JetStream summary).
type JSzResponse struct {
	Memory         uint64 `json:"memory"`
	Store          uint64 `json:"store"`
	ReservedMemory uint64 `json:"reserved_memory"`
	ReservedStore  uint64 `json:"reserved_store"`
	Accounts       int    `json:"account_count"`
	Streams        int    `json:"stream_count"`
	Consumers      int    `json:"consumer_count"`
	Messages       int64  `json:"messages"`
	Bytes          int64  `json:"bytes"`
}

// =====================================================================
// Metric building.
// =====================================================================

// BuildNATSMetrics maps monitoring API responses to collector.Metric under
// the messaging.nats.* namespace. Exported for external test coverage.
func BuildNATSMetrics(
	labels map[string]string,
	varz VarzResponse,
	connz ConnzResponse,
	routez RoutezResponse,
	subsz SubszResponse,
	jsz JSzResponse,
) []collector.Metric {
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
	gauge := func(suffix string, v float64, unit, desc string) collector.Metric {
		return mk("messaging.nats."+suffix, v, collector.MetricTypeGauge, unit, desc)
	}
	counter := func(suffix string, v float64, unit, desc string) collector.Metric {
		return mk("messaging.nats."+suffix, v, collector.MetricTypeCounter, unit, desc)
	}

	out := make([]collector.Metric, 0, 32)
	out = append(out,
		gauge("connections", float64(varz.Connections), "", "Active client connections"),
		counter("total_connections", float64(varz.TotalConns), "", "Total connections accepted"),
		gauge("subscriptions", float64(varz.Subscriptions), "", "Active subscriptions"),
		gauge("max_connections", float64(varz.MaxConn), "", "Max configured connections"),
		gauge("max_subscriptions", float64(varz.MaxSubs), "", "Max configured subscriptions"),
		gauge("slow_consumers", float64(varz.SlowConsumers), "", "Slow consumers"),
		gauge("cores", float64(varz.Cores), "", "CPU cores"),
		gauge("cpu", varz.CPU, "", "CPU usage"),
		gauge("mem", float64(varz.Mem), "bytes", "Process memory"),
		gauge("max_payload", float64(varz.MaxPayload), "bytes", "Max payload size"),
		counter("sent_msgs", float64(varz.Sent.Msgs), "", "Messages sent to clients"),
		counter("sent_bytes", float64(varz.Sent.Bytes), "bytes", "Bytes sent to clients"),
		counter("received_msgs", float64(varz.Received.Msgs), "", "Messages received from clients"),
		counter("received_bytes", float64(varz.Received.Bytes), "bytes", "Bytes received from clients"),
	)

	// /connz
	out = append(out,
		gauge("connz.num_connections", float64(connz.NumConns), "", "Connections reported by /connz"),
		gauge("connz.total", float64(connz.Total), "", "Total connections reported by /connz"),
	)
	// /routez
	out = append(out,
		gauge("routes", float64(routez.NumRoutes), "", "Active cluster routes"),
	)
	// /subsz
	out = append(out,
		gauge("subsz.num_subscriptions", float64(subsz.NumSubscriptions), "", "Cached subscriptions"),
		gauge("subsz.num_cache", float64(subsz.NumCache), "", "Subscription cache entries"),
		gauge("subsz.match_len", float64(subsz.MatchLen), "", "Subscription match list length"),
		gauge("subsz.cache_hit_rate", subsz.CacheHitRate, "ratio", "Subscription cache hit rate"),
	)

	// /jsz (JetStream) — only when populated.
	if jsz.Streams > 0 || jsz.Consumers > 0 || jsz.Messages > 0 || jsz.Bytes > 0 || jsz.Memory > 0 {
		out = append(out,
			gauge("jetstream.memory", float64(jsz.Memory), "bytes", "JetStream memory in use"),
			gauge("jetstream.store", float64(jsz.Store), "bytes", "JetStream disk store in use"),
			gauge("jetstream.streams", float64(jsz.Streams), "", "JetStream stream count"),
			gauge("jetstream.consumers", float64(jsz.Consumers), "", "JetStream consumer count"),
			counter("jetstream.messages", float64(jsz.Messages), "", "JetStream message count"),
			counter("jetstream.bytes", float64(jsz.Bytes), "bytes", "JetStream message bytes"),
		)
	}
	return out
}
