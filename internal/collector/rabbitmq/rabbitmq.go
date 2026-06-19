// Package rabbitmq implements a TelemetryFlow Agent collector for RabbitMQ
// brokers via the Management HTTP API. It scrapes /api/overview, /api/nodes
// and /api/queues (per vhost) and emits metrics under the queue.rabbitmq.*
// namespace. No external client library is required.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package rabbitmq

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "rabbitmq"

// RabbitMQCollector monitors one or more RabbitMQ brokers via the Management API.
type RabbitMQCollector struct {
	cfg    config.RabbitMQCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewRabbitMQCollector creates a new RabbitMQCollector.
func NewRabbitMQCollector(cfg config.RabbitMQCollectorConfig, logger *zap.Logger) *RabbitMQCollector {
	if cfg.OverviewInterval == 0 {
		cfg.OverviewInterval = 15 * time.Second
	}
	if cfg.QueueInterval == 0 {
		cfg.QueueInterval = 30 * time.Second
	}
	if cfg.NodeInterval == 0 {
		cfg.NodeInterval = 30 * time.Second
	}
	return &RabbitMQCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *RabbitMQCollector) Name() string { return collectorName }

func (c *RabbitMQCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *RabbitMQCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("rabbitmq collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("RabbitMQ collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("overview_interval", c.cfg.OverviewInterval),
	)
	return nil
}

func (c *RabbitMQCollector) Stop() error {
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
func (c *RabbitMQCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		metrics, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("RabbitMQ collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *RabbitMQCollector) collectInstance(ctx context.Context, inst config.RabbitMQInstanceConfig) ([]collector.Metric, error) {
	client, err := newMgmtClient(inst)
	if err != nil {
		return nil, err
	}

	var queueFilter *regexp.Regexp
	if inst.QueueFilter != "" {
		re, err := regexp.Compile(inst.QueueFilter)
		if err != nil {
			return nil, fmt.Errorf("queue_filter: %w", err)
		}
		queueFilter = re
	}

	labels := c.instanceLabels(inst)

	var overview OverviewResponse
	if err := client.getJSON(ctx, "/api/overview", &overview); err != nil {
		return nil, fmt.Errorf("overview: %w", err)
	}

	var nodes []NodeResponse
	if err := client.getJSON(ctx, "/api/nodes", &nodes); err != nil {
		c.logger.Warn("RabbitMQ /api/nodes failed", zap.String("instance", inst.Name), zap.Error(err))
	}

	queuesPath := "/api/queues"
	if inst.Vhost != "" {
		queuesPath = "/api/queues/" + pathEscape(inst.Vhost)
	}
	var queues []QueueResponse
	if err := client.getJSON(ctx, queuesPath, &queues); err != nil {
		c.logger.Warn("RabbitMQ /api/queues failed", zap.String("instance", inst.Name), zap.Error(err))
	}

	return BuildRabbitMQMetrics(labels, overview, nodes, queues, queueFilter), nil
}

func (c *RabbitMQCollector) instanceLabels(inst config.RabbitMQInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["rabbitmq_instance"] = inst.Name
	labels["messaging_system"] = "rabbitmq"
	return labels
}

// mgmtClient is a minimal HTTP client for the RabbitMQ Management API.
type mgmtClient struct {
	baseURL string
	hc      *http.Client
	req     func(method, url string, body io.Reader) (*http.Request, error)
}

func newMgmtClient(inst config.RabbitMQInstanceConfig) (*mgmtClient, error) {
	if inst.URL == "" {
		return nil, fmt.Errorf("rabbitmq instance %q: url is required", inst.Name)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: inst.TLSSkipVerify},
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: transport}
	mc := &mgmtClient{
		baseURL: strings.TrimRight(inst.URL, "/"),
		hc:      hc,
		req:     http.NewRequest,
	}
	if inst.Username != "" || inst.Password != "" {
		baseReq := mc.req
		mc.req = func(method, url string, body io.Reader) (*http.Request, error) {
			r, err := baseReq(method, url, body)
			if err != nil {
				return nil, err
			}
			r.SetBasicAuth(inst.Username, inst.Password)
			return r, nil
		}
	}
	return mc, nil
}

func (c *mgmtClient) getJSON(ctx context.Context, path string, target any) error {
	url := c.baseURL + path
	req, err := c.req(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")
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

// pathEscape percent-encodes a vhost path segment.
func pathEscape(s string) string {
	return strings.ReplaceAll(s, "/", "%2F")
}

// =====================================================================
// API response types (only fields we expose as metrics).
// =====================================================================

// OverviewResponse models the /api/overview document.
type OverviewResponse struct {
	Node          string           `json:"node"`
	ClusterName   string           `json:"cluster_name"`
	RabbitMQVer   string           `json:"rabbitmq_version"`
	ManagementVer string           `json:"management_version"`
	ErlangVer     string           `json:"(erlang_version)"`
	ObjectTotals  ObjectTotals     `json:"object_totals"`
	QueueTotals   QueueTotals      `json:"queue_totals"`
	MessageStats  MessageStats     `json:"message_stats"`
	Listeners     []map[string]any `json:"listeners"`
	Contexts      []map[string]any `json:"contexts"`
}

// ObjectTotals counts connections/channels/queues/consumers/exchanges.
type ObjectTotals struct {
	Consumers   int `json:"consumers"`
	Queues      int `json:"queues"`
	Exchanges   int `json:"exchanges"`
	Connections int `json:"connections"`
	Channels    int `json:"channels"`
}

// QueueTotals is the cluster-wide message breakdown.
type QueueTotals struct {
	Messages               int `json:"messages"`
	MessagesReady          int `json:"messages_ready"`
	MessagesUnacknowledged int `json:"messages_unacknowledged"`
}

// MessageStats holds cluster-wide counters/rates for message flow.
type MessageStats struct {
	Publish           float64 `json:"publish"`
	PublishDetails    Rate    `json:"publish_details"`
	Ack               float64 `json:"ack"`
	AckDetails        Rate    `json:"ack_details"`
	Deliver           float64 `json:"deliver"`
	DeliverDetails    Rate    `json:"deliver_details"`
	DeliverGet        float64 `json:"deliver_get"`
	DeliverGetDetails Rate    `json:"deliver_get_details"`
	Redeliver         float64 `json:"redeliver"`
	RedeliverDetails  Rate    `json:"redeliver_details"`
	ReturnUnroutable  float64 `json:"return_unroutable"`
	DropUnroutable    float64 `json:"drop_unroutable"`
}

// Rate is the RabbitMQ "{rate}" object.
type Rate struct {
	Rate float64 `json:"rate"`
}

// NodeResponse models an entry in /api/nodes.
type NodeResponse struct {
	Name          string `json:"name"`
	Running       bool   `json:"running"`
	MemUsed       int64  `json:"mem_used"`
	MemLimit      int64  `json:"mem_limit"`
	MemAlarm      bool   `json:"mem_alarm"`
	DiskFree      int64  `json:"disk_free"`
	DiskFreeLimit int64  `json:"disk_free_limit"`
	DiskAlarm     bool   `json:"disk_alarm"`
	FDUsed        int64  `json:"fd_used"`
	FDTotal       int64  `json:"fd_total"`
	SocketsUsed   int64  `json:"sockets_used"`
	SocketsTotal  int64  `json:"sockets_total"`
	ProcUsed      int64  `json:"proc_used"`
	ProcTotal     int64  `json:"proc_total"`
	RunQueue      int64  `json:"run_queue"`
	Uptime        int64  `json:"uptime"`
	GCNum         int64  `json:"gc_num"`
	GCBytes       int64  `json:"gc_bytes_reclaimed"`
}

// QueueResponse models an entry in /api/queues.
type QueueResponse struct {
	Name                   string            `json:"name"`
	Vhost                  string            `json:"vhost"`
	Type                   string            `json:"type"`
	Node                   string            `json:"node"`
	State                  string            `json:"state"`
	Messages               int               `json:"messages"`
	MessagesReady          int               `json:"messages_ready"`
	MessagesUnacknowledged int               `json:"messages_unacknowledged"`
	Consumers              int               `json:"consumers"`
	Memory                 int64             `json:"memory"`
	MessageStats           QueueMessageStats `json:"message_stats"`
}

// QueueMessageStats holds per-queue counters.
type QueueMessageStats struct {
	Publish        float64 `json:"publish"`
	PublishDetails Rate    `json:"publish_details"`
	Ack            float64 `json:"ack"`
	AckDetails     Rate    `json:"ack_details"`
	Deliver        float64 `json:"deliver"`
	DeliverDetails Rate    `json:"deliver_details"`
	DeliverGet     float64 `json:"deliver_get"`
	Redeliver      float64 `json:"redeliver"`
}

// =====================================================================
// Metric building.
// =====================================================================

// BuildRabbitMQMetrics maps the Management API responses to collector.Metric
// under the queue.rabbitmq.* namespace. Exported for external test coverage.
func BuildRabbitMQMetrics(
	labels map[string]string,
	overview OverviewResponse,
	nodes []NodeResponse,
	queues []QueueResponse,
	queueFilter *regexp.Regexp,
) []collector.Metric {
	now := time.Now()
	mk := func(name string, v float64, typ collector.MetricType, unit, desc string, extra map[string]string) collector.Metric {
		m := collector.Metric{
			Name: name, Type: typ, Value: v, Timestamp: now,
			Unit: unit, Description: desc,
			Labels: make(map[string]string, len(labels)+len(extra)),
		}
		for k, val := range labels {
			m.Labels[k] = val
		}
		for k, val := range extra {
			m.Labels[k] = val
		}
		return m
	}
	base := labels
	gauge := func(name string, v float64, unit, desc string, extra map[string]string) collector.Metric {
		return mk("queue.rabbitmq."+name, v, collector.MetricTypeGauge, unit, desc, extra)
	}
	counter := func(name string, v float64, unit, desc string, extra map[string]string) collector.Metric {
		return mk("queue.rabbitmq."+name, v, collector.MetricTypeCounter, unit, desc, extra)
	}

	out := make([]collector.Metric, 0, 40+len(nodes)*16+len(queues)*12)

	// Cluster-wide object totals.
	out = append(out,
		gauge("connections", float64(overview.ObjectTotals.Connections), "", "Cluster connections", nil),
		gauge("channels", float64(overview.ObjectTotals.Channels), "", "Cluster channels", nil),
		gauge("queues.total", float64(overview.ObjectTotals.Queues), "", "Cluster queue count", nil),
		gauge("exchanges", float64(overview.ObjectTotals.Exchanges), "", "Cluster exchanges", nil),
		gauge("consumers", float64(overview.ObjectTotals.Consumers), "", "Cluster consumers", nil),
	)
	// Cluster-wide queue totals.
	out = append(out,
		gauge("messages", float64(overview.QueueTotals.Messages), "", "Cluster messages across all queues", nil),
		gauge("messages_ready", float64(overview.QueueTotals.MessagesReady), "", "Cluster messages ready for delivery", nil),
		gauge("messages_unacknowledged", float64(overview.QueueTotals.MessagesUnacknowledged), "", "Cluster messages awaiting acknowledgement", nil),
	)
	// Cluster-wide message stats (counters + rates).
	ms := overview.MessageStats
	out = append(out,
		counter("messages_published", ms.Publish, "", "Cluster messages published", nil),
		gauge("publish_rate", ms.PublishDetails.Rate, "msg/s", "Cluster publish rate", nil),
		counter("messages_acked", ms.Ack, "", "Cluster messages acknowledged", nil),
		gauge("ack_rate", ms.AckDetails.Rate, "msg/s", "Cluster ack rate", nil),
		counter("messages_delivered", ms.Deliver, "", "Cluster messages delivered", nil),
		gauge("deliver_rate", ms.DeliverDetails.Rate, "msg/s", "Cluster deliver rate", nil),
		counter("messages_delivered_get", ms.DeliverGet, "", "Cluster messages delivered via basic.get", nil),
		gauge("deliver_get_rate", ms.DeliverGetDetails.Rate, "msg/s", "Cluster basic.get rate", nil),
		counter("messages_redelivered", ms.Redeliver, "", "Cluster messages redelivered", nil),
		gauge("redeliver_rate", ms.RedeliverDetails.Rate, "msg/s", "Cluster redeliver rate", nil),
		counter("messages_unroutable_returned", ms.ReturnUnroutable, "", "Unroutable messages returned to publisher", nil),
		counter("messages_unroutable_dropped", ms.DropUnroutable, "", "Unroutable messages dropped", nil),
	)

	// Per-node metrics.
	for _, n := range nodes {
		nodeLabels := withLabel(base, "rabbitmq_node", n.Name)
		running := 0.0
		if n.Running {
			running = 1
		}
		memAlarm := 0.0
		if n.MemAlarm {
			memAlarm = 1
		}
		diskAlarm := 0.0
		if n.DiskAlarm {
			diskAlarm = 1
		}
		out = append(out,
			gauge("node.running", running, "", "Node running flag (1=running)", nodeLabels),
			gauge("node.mem_used", float64(n.MemUsed), "bytes", "Memory used by node", nodeLabels),
			gauge("node.mem_limit", float64(n.MemLimit), "bytes", "Memory high-watermark limit", nodeLabels),
			gauge("node.mem_alarm", memAlarm, "", "Memory alarm active (1=active)", nodeLabels),
			gauge("node.disk_free", float64(n.DiskFree), "bytes", "Free disk space", nodeLabels),
			gauge("node.disk_free_limit", float64(n.DiskFreeLimit), "bytes", "Disk free limit", nodeLabels),
			gauge("node.disk_alarm", diskAlarm, "", "Disk alarm active (1=active)", nodeLabels),
			gauge("node.fd_used", float64(n.FDUsed), "", "File descriptors used", nodeLabels),
			gauge("node.fd_total", float64(n.FDTotal), "", "File descriptors available", nodeLabels),
			gauge("node.sockets_used", float64(n.SocketsUsed), "", "Sockets used", nodeLabels),
			gauge("node.sockets_total", float64(n.SocketsTotal), "", "Sockets available", nodeLabels),
			gauge("node.proc_used", float64(n.ProcUsed), "", "Erlang processes used", nodeLabels),
			gauge("node.proc_total", float64(n.ProcTotal), "", "Erlang process limit", nodeLabels),
			gauge("node.run_queue", float64(n.RunQueue), "", "Erlang run queue length", nodeLabels),
			gauge("node.uptime", float64(n.Uptime), "ms", "Node uptime", nodeLabels),
			counter("node.gc_num", float64(n.GCNum), "", "GC cycles", nodeLabels),
			counter("node.gc_bytes_reclaimed", float64(n.GCBytes), "bytes", "Bytes reclaimed by GC", nodeLabels),
		)
	}

	// Per-queue metrics.
	for _, q := range queues {
		if queueFilter != nil && !queueFilter.MatchString(q.Name) {
			continue
		}
		qlabels := withLabel(base, "rabbitmq_queue", q.Name)
		qlabels = withLabel(qlabels, "rabbitmq_vhost", q.Vhost)
		qlabels = withLabel(qlabels, "rabbitmq_queue_node", q.Node)
		qlabels = withLabel(qlabels, "rabbitmq_queue_type", q.Type)
		out = append(out,
			gauge("queue.messages", float64(q.Messages), "", "Messages in queue", qlabels),
			gauge("queue.messages_ready", float64(q.MessagesReady), "", "Messages ready for delivery", qlabels),
			gauge("queue.messages_unacknowledged", float64(q.MessagesUnacknowledged), "", "Messages awaiting acknowledgement", qlabels),
			gauge("queue.consumers", float64(q.Consumers), "", "Consumers attached to queue", qlabels),
			gauge("queue.memory", float64(q.Memory), "bytes", "Memory used by queue", qlabels),
			counter("queue.messages_published", q.MessageStats.Publish, "", "Messages published to queue", qlabels),
			gauge("queue.publish_rate", q.MessageStats.PublishDetails.Rate, "msg/s", "Publish rate", qlabels),
			counter("queue.messages_acked", q.MessageStats.Ack, "", "Messages acked from queue", qlabels),
			gauge("queue.ack_rate", q.MessageStats.AckDetails.Rate, "msg/s", "Ack rate", qlabels),
			counter("queue.messages_delivered", q.MessageStats.Deliver, "", "Messages delivered from queue", qlabels),
			gauge("queue.deliver_rate", q.MessageStats.DeliverDetails.Rate, "msg/s", "Deliver rate", qlabels),
			counter("queue.messages_redelivered", q.MessageStats.Redeliver, "", "Messages redelivered from queue", qlabels),
		)
	}

	return out
}

func withLabel(base map[string]string, key, val string) map[string]string {
	out := make(map[string]string, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[key] = val
	return out
}
