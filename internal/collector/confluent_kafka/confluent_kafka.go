// Package confluent_kafka implements a TelemetryFlow Agent collector for
// Confluent Cloud / Confluent Platform Kafka clusters via the Confluent
// Metrics HTTP query API. It POSTs aggregate metric queries grouped by topic
// and emits metrics under the queue.confluent_kafka.* namespace.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package confluent_kafka

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "confluent_kafka"

// metricQuery maps a Confluent Metrics API metric identifier to its
// aggregation and the emitted metric suffix.
type metricQuery struct {
	metric string
	agg    string
	suffix string
	typ    collector.MetricType
	unit   string
	desc   string
}

// standardQueries is the default metric set collected per topic.
var standardQueries = []metricQuery{
	{metric: "io.confluent.kafka.server/received_bytes", agg: "SUM", suffix: "received_bytes", typ: collector.MetricTypeCounter, unit: "bytes", desc: "Bytes received from producers"},
	{metric: "io.confluent.kafka.server/sent_bytes", agg: "SUM", suffix: "sent_bytes", typ: collector.MetricTypeCounter, unit: "bytes", desc: "Bytes sent to consumers"},
	{metric: "io.confluent.kafka.server/received_records", agg: "SUM", suffix: "received_records", typ: collector.MetricTypeCounter, unit: "", desc: "Records received from producers"},
	{metric: "io.confluent.kafka.server/sent_records", agg: "SUM", suffix: "sent_records", typ: collector.MetricTypeCounter, unit: "", desc: "Records sent to consumers"},
	{metric: "io.confluent.kafka.server/retained_bytes", agg: "MAX", suffix: "retained_bytes", typ: collector.MetricTypeGauge, unit: "bytes", desc: "Bytes retained"},
	{metric: "io.confluent.kafka.server/partition_count", agg: "MAX", suffix: "partition_count", typ: collector.MetricTypeGauge, unit: "", desc: "Partition count"},
}

// ConfluentKafkaCollector monitors Confluent Kafka clusters via the Metrics API.
type ConfluentKafkaCollector struct {
	cfg    config.ConfluentKafkaCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewConfluentKafkaCollector creates a new ConfluentKafkaCollector.
func NewConfluentKafkaCollector(cfg config.ConfluentKafkaCollectorConfig, logger *zap.Logger) *ConfluentKafkaCollector {
	if cfg.QueryInterval == 0 {
		cfg.QueryInterval = 30 * time.Second
	}
	return &ConfluentKafkaCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *ConfluentKafkaCollector) Name() string { return collectorName }

func (c *ConfluentKafkaCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *ConfluentKafkaCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("confluent_kafka collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("Confluent Kafka collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("query_interval", c.cfg.QueryInterval),
	)
	return nil
}

func (c *ConfluentKafkaCollector) Stop() error {
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
func (c *ConfluentKafkaCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		metrics, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("Confluent Kafka collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *ConfluentKafkaCollector) collectInstance(ctx context.Context, inst config.ConfluentKafkaInstanceConfig) ([]collector.Metric, error) {
	if inst.MetricsURL == "" {
		return nil, fmt.Errorf("confluent_kafka instance %q: metrics_url is required", inst.Name)
	}
	if inst.APIKey == "" || inst.APISecret == "" {
		return nil, fmt.Errorf("confluent_kafka instance %q: api_key and api_secret are required", inst.Name)
	}

	results, err := queryMetrics(ctx, inst, standardQueries)
	if err != nil {
		return nil, err
	}
	labels := c.instanceLabels(inst)
	return BuildConfluentKafkaMetrics(labels, standardQueries, results), nil
}

func (c *ConfluentKafkaCollector) instanceLabels(inst config.ConfluentKafkaInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["confluent_kafka_instance"] = inst.Name
	labels["queueing_system"] = "confluent_kafka"
	if inst.Cluster != "" {
		labels["kafka_cluster"] = inst.Cluster
	}
	return labels
}

// =====================================================================
// Metrics API request/response types.
// =====================================================================

type queryRequest struct {
	Aggregations []aggregation `json:"aggregations"`
	Filter       *queryFilter  `json:"filter,omitempty"`
	Granularity  string        `json:"granularity"`
	GroupBy      []string      `json:"group_by"`
	Intervals    []string      `json:"intervals"`
}

type aggregation struct {
	Metric string `json:"metric"`
	Agg    string `json:"agg"`
}

type queryFilter struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type queryResponse struct {
	Data []dataPoint `json:"data"`
}

type dataPoint struct {
	Timestamp string            `json:"timestamp"`
	Value     float64           `json:"value"`
	Metric    string            `json:"metric"`
	Subject   map[string]string `json:"subject"`
}

// queryMetrics issues one POST containing all aggregations for the latest
// window and returns the raw data points.
func queryMetrics(ctx context.Context, inst config.ConfluentKafkaInstanceConfig, queries []metricQuery) ([]dataPoint, error) {
	end := time.Now().UTC().Truncate(time.Minute)
	start := end.Add(-2 * time.Minute)
	intervals := []string{fmt.Sprintf("%s/%s", start.Format(time.RFC3339), end.Format(time.RFC3339))}

	aggs := make([]aggregation, 0, len(queries))
	for _, q := range queries {
		aggs = append(aggs, aggregation{Metric: q.metric, Agg: q.agg})
	}

	reqBody := queryRequest{
		Aggregations: aggs,
		Granularity:  "PT1M",
		GroupBy:      []string{"metric.label.topic"},
		Intervals:    intervals,
	}
	if inst.Cluster != "" {
		reqBody.Filter = &queryFilter{
			Field: "metric.label.cluster_id",
			Op:    "EQ",
			Value: inst.Cluster,
		}
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inst.MetricsURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(inst.APIKey, inst.APISecret)

	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metrics query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("metrics query: HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 256))
	}

	var qr queryResponse
	if err := json.Unmarshal(respBody, &qr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return qr.Data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// =====================================================================
// Metric building.
// =====================================================================

// BuildConfluentKafkaMetrics maps Confluent Metrics API data points to
// collector.Metric under the queue.confluent_kafka.* namespace. The most
// recent data point per (topic, metric) is emitted. Exported for external
// test coverage.
func BuildConfluentKafkaMetrics(labels map[string]string, queries []metricQuery, points []dataPoint) []collector.Metric {
	metricBySuffix := make(map[string]metricQuery, len(queries))
	for _, q := range queries {
		metricBySuffix[q.metric] = q
	}

	// latest[(topic|metric)] keeps the most recent timestamp per topic+metric.
	type key struct{ topic, metric string }
	latest := make(map[key]dataPoint)
	for _, p := range points {
		topic := p.Subject["topic"]
		k := key{topic: topic, metric: p.Metric}
		if cur, ok := latest[k]; !ok || p.Timestamp >= cur.Timestamp {
			latest[k] = p
		}
	}

	out := make([]collector.Metric, 0, len(latest))
	now := time.Now()
	for k, p := range latest {
		q, ok := metricBySuffix[k.metric]
		if !ok {
			continue
		}
		lbl := make(map[string]string, len(labels)+1)
		for kk, vv := range labels {
			lbl[kk] = vv
		}
		if k.topic != "" {
			lbl["kafka_topic"] = k.topic
		}
		// Pull additional subject labels (partition_count etc. carry no topic).
		for sk, sv := range p.Subject {
			if sk == "topic" {
				continue
			}
			lbl["confluent_"+strings.ToLower(sk)] = sv
		}
		out = append(out, collector.Metric{
			Name: "queue.confluent_kafka." + q.suffix,
			Type: q.typ, Value: p.Value, Timestamp: now,
			Unit: q.unit, Description: q.desc, Labels: lbl,
		})
	}
	return out
}
