// Package kafka implements a TelemetryFlow Agent collector for Apache Kafka
// that scrapes a JMX Prometheus exporter HTTP endpoint (the standard sidecar
// deployment for Kafka brokers). It parses Prometheus text exposition and
// re-emits broker/topic metrics under the queue.kafka.* namespace with
// cluster and instance labels applied. No external Kafka client library is
// required.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0

package kafka

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const collectorName = "kafka"

// KafkaCollector monitors one or more Kafka brokers via JMX Prometheus exporters.
type KafkaCollector struct {
	cfg    config.KafkaCollectorConfig
	logger *zap.Logger

	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
}

// NewKafkaCollector creates a new KafkaCollector.
func NewKafkaCollector(cfg config.KafkaCollectorConfig, logger *zap.Logger) *KafkaCollector {
	if cfg.ScrapeInterval == 0 {
		cfg.ScrapeInterval = 15 * time.Second
	}
	return &KafkaCollector{
		cfg:      cfg,
		logger:   logger.Named(collectorName),
		stopChan: make(chan struct{}),
	}
}

func (c *KafkaCollector) Name() string { return collectorName }

func (c *KafkaCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func (c *KafkaCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("kafka collector already running")
	}
	c.running = true
	c.stopChan = make(chan struct{})
	c.mu.Unlock()
	c.logger.Info("Kafka collector starting",
		zap.Int("instances", len(c.cfg.Instances)),
		zap.Duration("scrape_interval", c.cfg.ScrapeInterval),
	)
	return nil
}

func (c *KafkaCollector) Stop() error {
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
func (c *KafkaCollector) Collect(ctx context.Context) ([]collector.Metric, error) {
	if len(c.cfg.Instances) == 0 {
		return nil, nil
	}
	var all []collector.Metric
	for _, inst := range c.cfg.Instances {
		metrics, err := c.collectInstance(ctx, inst)
		if err != nil {
			c.logger.Warn("Kafka collection failed",
				zap.String("instance", inst.Name),
				zap.Error(err),
			)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func (c *KafkaCollector) collectInstance(ctx context.Context, inst config.KafkaInstanceConfig) ([]collector.Metric, error) {
	if inst.ExporterURL == "" {
		return nil, fmt.Errorf("kafka instance %q: exporter_url is required", inst.Name)
	}
	body, err := scrape(ctx, inst)
	if err != nil {
		return nil, err
	}
	families, err := parseText(body)
	if err != nil && len(families) == 0 {
		return nil, fmt.Errorf("parse exporter text: %w", err)
	}
	labels := c.instanceLabels(inst)
	return BuildKafkaMetrics(labels, families), nil
}

func (c *KafkaCollector) instanceLabels(inst config.KafkaInstanceConfig) map[string]string {
	labels := make(map[string]string)
	for k, v := range c.cfg.Tags {
		labels[k] = v
	}
	for k, v := range inst.Tags {
		labels[k] = v
	}
	labels["kafka_instance"] = inst.Name
	labels["queueing_system"] = "kafka"
	if inst.Cluster != "" {
		labels["kafka_cluster"] = inst.Cluster
	}
	return labels
}

// scrape fetches the exporter exposition.
func scrape(ctx context.Context, inst config.KafkaInstanceConfig) (io.Reader, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: inst.TLSSkipVerify},
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, inst.ExporterURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", string(expfmt.NewFormat(expfmt.TypeTextPlain)))
	if inst.Username != "" || inst.Password != "" {
		req.SetBasicAuth(inst.Username, inst.Password)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scrape %s: %w", inst.ExporterURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("scrape %s: HTTP %d", inst.ExporterURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", inst.ExporterURL, err)
	}
	return strings.NewReader(string(body)), nil
}

// parseText parses Prometheus exposition into MetricFamilies.
func parseText(r io.Reader) (map[string]*dto.MetricFamily, error) {
	parser := expfmt.NewTextParser(model.LegacyValidation)
	return parser.TextToMetricFamilies(r)
}

// BuildKafkaMetrics converts JMX exporter MetricFamilies into collector.Metric
// values under the queue.kafka.* namespace. Metric names are normalized:
// a leading "kafka_" is stripped and the remainder is re-prefixed with
// "queue.kafka.". Exported for external test coverage.
func BuildKafkaMetrics(labels map[string]string, families map[string]*dto.MetricFamily) []collector.Metric {
	now := time.Now()
	var out []collector.Metric

	for name, family := range families {
		metricName := normalizeName(name)
		help := family.GetHelp()
		for _, m := range family.GetMetric() {
			lbl := make(map[string]string, len(labels)+len(m.Label))
			for k, v := range labels {
				lbl[k] = v
			}
			for _, lp := range m.Label {
				lbl[lp.GetName()] = lp.GetValue()
			}
			switch family.GetType() {
			case dto.MetricType_COUNTER:
				out = append(out, newMetric(metricName, m.Counter.GetValue(), collector.MetricTypeCounter, now, help, lbl))
			case dto.MetricType_GAUGE:
				out = append(out, newMetric(metricName, m.Gauge.GetValue(), collector.MetricTypeGauge, now, help, lbl))
			case dto.MetricType_UNTYPED:
				if m.Untyped != nil {
					out = append(out, newMetric(metricName, m.Untyped.GetValue(), collector.MetricTypeGauge, now, help, lbl))
				}
			}
		}
	}
	return out
}

func newMetric(name string, value float64, typ collector.MetricType, ts time.Time, desc string, labels map[string]string) collector.Metric {
	return collector.Metric{
		Name: name, Type: typ, Value: value, Timestamp: ts,
		Description: desc, Labels: labels,
	}
}

// normalizeName turns a JMX exporter metric family name into a queue.kafka.*
// metric name. Example: kafka_server_brokertopicmetrics_messages_in_persec ->
// queue.kafka.server_brokertopicmetrics_messages_in_persec
func normalizeName(family string) string {
	name := family
	name = strings.TrimPrefix(name, "kafka_")
	return "queue.kafka." + name
}
