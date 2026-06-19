// Package kafka_test contains black-box unit tests for the Kafka collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package kafka_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	dto "github.com/prometheus/client_model/go"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	kafkacol "github.com/telemetryflow/telemetryflow-agent/internal/collector/kafka"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestBuildKafkaMetrics(t *testing.T) {
	families := map[string]*dto.MetricFamily{
		"kafka_server_brokertopicmetrics_messages_in_persec": {
			Name: strPtr("kafka_server_brokertopicmetrics_messages_in_persec"),
			Help: strPtr("messages in per second"),
			Type: dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{
				{
					Label: []*dto.LabelPair{
						{Name: strPtr("topic"), Value: strPtr("orders")},
						{Name: strPtr("instance"), Value: strPtr("broker-1")},
					},
					Counter: &dto.Counter{Value: float64Ptr(1500)},
				},
			},
		},
		"kafka_server_kafkarequesthandler_requestqueuetimems": {
			Name: strPtr("kafka_server_kafkarequesthandler_requestqueuetimems"),
			Help: strPtr("request queue time"),
			Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{
				{
					Counter: nil,
					Gauge:   &dto.Gauge{Value: float64Ptr(3.5)},
				},
			},
		},
	}

	metrics := kafkacol.BuildKafkaMetrics(map[string]string{"env": "ci", "kafka_cluster": "prod"}, families)

	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}

	names := make(map[string]bool)
	for _, m := range metrics {
		names[m.Name] = true
		if m.Labels["env"] != "ci" || m.Labels["kafka_cluster"] != "prod" {
			t.Fatalf("labels not preserved on %s: %+v", m.Name, m.Labels)
		}
	}
	if !names["queue.kafka.server_brokertopicmetrics_messages_in_persec"] {
		t.Error("counter metric not normalized/prefixed correctly")
	}
	if !names["queue.kafka.server_kafkarequesthandler_requestqueuetimems"] {
		t.Error("gauge metric not normalized/prefixed correctly")
	}

	// Topic label carried through.
	var sawTopic bool
	for _, m := range metrics {
		if m.Labels["topic"] == "orders" {
			sawTopic = true
		}
	}
	if !sawTopic {
		t.Error("topic label not propagated")
	}
}

func TestKafkaCollector_Lifecycle(t *testing.T) {
	c := kafkacol.NewKafkaCollector(config.KafkaCollectorConfig{Enabled: true}, zap.NewNop())
	if c.Name() != "kafka" {
		t.Fatalf("name=%q", c.Name())
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("not running")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double start should fail")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestKafkaCollector_NoInstances(t *testing.T) {
	c := kafkacol.NewKafkaCollector(config.KafkaCollectorConfig{Enabled: true}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestKafkaCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*kafkacol.KafkaCollector)(nil)
}

func strPtr(s string) *string       { return &s }
func float64Ptr(v float64) *float64 { return &v }
