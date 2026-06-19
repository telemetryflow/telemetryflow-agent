// White-box unit tests for the Confluent Kafka collector. The Build function
// consumes the unexported metricQuery / dataPoint types, so this test lives in
// the confluent_kafka package alongside the source.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package confluent_kafka

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestBuildConfluentKafkaMetrics(t *testing.T) {
	queries := []metricQuery{
		{metric: "io.confluent.kafka.server/received_bytes", agg: "SUM", suffix: "received_bytes", typ: collector.MetricTypeCounter, unit: "bytes"},
		{metric: "io.confluent.kafka.server/sent_records", agg: "SUM", suffix: "sent_records", typ: collector.MetricTypeCounter},
		{metric: "io.confluent.kafka.server/retained_bytes", agg: "MAX", suffix: "retained_bytes", typ: collector.MetricTypeGauge, unit: "bytes"},
	}
	points := []dataPoint{
		// Older sample for orders — should be superseded by the newer one.
		{Timestamp: "2024-01-01T00:00:00Z", Value: 100, Metric: "io.confluent.kafka.server/received_bytes", Subject: map[string]string{"topic": "orders"}},
		{Timestamp: "2024-01-01T00:01:00Z", Value: 250, Metric: "io.confluent.kafka.server/received_bytes", Subject: map[string]string{"topic": "orders"}},
		{Timestamp: "2024-01-01T00:01:00Z", Value: 75, Metric: "io.confluent.kafka.server/sent_records", Subject: map[string]string{"topic": "billing"}},
		// No matching query — should be dropped.
		{Timestamp: "2024-01-01T00:01:00Z", Value: 999, Metric: "io.confluent.kafka.server/unknown", Subject: map[string]string{"topic": "orders"}},
	}

	metrics := BuildConfluentKafkaMetrics(
		map[string]string{"env": "ci", "kafka_cluster": "lkc-x"},
		queries, points,
	)

	byName := map[string]float64{}
	for _, m := range metrics {
		if m.Labels["env"] != "ci" || m.Labels["kafka_cluster"] != "lkc-x" {
			t.Fatalf("labels not preserved on %s: %+v", m.Name, m.Labels)
		}
		byName[m.Name+"|"+m.Labels["kafka_topic"]] = m.Value
	}

	if got := byName["queue.confluent_kafka.received_bytes|orders"]; got != 250 {
		t.Errorf("expected latest received_bytes for orders=250, got %v", got)
	}
	if got := byName["queue.confluent_kafka.sent_records|billing"]; got != 75 {
		t.Errorf("expected sent_records for billing=75, got %v", got)
	}
	if _, ok := byName["queue.confluent_kafka.retained_bytes|"]; ok {
		t.Error("retained_bytes emitted without data")
	}
}

func TestConfluentKafkaCollector_Lifecycle(t *testing.T) {
	c := NewConfluentKafkaCollector(config.ConfluentKafkaCollectorConfig{Enabled: true}, zap.NewNop())
	if c.Name() != "confluent_kafka" {
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

func TestConfluentKafkaCollector_NoInstances(t *testing.T) {
	c := NewConfluentKafkaCollector(config.ConfluentKafkaCollectorConfig{Enabled: true}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestConfluentKafkaCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*ConfluentKafkaCollector)(nil)
}
