// Package rabbitmq_test contains black-box unit tests for the RabbitMQ collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package rabbitmq_test

import (
	"context"
	"regexp"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	rabbitmqcol "github.com/telemetryflow/telemetryflow-agent/internal/collector/rabbitmq"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestBuildRabbitMQMetrics(t *testing.T) {
	overview := rabbitmqcol.OverviewResponse{
		ObjectTotals: rabbitmqcol.ObjectTotals{Connections: 3, Channels: 7, Queues: 2, Exchanges: 4, Consumers: 5},
		QueueTotals:  rabbitmqcol.QueueTotals{Messages: 100, MessagesReady: 80, MessagesUnacknowledged: 20},
		MessageStats: rabbitmqcol.MessageStats{
			Publish: 1000, PublishDetails: rabbitmqcol.Rate{Rate: 12.5},
			Ack: 900, AckDetails: rabbitmqcol.Rate{Rate: 11.0},
			Deliver: 950, DeliverDetails: rabbitmqcol.Rate{Rate: 10.5},
		},
	}
	nodes := []rabbitmqcol.NodeResponse{
		{Name: "rabbit@node-1", Running: true, MemUsed: 1 << 20, MemLimit: 1 << 24, DiskFree: 1 << 30, FDUsed: 50, FDTotal: 1024, Uptime: 999},
		{Name: "rabbit@node-2", Running: false, MemAlarm: true},
	}
	queues := []rabbitmqcol.QueueResponse{
		{Name: "orders", Vhost: "/", Type: "classic", Node: "rabbit@node-1", Messages: 10, MessagesReady: 8, Consumers: 2, Memory: 4096},
		{Name: "billing", Vhost: "/", Type: "quorum", Node: "rabbit@node-2", Messages: 5, Consumers: 1},
		{Name: "internal-bus", Vhost: "/", Type: "classic", Messages: 1},
	}

	metrics := rabbitmqcol.BuildRabbitMQMetrics(
		map[string]string{"env": "ci"},
		overview, nodes, queues,
		regexp.MustCompile("^orders$"),
	)

	names := make(map[string]bool)
	for _, m := range metrics {
		names[m.Name] = true
		if m.Labels["env"] != "ci" {
			t.Fatalf("label not preserved on %s", m.Name)
		}
	}

	for _, want := range []string{
		"queue.rabbitmq.connections",
		"queue.rabbitmq.queues.total",
		"queue.rabbitmq.messages",
		"queue.rabbitmq.messages_published",
		"queue.rabbitmq.publish_rate",
		"queue.rabbitmq.node.mem_used",
		"queue.rabbitmq.node.running",
		"queue.rabbitmq.queue.messages",
		"queue.rabbitmq.queue.consumers",
	} {
		if !names[want] {
			t.Errorf("missing metric %s", want)
		}
	}

	// Queue filter: only "orders" should produce per-queue metrics.
	queueSeen := false
	for _, m := range metrics {
		if q := m.Labels["rabbitmq_queue"]; q != "" {
			queueSeen = true
			if q != "orders" {
				t.Errorf("unexpected queue %q passed filter", q)
			}
		}
	}
	if !queueSeen {
		t.Error("queue filter excluded all queues")
	}
}

func TestRabbitMQCollector_Lifecycle(t *testing.T) {
	c := rabbitmqcol.NewRabbitMQCollector(config.RabbitMQCollectorConfig{Enabled: true}, zap.NewNop())
	if c.Name() != "rabbitmq" {
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

func TestRabbitMQCollector_NoInstances(t *testing.T) {
	c := rabbitmqcol.NewRabbitMQCollector(config.RabbitMQCollectorConfig{Enabled: true}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestRabbitMQCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*rabbitmqcol.RabbitMQCollector)(nil)
}
