// Package nats_test contains black-box unit tests for the NATS collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package nats_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	natscol "github.com/telemetryflow/telemetryflow-agent/internal/collector/nats"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func TestBuildNATSMetrics(t *testing.T) {
	varz := natscol.VarzResponse{
		Connections: 12, TotalConns: 100, Subscriptions: 50,
		MaxConn: 1000, SlowConsumers: 1, Cores: 4, CPU: 12.5,
		Mem: 1 << 20, MaxPayload: 1 << 20,
		Sent:     natscol.Stats{Msgs: 5000, Bytes: 1 << 16},
		Received: natscol.Stats{Msgs: 4500, Bytes: 1 << 15},
	}
	connz := natscol.ConnzResponse{NumConns: 12, Total: 100}
	routez := natscol.RoutezResponse{NumRoutes: 2}
	subsz := natscol.SubszResponse{NumSubscriptions: 50, CacheHitRate: 0.9}
	jsz := natscol.JSzResponse{Streams: 3, Consumers: 6, Messages: 1000, Bytes: 1 << 20}

	metrics := natscol.BuildNATSMetrics(
		map[string]string{"env": "ci"},
		varz, connz, routez, subsz, jsz,
	)

	names := make(map[string]bool)
	for _, m := range metrics {
		names[m.Name] = true
		if m.Labels["env"] != "ci" {
			t.Fatalf("label not preserved on %s", m.Name)
		}
	}
	for _, want := range []string{
		"messaging.nats.connections",
		"messaging.nats.total_connections",
		"messaging.nats.subscriptions",
		"messaging.nats.sent_msgs",
		"messaging.nats.received_bytes",
		"messaging.nats.routes",
		"messaging.nats.connz.num_connections",
		"messaging.nats.jetstream.streams",
		"messaging.nats.jetstream.messages",
	} {
		if !names[want] {
			t.Errorf("missing metric %s", want)
		}
	}
}

func TestNATSCollector_Lifecycle(t *testing.T) {
	c := natscol.NewNATSCollector(config.NATSCollectorConfig{Enabled: true}, zap.NewNop())
	if c.Name() != "nats" {
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

func TestNATSCollector_NoInstances(t *testing.T) {
	c := natscol.NewNATSCollector(config.NATSCollectorConfig{Enabled: true}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestNATSCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*natscol.NATSCollector)(nil)
}
