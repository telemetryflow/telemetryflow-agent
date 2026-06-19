// White-box unit tests for the Pub/Sub collector. The Build function consumes
// the unexported pubsubMetric / monitoringTimeSeries types, so this test lives
// in the pubsub package alongside the source.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package pubsub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func int64Ptr(v int64) *int64 { return &v }

func TestBuildPubSubMetrics(t *testing.T) {
	metrics := []pubsubMetric{
		{metricType: "pubsub.googleapis.com/subscription/num_undelivered_messages", suffix: "undelivered_messages", typ: collector.MetricTypeGauge},
		{metricType: "pubsub.googleapis.com/subscription/sent_message_count", suffix: "sent_messages", typ: collector.MetricTypeCounter},
	}
	end := time.Now()
	series := []monitoringTimeSeries{
		{
			Metric: struct {
				Type string `json:"type"`
			}{Type: "pubsub.googleapis.com/subscription/num_undelivered_messages"},
			Resource: struct {
				Labels struct {
					SubscriptionID string `json:"subscription_id"`
					ProjectID      string `json:"project_id"`
				} `json:"labels"`
			}{},
			Points: []monitoringPoint{
				{Interval: struct {
					EndTime   time.Time `json:"endTime"`
					StartTime time.Time `json:"startTime"`
				}{EndTime: end.Add(-2 * time.Minute)}, Value: struct {
					Int64Value  *int64   `json:"int64Value,omitempty"`
					DoubleValue *float64 `json:"doubleValue,omitempty"`
				}{Int64Value: int64Ptr(5)}},
				{Interval: struct {
					EndTime   time.Time `json:"endTime"`
					StartTime time.Time `json:"startTime"`
				}{EndTime: end}, Value: struct {
					Int64Value  *int64   `json:"int64Value,omitempty"`
					DoubleValue *float64 `json:"doubleValue,omitempty"`
				}{Int64Value: int64Ptr(9)}},
			},
		},
	}
	series[0].Resource.Labels.SubscriptionID = "orders-sub"

	// Apply a filter that excludes the subscription, then one that includes it.
	t.Run("filter_excludes", func(t *testing.T) {
		got, err := BuildPubSubMetrics(map[string]string{"env": "ci"}, metrics, series, "^nonexistent-.*")
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("filter should exclude all, got %d", len(got))
		}
	})

	t.Run("latest_point_selected", func(t *testing.T) {
		got, err := BuildPubSubMetrics(map[string]string{"env": "ci"}, metrics, series, "")
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 metric, got %d", len(got))
		}
		if got[0].Value != 9 {
			t.Errorf("expected latest value 9, got %v", got[0].Value)
		}
		if got[0].Name != "messaging.pubsub.undelivered_messages" {
			t.Errorf("unexpected name %s", got[0].Name)
		}
		if got[0].Labels["pubsub_subscription"] != "orders-sub" || got[0].Labels["env"] != "ci" {
			t.Errorf("labels wrong: %+v", got[0].Labels)
		}
	})
}

func TestSignJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	token, err := signJWT(map[string]any{"iss": "test", "aud": "x", "iat": 1, "exp": 2}, key)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	parts := splitOnDot(token)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
}

func splitOnDot(s string) (out []string) {
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func TestPubSubCollector_Lifecycle(t *testing.T) {
	c := NewPubSubCollector(config.PubSubCollectorConfig{Enabled: true}, zap.NewNop())
	if c.Name() != "pubsub" {
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

func TestPubSubCollector_NoInstances(t *testing.T) {
	c := NewPubSubCollector(config.PubSubCollectorConfig{Enabled: true}, zap.NewNop())
	_ = c.Start(context.Background())
	defer func() { _ = c.Stop() }()
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil, got %v %v", m, err)
	}
}

func TestPubSubCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*PubSubCollector)(nil)
}
