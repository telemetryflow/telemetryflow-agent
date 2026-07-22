// External black-box unit tests for the NATS collector. Unexported symbols
// (monitorClient / getJSON / collectInstance / instanceLabels) are reached
// through forwarding wrappers in internal/collector/nats/exports.go. The NATS
// monitoring HTTP endpoints (/varz, /connz, /routez, /subsz, /jsz) are served
// by httptest — no live services, Docker, or network access are required.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package nats_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nats"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ---------------------------------------------------------------------------
// BuildNATSMetrics
// ---------------------------------------------------------------------------

func findMetric(t *testing.T, metrics []collector.Metric, name string) collector.Metric {
	t.Helper()
	for _, m := range metrics {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("metric %q not found", name)
	return collector.Metric{}
}

func hasMetric(metrics []collector.Metric, name string) bool {
	for _, m := range metrics {
		if m.Name == name {
			return true
		}
	}
	return false
}

func TestBuildNATSMetrics_CoreFields(t *testing.T) {
	labels := map[string]string{"env": "ci", "nats_instance": "n1"}
	varz := nats.VarzResponse{
		Connections:   12,
		TotalConns:    100,
		Subscriptions: 7,
		MaxConn:       1000,
		MaxSubs:       2000,
		SlowConsumers: 3,
		Cores:         8,
		CPU:           42.5,
		Mem:           1 << 20,
		MaxPayload:    1024,
		Sent:          nats.Stats{Msgs: 50, Bytes: 500},
		Received:      nats.Stats{Msgs: 60, Bytes: 600},
	}
	connz := nats.ConnzResponse{NumConns: 12, Total: 100}
	routez := nats.RoutezResponse{NumRoutes: 4}
	subsz := nats.SubszResponse{NumSubscriptions: 5, NumCache: 2, MatchLen: 9, CacheHitRate: 0.75}

	metrics := nats.BuildNATSMetrics(labels, varz, connz, routez, subsz, nats.JSzResponse{})

	conns := findMetric(t, metrics, "messaging.nats.connections")
	if conns.Value != 12 || conns.Type != collector.MetricTypeGauge {
		t.Errorf("connections wrong: %+v", conns)
	}
	if conns.Labels["env"] != "ci" {
		t.Errorf("labels not copied: %+v", conns.Labels)
	}
	// Mutating returned labels must not affect the source map (deep copy).
	conns.Labels["env"] = "mutated"
	if labels["env"] != "ci" {
		t.Errorf("source labels mutated")
	}

	total := findMetric(t, metrics, "messaging.nats.total_connections")
	if total.Type != collector.MetricTypeCounter || total.Value != 100 {
		t.Errorf("total_connections wrong: %+v", total)
	}

	cpu := findMetric(t, metrics, "messaging.nats.cpu")
	if cpu.Value != 42.5 {
		t.Errorf("cpu wrong: %v", cpu.Value)
	}

	hit := findMetric(t, metrics, "messaging.nats.subsz.cache_hit_rate")
	if hit.Value != 0.75 || hit.Unit != "ratio" {
		t.Errorf("cache_hit_rate wrong: %+v", hit)
	}

	routes := findMetric(t, metrics, "messaging.nats.routes")
	if routes.Value != 4 {
		t.Errorf("routes wrong: %v", routes.Value)
	}

	// JetStream metrics must be absent when jsz is empty.
	if hasMetric(metrics, "messaging.nats.jetstream.memory") {
		t.Errorf("jetstream metrics should be absent for empty jsz")
	}
}

func TestBuildNATSMetrics_JetStreamIncluded(t *testing.T) {
	jsz := nats.JSzResponse{
		Memory:    2048,
		Store:     4096,
		Streams:   3,
		Consumers: 6,
		Messages:  1000,
		Bytes:     9999,
	}
	metrics := nats.BuildNATSMetrics(map[string]string{}, nats.VarzResponse{}, nats.ConnzResponse{}, nats.RoutezResponse{}, nats.SubszResponse{}, jsz)

	mem := findMetric(t, metrics, "messaging.nats.jetstream.memory")
	if mem.Value != 2048 || mem.Unit != "bytes" {
		t.Errorf("jetstream.memory wrong: %+v", mem)
	}
	msgs := findMetric(t, metrics, "messaging.nats.jetstream.messages")
	if msgs.Type != collector.MetricTypeCounter || msgs.Value != 1000 {
		t.Errorf("jetstream.messages wrong: %+v", msgs)
	}
	streams := findMetric(t, metrics, "messaging.nats.jetstream.streams")
	if streams.Value != 3 {
		t.Errorf("jetstream.streams wrong: %v", streams.Value)
	}
}

func TestBuildNATSMetrics_JetStreamTriggeredByBytesOnly(t *testing.T) {
	// Only Bytes set — the OR condition should still include JetStream metrics.
	jsz := nats.JSzResponse{Bytes: 42}
	metrics := nats.BuildNATSMetrics(map[string]string{}, nats.VarzResponse{}, nats.ConnzResponse{}, nats.RoutezResponse{}, nats.SubszResponse{}, jsz)
	if !hasMetric(metrics, "messaging.nats.jetstream.bytes") {
		t.Errorf("jetstream metrics should be present when only Bytes>0")
	}
}

// ---------------------------------------------------------------------------
// Config defaults / constructor
// ---------------------------------------------------------------------------

func TestNewNATSCollector_DefaultStatsInterval(t *testing.T) {
	c := nats.NewNATSCollector(config.NATSCollectorConfig{}, zap.NewNop())
	if c == nil {
		t.Fatal("nil collector")
	}
	if c.Name() != "nats" {
		t.Errorf("name=%q", c.Name())
	}
}

func TestNewNATSCollector_RespectsCustomInterval(t *testing.T) {
	c := nats.NewNATSCollector(config.NATSCollectorConfig{StatsInterval: 30 * time.Second}, zap.NewNop())
	if c == nil {
		t.Fatal("nil collector")
	}
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func TestNATSCollector_Lifecycle(t *testing.T) {
	c := nats.NewNATSCollector(config.NATSCollectorConfig{Enabled: true}, zap.NewNop())
	if c.IsRunning() {
		t.Fatal("should not be running before Start")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("not running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double Start should fail")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("still running after Stop")
	}
	// Double Stop is a no-op.
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestNATSCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*nats.NATSCollector)(nil)
}

// ---------------------------------------------------------------------------
// instanceLabels
// ---------------------------------------------------------------------------

func TestInstanceLabels_MergesTags(t *testing.T) {
	cfg := config.NATSCollectorConfig{
		Tags: map[string]string{"env": "prod", "region": "us"},
	}
	c := nats.NewNATSCollector(cfg, zap.NewNop())
	inst := config.NATSInstanceConfig{
		Name: "cluster-a",
		Tags: map[string]string{"region": "eu"}, // overrides global
	}
	labels := c.InstanceLabelsExported(inst)
	if labels["env"] != "prod" {
		t.Errorf("global tag lost: %+v", labels)
	}
	if labels["region"] != "eu" {
		t.Errorf("instance tag should override global: %+v", labels)
	}
	if labels["nats_instance"] != "cluster-a" {
		t.Errorf("nats_instance label wrong: %+v", labels)
	}
	if labels["messaging_system"] != "nats" {
		t.Errorf("messaging_system label wrong: %+v", labels)
	}
}

// ---------------------------------------------------------------------------
// monitorClient.getJSON
// ---------------------------------------------------------------------------

func newVarzServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/varz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"server_id":"S1","connections":3,"total_connections":42,"subscriptions":5,"sent":{"msgs":10,"bytes":100},"received":{"msgs":20,"bytes":200}}`))
	})
	mux.HandleFunc("/connz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"num_connections":3,"total":42}`))
	})
	mux.HandleFunc("/routez", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"num_routes":2}`))
	})
	mux.HandleFunc("/subsz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"num_subscriptions":5,"cache_hit_rate":0.9}`))
	})
	mux.HandleFunc("/jsz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"memory":1024,"store":2048,"stream_count":1,"consumer_count":2,"messages":7,"bytes":70}`))
	})
	return httptest.NewServer(mux)
}

func TestGetJSON_Success(t *testing.T) {
	srv := newVarzServer(t)
	defer srv.Close()

	client := nats.NewMonitorClientExported(config.NATSInstanceConfig{URL: srv.URL})
	if client.BaseURL() != srv.URL {
		t.Errorf("baseURL=%q", client.BaseURL())
	}
	var varz nats.VarzResponse
	if err := client.GetJSON(context.Background(), "/varz", &varz); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if varz.Connections != 3 || varz.TotalConns != 42 {
		t.Errorf("varz decoded wrong: %+v", varz)
	}
}

func TestGetJSON_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := nats.NewMonitorClientExported(config.NATSInstanceConfig{URL: srv.URL})
	var varz nats.VarzResponse
	err := client.GetJSON(context.Background(), "/varz", &varz)
	if err == nil {
		t.Fatal("expected HTTP error")
	}
}

func TestGetJSON_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	client := nats.NewMonitorClientExported(config.NATSInstanceConfig{URL: srv.URL})
	var varz nats.VarzResponse
	if err := client.GetJSON(context.Background(), "/varz", &varz); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGetJSON_RequestError_ConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // ensure the port is closed -> connection refused

	client := nats.NewMonitorClientExported(config.NATSInstanceConfig{URL: url})
	var varz nats.VarzResponse
	if err := client.GetJSON(context.Background(), "/varz", &varz); err == nil {
		t.Fatal("expected request error")
	}
}

func TestGetJSON_BuildRequestError(t *testing.T) {
	// A control character in the URL makes http.NewRequestWithContext fail.
	client := nats.NewMonitorClientExported(config.NATSInstanceConfig{URL: "http://exa\x7fmple"})
	var varz nats.VarzResponse
	if err := client.GetJSON(context.Background(), "/varz", &varz); err == nil {
		t.Fatal("expected build-request error")
	}
}

// ---------------------------------------------------------------------------
// collectInstance / Collect
// ---------------------------------------------------------------------------

func TestCollectInstance_EmptyURL(t *testing.T) {
	c := nats.NewNATSCollector(config.NATSCollectorConfig{}, zap.NewNop())
	_, err := c.CollectInstanceExported(context.Background(), config.NATSInstanceConfig{Name: "x"})
	if err == nil {
		t.Fatal("expected url-required error")
	}
}

func TestCollectInstance_VarzFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := nats.NewNATSCollector(config.NATSCollectorConfig{}, zap.NewNop())
	_, err := c.CollectInstanceExported(context.Background(), config.NATSInstanceConfig{Name: "x", URL: srv.URL})
	if err == nil {
		t.Fatal("expected varz error to propagate")
	}
}

func TestCollectInstance_Success_WithJetStream(t *testing.T) {
	srv := newVarzServer(t)
	defer srv.Close()

	c := nats.NewNATSCollector(config.NATSCollectorConfig{Tags: map[string]string{"env": "ci"}}, zap.NewNop())
	inst := config.NATSInstanceConfig{Name: "n1", URL: srv.URL, CollectJetStream: true}
	metrics, err := c.CollectInstanceExported(context.Background(), inst)
	if err != nil {
		t.Fatalf("collectInstance: %v", err)
	}
	if !hasMetric(metrics, "messaging.nats.connections") {
		t.Error("missing core metric")
	}
	if !hasMetric(metrics, "messaging.nats.jetstream.memory") {
		t.Error("missing jetstream metric")
	}
	conns := findMetric(t, metrics, "messaging.nats.connections")
	if conns.Labels["nats_instance"] != "n1" || conns.Labels["env"] != "ci" {
		t.Errorf("labels wrong: %+v", conns.Labels)
	}
}

func TestCollectInstance_Success_SecondaryEndpointsFailTolerantly(t *testing.T) {
	// Only /varz succeeds; connz/routez/subsz/jsz return errors but collection
	// must still succeed with core metrics.
	mux := http.NewServeMux()
	mux.HandleFunc("/varz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"connections":1}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := nats.NewNATSCollector(config.NATSCollectorConfig{}, zap.NewNop())
	inst := config.NATSInstanceConfig{Name: "n1", URL: srv.URL, CollectJetStream: true}
	metrics, err := c.CollectInstanceExported(context.Background(), inst)
	if err != nil {
		t.Fatalf("collectInstance should tolerate secondary failures: %v", err)
	}
	if !hasMetric(metrics, "messaging.nats.connections") {
		t.Error("core metric missing")
	}
}

func TestCollect_NoInstances(t *testing.T) {
	c := nats.NewNATSCollector(config.NATSCollectorConfig{}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil,nil got %v %v", m, err)
	}
}

func TestCollect_MixedInstances(t *testing.T) {
	srv := newVarzServer(t)
	defer srv.Close()

	cfg := config.NATSCollectorConfig{
		Instances: []config.NATSInstanceConfig{
			{Name: "good", URL: srv.URL},
			{Name: "bad", URL: ""}, // triggers a per-instance error that is logged and skipped
		},
	}
	c := nats.NewNATSCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasMetric(metrics, "messaging.nats.connections") {
		t.Error("expected metrics from the good instance")
	}
	for _, m := range metrics {
		if m.Labels["nats_instance"] == "bad" {
			t.Error("bad instance should have been skipped")
		}
	}
}
