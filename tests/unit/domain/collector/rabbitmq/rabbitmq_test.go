// External black-box unit tests for the RabbitMQ collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package rabbitmq_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	rmq "github.com/telemetryflow/telemetryflow-agent/internal/collector/rabbitmq"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- fixtures -------------------------------------------------------------

const overviewJSON = `{
  "node": "rabbit@node1",
  "cluster_name": "rmq-cluster",
  "rabbitmq_version": "3.13.0",
  "object_totals": {"consumers": 4, "queues": 3, "exchanges": 7, "connections": 5, "channels": 6},
  "queue_totals": {"messages": 100, "messages_ready": 60, "messages_unacknowledged": 40},
  "message_stats": {
    "publish": 1000, "publish_details": {"rate": 1.5},
    "ack": 900, "ack_details": {"rate": 1.2},
    "deliver": 800, "deliver_details": {"rate": 1.1},
    "deliver_get": 850, "deliver_get_details": {"rate": 1.3},
    "redeliver": 10, "redeliver_details": {"rate": 0.1},
    "return_unroutable": 2, "drop_unroutable": 3
  }
}`

const nodesJSON = `[{
  "name": "rabbit@node1", "running": true,
  "mem_used": 1000, "mem_limit": 2000, "mem_alarm": true,
  "disk_free": 5000, "disk_free_limit": 1000, "disk_alarm": true,
  "fd_used": 10, "fd_total": 1024, "sockets_used": 5, "sockets_total": 900,
  "proc_used": 300, "proc_total": 1048576, "run_queue": 1, "uptime": 123456,
  "gc_num": 77, "gc_bytes_reclaimed": 8888
}]`

const queuesJSON = `[
  {"name": "orders", "vhost": "/", "type": "classic", "node": "rabbit@node1", "state": "running",
   "messages": 50, "messages_ready": 30, "messages_unacknowledged": 20, "consumers": 2, "memory": 4096,
   "message_stats": {"publish": 500, "publish_details": {"rate": 0.5}, "ack": 480, "ack_details": {"rate": 0.4},
     "deliver": 470, "deliver_details": {"rate": 0.3}, "deliver_get": 475, "redeliver": 5}},
  {"name": "billing", "vhost": "/", "type": "quorum", "node": "rabbit@node1", "state": "running",
   "messages": 10, "messages_ready": 8, "messages_unacknowledged": 2, "consumers": 1, "memory": 2048,
   "message_stats": {"publish": 100, "publish_details": {"rate": 0.1}}}
]`

// newTestServer returns an httptest server responding to the management API.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(overviewJSON))
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodesJSON))
	})
	mux.HandleFunc("/api/queues", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(queuesJSON))
	})
	return httptest.NewServer(mux)
}

// --- lifecycle ------------------------------------------------------------

func TestRabbitMQCollector_Lifecycle(t *testing.T) {
	c := rmq.NewRabbitMQCollector(config.RabbitMQCollectorConfig{Enabled: true}, zap.NewNop())
	if c.Name() != "rabbitmq" {
		t.Fatalf("name=%q", c.Name())
	}
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
		t.Fatal("double start should fail")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestRabbitMQCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*rmq.RabbitMQCollector)(nil)
}

func TestRabbitMQCollector_Defaults(t *testing.T) {
	c := rmq.NewRabbitMQCollector(config.RabbitMQCollectorConfig{}, zap.NewNop())
	// Defaults applied by constructor are internal; exercise labels + no-instance Collect.
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil metrics with no instances, got %v %v", m, err)
	}
}

func TestRabbitMQCollector_DefaultsWithProvidedIntervals(t *testing.T) {
	// Ensure the non-zero branch of NewRabbitMQCollector is exercised too.
	cfg := config.RabbitMQCollectorConfig{
		OverviewInterval: 5 * time.Second,
		QueueInterval:    5 * time.Second,
		NodeInterval:     5 * time.Second,
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	if c.Name() != "rabbitmq" {
		t.Fatalf("name=%q", c.Name())
	}
}

// --- Collect end-to-end via httptest -------------------------------------

func TestRabbitMQCollector_CollectSuccess(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	cfg := config.RabbitMQCollectorConfig{
		Enabled: true,
		Tags:    map[string]string{"env": "ci"},
		Instances: []config.RabbitMQInstanceConfig{{
			Name:     "primary",
			URL:      srv.URL,
			Username: "guest",
			Password: "guest",
			Tags:     map[string]string{"team": "platform"},
		}},
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics")
	}

	byKey := map[string]float64{}
	for _, m := range metrics {
		if m.Labels["env"] != "ci" || m.Labels["team"] != "platform" {
			t.Fatalf("tags not merged onto %s: %+v", m.Name, m.Labels)
		}
		if m.Labels["rabbitmq_instance"] != "primary" || m.Labels["messaging_system"] != "rabbitmq" {
			t.Fatalf("instance labels missing on %s", m.Name)
		}
		key := m.Name
		if q := m.Labels["rabbitmq_queue"]; q != "" {
			key += "|" + q
		}
		if n := m.Labels["rabbitmq_node"]; n != "" {
			key += "|" + n
		}
		byKey[key] = m.Value
	}

	checks := map[string]float64{
		"queue.rabbitmq.connections":                  5,
		"queue.rabbitmq.channels":                     6,
		"queue.rabbitmq.queues.total":                 3,
		"queue.rabbitmq.exchanges":                    7,
		"queue.rabbitmq.consumers":                    4,
		"queue.rabbitmq.messages":                     100,
		"queue.rabbitmq.messages_ready":               60,
		"queue.rabbitmq.messages_unacknowledged":      40,
		"queue.rabbitmq.messages_published":           1000,
		"queue.rabbitmq.publish_rate":                 1.5,
		"queue.rabbitmq.messages_acked":               900,
		"queue.rabbitmq.messages_delivered_get":       850,
		"queue.rabbitmq.messages_unroutable_dropped":  3,
		"queue.rabbitmq.node.running|rabbit@node1":    1,
		"queue.rabbitmq.node.mem_alarm|rabbit@node1":  1,
		"queue.rabbitmq.node.disk_alarm|rabbit@node1": 1,
		"queue.rabbitmq.node.gc_num|rabbit@node1":     77,
		"queue.rabbitmq.queue.messages|orders":        50,
		"queue.rabbitmq.queue.consumers|orders":       2,
		"queue.rabbitmq.queue.messages|billing":       10,
	}
	for k, want := range checks {
		if got := byKey[k]; got != want {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
}

func TestRabbitMQCollector_CollectWithQueueFilter(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	cfg := config.RabbitMQCollectorConfig{
		Instances: []config.RabbitMQInstanceConfig{{
			Name:        "primary",
			URL:         srv.URL,
			QueueFilter: "^orders$",
		}},
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, m := range metrics {
		if m.Labels["rabbitmq_queue"] == "billing" {
			t.Fatal("billing queue should have been filtered out")
		}
	}
}

func TestRabbitMQCollector_CollectBadQueueFilter(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	cfg := config.RabbitMQCollectorConfig{
		Instances: []config.RabbitMQInstanceConfig{{
			Name:        "primary",
			URL:         srv.URL,
			QueueFilter: "([",
		}},
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	// collectInstance returns an error which Collect logs and skips -> nil metrics.
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should not surface per-instance error: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected no metrics from failing instance, got %d", len(metrics))
	}
}

func TestRabbitMQCollector_CollectMissingURL(t *testing.T) {
	cfg := config.RabbitMQCollectorConfig{
		Instances: []config.RabbitMQInstanceConfig{{Name: "broken"}},
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected nil, got %d metrics", len(metrics))
	}
}

func TestRabbitMQCollector_CollectOverviewError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := config.RabbitMQCollectorConfig{
		Instances: []config.RabbitMQInstanceConfig{{Name: "primary", URL: srv.URL}},
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected nil metrics on overview failure, got %d", len(metrics))
	}
}

func TestRabbitMQCollector_CollectNodesAndQueuesFailTolerantly(t *testing.T) {
	// overview succeeds; nodes and queues return errors. Collect should still
	// return the overview-derived metrics.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(overviewJSON))
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/queues/myvhost", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.RabbitMQCollectorConfig{
		Instances: []config.RabbitMQInstanceConfig{{Name: "primary", URL: srv.URL, Vhost: "myvhost"}},
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Only cluster-level metrics remain.
	for _, m := range metrics {
		if m.Labels["rabbitmq_node"] != "" || m.Labels["rabbitmq_queue"] != "" {
			t.Fatalf("did not expect node/queue metrics, got %s", m.Name)
		}
	}
	if len(metrics) == 0 {
		t.Fatal("expected cluster metrics")
	}
}

func TestRabbitMQCollector_CollectVhostEscaped(t *testing.T) {
	// Verify that a vhost with a slash is percent-encoded in the request path.
	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(overviewJSON))
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodesJSON))
	})
	mux.HandleFunc("/api/queues/", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(queuesJSON))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.RabbitMQCollectorConfig{
		Instances: []config.RabbitMQInstanceConfig{{Name: "primary", URL: srv.URL, Vhost: "a/b"}},
	}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if gotPath != "/api/queues/a%2Fb" {
		t.Fatalf("vhost not escaped, path=%q", gotPath)
	}
}

// --- instanceLabels (via shim) -------------------------------------------

func TestInstanceLabels(t *testing.T) {
	cfg := config.RabbitMQCollectorConfig{Tags: map[string]string{"env": "ci", "shared": "base"}}
	c := rmq.NewRabbitMQCollector(cfg, zap.NewNop())
	labels := c.InstanceLabelsExported(config.RabbitMQInstanceConfig{
		Name: "primary",
		Tags: map[string]string{"shared": "override", "team": "x"},
	})
	if labels["env"] != "ci" || labels["team"] != "x" {
		t.Fatalf("labels merge wrong: %+v", labels)
	}
	if labels["shared"] != "override" {
		t.Fatalf("instance tag should override collector tag, got %q", labels["shared"])
	}
	if labels["rabbitmq_instance"] != "primary" || labels["messaging_system"] != "rabbitmq" {
		t.Fatalf("built-in labels missing: %+v", labels)
	}
}

// --- newMgmtClient / getJSON (via shim) ----------------------------------

func TestNewMgmtClient_EmptyURL(t *testing.T) {
	if _, err := rmq.NewMgmtClientExported(config.RabbitMQInstanceConfig{Name: "x"}); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewMgmtClient_TrimsTrailingSlashAndTLS(t *testing.T) {
	mc, err := rmq.NewMgmtClientExported(config.RabbitMQInstanceConfig{
		Name:          "x",
		URL:           "https://rmq.example.com:15672/",
		TLSSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("newMgmtClient: %v", err)
	}
	if mc.BaseURL() != "https://rmq.example.com:15672" {
		t.Fatalf("trailing slash not trimmed: %q", mc.BaseURL())
	}
}

func TestGetJSON_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "guest" || p != "secret" {
			t.Errorf("basic auth not set: %q %q %v", u, p, ok)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("accept header not set")
		}
		_, _ = w.Write([]byte(`{"cluster_name":"c1"}`))
	}))
	defer srv.Close()

	mc, err := rmq.NewMgmtClientExported(config.RabbitMQInstanceConfig{
		Name: "x", URL: srv.URL, Username: "guest", Password: "secret",
	})
	if err != nil {
		t.Fatalf("newMgmtClient: %v", err)
	}
	var ov rmq.OverviewResponse
	if err := mc.GetJSON(context.Background(), "/api/overview", &ov); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if ov.ClusterName != "c1" {
		t.Fatalf("decode wrong: %+v", ov)
	}
}

func TestGetJSON_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	mc, _ := rmq.NewMgmtClientExported(config.RabbitMQInstanceConfig{Name: "x", URL: srv.URL})
	var v map[string]any
	if err := mc.GetJSON(context.Background(), "/api/overview", &v); err == nil {
		t.Fatal("expected HTTP error")
	}
}

func TestGetJSON_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	mc, _ := rmq.NewMgmtClientExported(config.RabbitMQInstanceConfig{Name: "x", URL: srv.URL})
	var v map[string]any
	if err := mc.GetJSON(context.Background(), "/api/overview", &v); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGetJSON_RequestBuildError(t *testing.T) {
	// A control character in the URL makes http.NewRequest fail.
	mc, _ := rmq.NewMgmtClientExported(config.RabbitMQInstanceConfig{Name: "x", URL: "http://example.com"})
	var v map[string]any
	if err := mc.GetJSON(context.Background(), "/\x7f\x00bad", &v); err == nil {
		t.Fatal("expected request build error")
	}
}

func TestGetJSON_RequestDoError(t *testing.T) {
	// Point at a closed server to force a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	mc, _ := rmq.NewMgmtClientExported(config.RabbitMQInstanceConfig{Name: "x", URL: url})
	var v map[string]any
	if err := mc.GetJSON(context.Background(), "/api/overview", &v); err == nil {
		t.Fatal("expected transport error")
	}
}

// --- helpers -------------------------------------------------------------

func TestPathEscape(t *testing.T) {
	tests := map[string]string{
		"/":    "%2F",
		"a/b":  "a%2Fb",
		"host": "host",
		"":     "",
	}
	for in, want := range tests {
		if got := rmq.PathEscapeExported(in); got != want {
			t.Errorf("pathEscape(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestWithLabel(t *testing.T) {
	base := map[string]string{"a": "1"}
	got := rmq.WithLabelExported(base, "b", "2")
	if got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("withLabel wrong: %+v", got)
	}
	if _, ok := base["b"]; ok {
		t.Fatal("withLabel must not mutate base map")
	}
}

// --- BuildRabbitMQMetrics direct -----------------------------------------

func TestBuildRabbitMQMetrics_Empty(t *testing.T) {
	metrics := rmq.BuildRabbitMQMetrics(
		map[string]string{"env": "ci"},
		rmq.OverviewResponse{},
		nil, nil, nil,
	)
	// Cluster-level metrics are always emitted (20 of them), no node/queue.
	if len(metrics) == 0 {
		t.Fatal("expected cluster metrics even with empty input")
	}
	for _, m := range metrics {
		if m.Labels["env"] != "ci" {
			t.Fatalf("label not preserved on %s", m.Name)
		}
	}
}

func TestBuildRabbitMQMetrics_FilterNoMatch(t *testing.T) {
	re := regexp.MustCompile("^nomatch$")
	queues := []rmq.QueueResponse{{Name: "orders", Vhost: "/"}}
	metrics := rmq.BuildRabbitMQMetrics(nil, rmq.OverviewResponse{}, nil, queues, re)
	for _, m := range metrics {
		if m.Labels["rabbitmq_queue"] != "" {
			t.Fatal("no queue should pass the filter")
		}
	}
}

func TestBuildRabbitMQMetrics_MetricTypes(t *testing.T) {
	metrics := rmq.BuildRabbitMQMetrics(
		nil,
		rmq.OverviewResponse{
			MessageStats: rmq.MessageStats{Publish: 5},
			ObjectTotals: rmq.ObjectTotals{Connections: 1},
		},
		[]rmq.NodeResponse{{Name: "n1", Running: false, MemAlarm: false, DiskAlarm: false, GCNum: 3}},
		[]rmq.QueueResponse{{Name: "q1"}},
		nil,
	)
	var sawCounter, sawGauge bool
	for _, m := range metrics {
		switch m.Type {
		case collector.MetricTypeCounter:
			sawCounter = true
		case collector.MetricTypeGauge:
			sawGauge = true
		}
		if m.Name == "queue.rabbitmq.node.running" && m.Value != 0 {
			t.Fatalf("non-running node should have running=0, got %v", m.Value)
		}
	}
	if !sawCounter || !sawGauge {
		t.Fatal("expected both counter and gauge metrics")
	}
}
