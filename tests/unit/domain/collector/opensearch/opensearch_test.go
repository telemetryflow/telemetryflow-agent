// External black-box unit tests for the OpenSearch collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package opensearch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/opensearch"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- fixtures -------------------------------------------------------------

const healthJSON = `{
  "cluster_name": "test-cluster",
  "status": "green",
  "timed_out": false,
  "number_of_nodes": 3,
  "number_of_data_nodes": 2,
  "active_primary_shards": 10,
  "active_shards": 20,
  "relocating_shards": 0,
  "initializing_shards": 1,
  "unassigned_shards": 2,
  "number_of_pending_tasks": 5
}`

const yellowHealthJSON = `{
  "cluster_name": "yellow-cluster",
  "status": "yellow",
  "timed_out": false,
  "number_of_nodes": 2,
  "number_of_data_nodes": 2,
  "active_primary_shards": 4,
  "active_shards": 6,
  "relocating_shards": 1,
  "initializing_shards": 0,
  "unassigned_shards": 0,
  "number_of_pending_tasks": 0
}`

const redHealthJSON = `{
  "cluster_name": "red-cluster",
  "status": "red",
  "timed_out": false,
  "number_of_nodes": 1,
  "number_of_data_nodes": 1,
  "active_primary_shards": 2,
  "active_shards": 2,
  "relocating_shards": 0,
  "initializing_shards": 0,
  "unassigned_shards": 5,
  "number_of_pending_tasks": 9
}`

const nodesJSON = `{
  "cluster_name": "test-cluster",
  "nodes": {
    "node-id-1": {
      "name": "node-1",
      "jvm": {"mem": {"heap_used_percent": 65}},
      "indices": {
        "docs": {"count": 10000},
        "store": {"size_in_bytes": 1048576},
        "search": {"query_total": 500},
        "indexing": {"index_total": 200}
      }
    },
    "node-id-2": {
      "name": "node-2",
      "jvm": {"mem": {"heap_used_percent": 45}},
      "indices": {
        "docs": {"count": 5000},
        "store": {"size_in_bytes": 524288},
        "search": {"query_total": 250},
        "indexing": {"index_total": 100}
      }
    }
  }
}`

// newOSCollector constructs a collector with sane defaults and ensures it is
// stopped during test cleanup.
func newOSCollector(t *testing.T, instances []config.OpenSearchInstance) *opensearch.OpenSearchCollector {
	t.Helper()
	c := opensearch.NewOpenSearchCollector(config.OpenSearchCollectorConfig{
		Enabled:   true,
		Interval:  15 * time.Second,
		Instances: instances,
	}, zap.NewNop())
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	return c
}

// newHappyServer returns an httptest server that serves both /_cluster/health
// and /_nodes/stats with the canned JSON above.
func newHappyServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/_cluster/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(healthJSON))
	})
	mux.HandleFunc("/_nodes/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nodesJSON))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// mustGet returns the first metric matching name (and optional label filters).
// Filters are passed as alternating key/value pairs.
func mustGet(t *testing.T, metrics []collector.Metric, name string, labels ...string) collector.Metric {
	t.Helper()
	for _, m := range metrics {
		if m.Name != name {
			continue
		}
		match := true
		for i := 0; i+1 < len(labels); i += 2 {
			if m.Labels[labels[i]] != labels[i+1] {
				match = false
				break
			}
		}
		if match {
			return m
		}
	}
	t.Fatalf("metric %q %v not found in %d metrics", name, labels, len(metrics))
	return collector.Metric{}
}

// findMetric is the non-fatal variant of mustGet.
func findMetric(metrics []collector.Metric, name string, labels ...string) (collector.Metric, bool) {
	for _, m := range metrics {
		if m.Name != name {
			continue
		}
		match := true
		for i := 0; i+1 < len(labels); i += 2 {
			if m.Labels[labels[i]] != labels[i+1] {
				match = false
				break
			}
		}
		if match {
			return m, true
		}
	}
	return collector.Metric{}, false
}

// --- lifecycle -----------------------------------------------------------

func TestCollectorLifecycle(t *testing.T) {
	c := opensearch.NewOpenSearchCollector(config.OpenSearchCollectorConfig{}, zap.NewNop())
	const wantName = "opensearch"
	if c.Name() != wantName {
		t.Fatalf("name = %q, want %q", c.Name(), wantName)
	}
	if c.IsRunning() {
		t.Fatal("should not be running before start")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("should be running after start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double start should error")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("should not be running after stop")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double stop should be no-op, got: %v", err)
	}
}

func TestCollectorSatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*opensearch.OpenSearchCollector)(nil)
}

func TestCollectNoInstances(t *testing.T) {
	c := newOSCollector(t, nil)
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if ms != nil {
		t.Fatalf("expected nil metrics, got %d", len(ms))
	}
}

// --- happy paths ---------------------------------------------------------

func TestClusterHealthMetricsEmitted(t *testing.T) {
	srv := newHappyServer(t)
	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// state must be 1 on a successful scrape.
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	// Cluster health metrics. green=2.
	cases := map[string]float64{
		"db.opensearch.cluster_status":        2,
		"db.opensearch.nodes_total":           3,
		"db.opensearch.nodes_data":            2,
		"db.opensearch.shards_active":         20,
		"db.opensearch.shards_active_primary": 10,
		"db.opensearch.shards_relocating":     0,
		"db.opensearch.shards_initializing":   1,
		"db.opensearch.shards_unassigned":     2,
		"db.opensearch.pending_tasks":         5,
	}
	for name, want := range cases {
		if got := mustGet(t, ms, name).Value; got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}

	// os_cluster label is promoted from cluster_name in the health response.
	m := mustGet(t, ms, "db.opensearch.nodes_total")
	if m.Labels["os_cluster"] != "test-cluster" {
		t.Fatalf("os_cluster label = %q, want %q", m.Labels["os_cluster"], "test-cluster")
	}
	if m.Labels["db_system"] != "opensearch" {
		t.Fatalf("db_system label = %q, want opensearch", m.Labels["db_system"])
	}
}

func TestYellowClusterStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_cluster/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(yellowHealthJSON))
	})
	mux.HandleFunc("/_nodes/stats", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodesJSON))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// yellow = 1
	if v := mustGet(t, ms, "db.opensearch.cluster_status").Value; v != 1 {
		t.Fatalf("cluster_status = %v, want 1 (yellow)", v)
	}
}

func TestRedClusterStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_cluster/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(redHealthJSON))
	})
	mux.HandleFunc("/_nodes/stats", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodesJSON))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// red = 0
	if v := mustGet(t, ms, "db.opensearch.cluster_status").Value; v != 0 {
		t.Fatalf("cluster_status = %v, want 0 (red)", v)
	}
	if v := mustGet(t, ms, "db.opensearch.shards_unassigned").Value; v != 5 {
		t.Fatalf("shards_unassigned = %v, want 5", v)
	}
}

func TestNodeStatsMetricsEmitted(t *testing.T) {
	srv := newHappyServer(t)
	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// Per-node metrics: two nodes × five metrics each.
	nodeMetrics := []string{
		"db.opensearch.node.heap_used_percent",
		"db.opensearch.node.docs_count",
		"db.opensearch.node.store_size_bytes",
		"db.opensearch.node.search_query_total",
		"db.opensearch.node.indexing_total",
	}
	for _, name := range nodeMetrics {
		if got := mustGet(t, ms, name, "os_node", "node-1").Value; got < 0 {
			t.Fatalf("%s for node-1 missing or negative: %v", name, got)
		}
	}

	// Spot-check a couple of values + types.
	if v := mustGet(t, ms, "db.opensearch.node.heap_used_percent", "os_node", "node-1").Value; v != 65 {
		t.Fatalf("node-1 heap_used_percent = %v, want 65", v)
	}
	if v := mustGet(t, ms, "db.opensearch.node.docs_count", "os_node", "node-1").Value; v != 10000 {
		t.Fatalf("node-1 docs_count = %v, want 10000", v)
	}
	if v := mustGet(t, ms, "db.opensearch.node.store_size_bytes", "os_node", "node-2").Value; v != 524288 {
		t.Fatalf("node-2 store_size_bytes = %v, want 524288", v)
	}

	// Counters for cumulative totals.
	if m := mustGet(t, ms, "db.opensearch.node.search_query_total", "os_node", "node-1"); m.Type != collector.MetricTypeCounter {
		t.Fatalf("search_query_total type = %q, want counter", m.Type)
	}
	if m := mustGet(t, ms, "db.opensearch.node.indexing_total", "os_node", "node-1"); m.Type != collector.MetricTypeCounter {
		t.Fatalf("indexing_total type = %q, want counter", m.Type)
	}

	// All five node metrics should be present for both nodes.
	for _, node := range []string{"node-1", "node-2"} {
		for _, name := range nodeMetrics {
			if _, ok := findMetric(ms, name, "os_node", node); !ok {
				t.Fatalf("metric %q for %s not emitted", name, node)
			}
		}
	}
}

// --- failure modes -------------------------------------------------------

func TestUnauthorizedReturnsStateZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on 401", state)
	}
	// Only the state metric should be emitted on failure.
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on failure, got %d", len(ms))
	}
}

func TestServiceUnavailableReturnsStateZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on 503", state)
	}
}

func TestMalformedHealthJSONReturnsStateZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on malformed JSON", state)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on failure, got %d", len(ms))
	}
}

func TestNodesStatsFailureKeepsClusterMetrics(t *testing.T) {
	// /_cluster/health succeeds; /_nodes/stats fails. We should still get
	// the cluster-level metrics (state=1, status, ...) and no node metrics.
	mux := http.NewServeMux()
	mux.HandleFunc("/_cluster/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(healthJSON))
	})
	mux.HandleFunc("/_nodes/stats", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 when health succeeds", state)
	}
	// Cluster metric must still be present.
	if v := mustGet(t, ms, "db.opensearch.nodes_total").Value; v != 3 {
		t.Fatalf("nodes_total = %v, want 3", v)
	}
	// No node-level metrics should be present.
	for _, m := range ms {
		if m.Labels["os_node"] != "" {
			t.Fatalf("did not expect node metrics, got %s", m.Name)
		}
	}
}

func TestMalformedNodesStatsJSONSkipped(t *testing.T) {
	// /_cluster/health succeeds; /_nodes/stats returns malformed JSON.
	// We should still get cluster-level metrics and no node metrics.
	mux := http.NewServeMux()
	mux.HandleFunc("/_cluster/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(healthJSON))
	})
	mux.HandleFunc("/_nodes/stats", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not valid json`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newOSCollector(t, []config.OpenSearchInstance{{Name: "os1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 when health succeeds", state)
	}
	for _, m := range ms {
		if m.Labels["os_node"] != "" {
			t.Fatalf("did not expect node metrics on malformed nodes JSON, got %s", m.Name)
		}
	}
}

// --- modes ---------------------------------------------------------------

func TestClusterHealthOnlySkipsNodeStats(t *testing.T) {
	srv := newHappyServer(t)
	c := newOSCollector(t, []config.OpenSearchInstance{{
		Name:              "os1",
		URL:               srv.URL,
		ClusterHealthOnly: true,
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// state=1, cluster metrics emitted.
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	if v := mustGet(t, ms, "db.opensearch.nodes_total").Value; v != 3 {
		t.Fatalf("nodes_total = %v, want 3", v)
	}
	// No node-level metrics.
	for _, m := range ms {
		if m.Labels["os_node"] != "" {
			t.Fatalf("ClusterHealthOnly should skip node metrics, got %s", m.Name)
		}
	}
	// Exactly: state + 9 cluster metrics = 10 metrics total.
	if len(ms) != 10 {
		t.Fatalf("expected 10 cluster metrics, got %d", len(ms))
	}
}

func TestBasicAuth(t *testing.T) {
	const user, pass = "admin", "s3cr3t"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Auth ok — route to handlers.
		switch r.URL.Path {
		case "/_cluster/health":
			_, _ = w.Write([]byte(healthJSON))
		case "/_nodes/stats":
			_, _ = w.Write([]byte(nodesJSON))
		}
	}))
	defer srv.Close()

	// Wrong credentials -> 401 -> state=0.
	bad := newOSCollector(t, []config.OpenSearchInstance{{
		Name: "os1", URL: srv.URL, Username: "wrong", Password: "nope",
	}})
	ms, err := bad.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on auth failure", state)
	}

	// Correct credentials -> state=1.
	good := newOSCollector(t, []config.OpenSearchInstance{{
		Name: "os1", URL: srv.URL, Username: user, Password: pass,
	}})
	ms, err = good.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 on auth success", state)
	}
}

func TestDefaultTimeoutApplied(t *testing.T) {
	// Instance with Timeout=0 must still work via the default timeout.
	srv := newHappyServer(t)
	c := newOSCollector(t, []config.OpenSearchInstance{{
		Name: "os1", URL: srv.URL, Timeout: 0,
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.opensearch.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 with default timeout", state)
	}
}

func TestMultipleInstances(t *testing.T) {
	// Two happy servers should yield two complete metric sets.
	srv1 := newHappyServer(t)
	srv2 := newHappyServer(t)
	c := newOSCollector(t, []config.OpenSearchInstance{
		{Name: "os-a", URL: srv1.URL},
		{Name: "os-b", URL: srv2.URL},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// Both clusters promote cluster_name=test-cluster so os_cluster collides;
	// however each instance still emits its own metric set. We expect two
	// state=1 markers (one per instance scrape).
	count := 0
	for _, m := range ms {
		if m.Name == "db.opensearch.state" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 state metrics (one per instance), got %d", count)
	}
}

func TestContextCancellationStopsIteration(t *testing.T) {
	// A slow /_cluster/health that respects ctx cancellation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	c := newOSCollector(t, []config.OpenSearchInstance{
		{Name: "os1", URL: srv.URL, Timeout: 5 * time.Second},
		{Name: "os2", URL: srv.URL, Timeout: 5 * time.Second},
	})
	ms, err := c.Collect(ctx)
	// Either ctx.Err() is returned (when iteration sees Done) or we get a
	// state=0 failure set from the timed-out first scrape. Both are
	// acceptable; we only assert the second instance is never scraped.
	_ = err
	// At most the first instance's state=0 metric should be present.
	count := 0
	for _, m := range ms {
		if m.Name == "db.opensearch.state" {
			count++
		}
	}
	if count > 1 {
		t.Fatalf("expected at most 1 state metric after cancellation, got %d", count)
	}
}
