// External black-box unit tests for the Couchbase collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package couchbase_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/couchbase"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- fixtures -------------------------------------------------------------

const poolsJSON = `{
  "name": "test-cluster",
  "storageTotals": {
    "ram": {"used": 1000000, "total": 2000000},
    "hdd": {"used": 5000000, "total": 10000000}
  },
  "nodes": [
    {
      "hostname": "10.0.0.1:8091",
      "otpNode": "ns_1@10.0.0.1",
      "systemStats": {"mem_used": 123456, "cpu_utilization_rate": 12.5},
      "interestingStats": {"cmd_get": 5000}
    },
    {
      "hostname": "10.0.0.2:8091",
      "otpNode": "ns_1@10.0.0.2",
      "systemStats": {"mem_used": 234567, "cpu_utilization_rate": 7.25},
      "interestingStats": {"cmd_get": 3000}
    }
  ]
}`

const bucketDefaultJSON = `{
  "name": "default",
  "basicStats": {
    "opsPerSec": 150.5,
    "diskUsed": 1048576,
    "memUsed": 524288,
    "itemCount": 10000
  }
}`

const bucketTravelJSON = `{
  "name": "travel-data",
  "basicStats": {
    "opsPerSec": 42,
    "diskUsed": 2097152,
    "memUsed": 131072,
    "itemCount": 2500
  }
}`

// newCBCollector constructs a collector with sane defaults and ensures it is
// stopped during test cleanup.
func newCBCollector(t *testing.T, instances []config.CouchbaseInstance) *couchbase.CouchbaseCollector {
	t.Helper()
	c := couchbase.NewCouchbaseCollector(config.CouchbaseCollectorConfig{
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

// newPoolsServer serves only /pools/default.
func newPoolsServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pools/default", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(poolsJSON))
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

// --- lifecycle -----------------------------------------------------------

func TestCollectorLifecycle(t *testing.T) {
	c := couchbase.NewCouchbaseCollector(config.CouchbaseCollectorConfig{}, zap.NewNop())
	const wantName = "couchbase"
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
	var _ collector.Collector = (*couchbase.CouchbaseCollector)(nil)
}

func TestCollectNoInstances(t *testing.T) {
	c := newCBCollector(t, nil)
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if ms != nil {
		t.Fatalf("expected nil metrics, got %d", len(ms))
	}
}

// --- cluster-level happy path -------------------------------------------

func TestClusterAndNodeMetricsEmitted(t *testing.T) {
	srv := newPoolsServer(t)
	c := newCBCollector(t, []config.CouchbaseInstance{{Name: "cb1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// state must be 1 on a successful scrape.
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}

	// Cluster-wide storage totals + node count.
	cases := map[string]float64{
		"db.couchbase.cluster.ram_used_bytes":  1000000,
		"db.couchbase.cluster.ram_total_bytes": 2000000,
		"db.couchbase.cluster.hdd_used_bytes":  5000000,
		"db.couchbase.cluster.hdd_total_bytes": 10000000,
		"db.couchbase.cluster.node_count":      2,
	}
	for name, want := range cases {
		if got := mustGet(t, ms, name).Value; got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}

	// cb_cluster label is promoted from the cluster name in the pools response.
	m := mustGet(t, ms, "db.couchbase.cluster.node_count")
	if m.Labels["cb_cluster"] != "test-cluster" {
		t.Fatalf("cb_cluster label = %q, want %q", m.Labels["cb_cluster"], "test-cluster")
	}
	if m.Labels["db_system"] != "couchbase" {
		t.Fatalf("db_system label = %q, want couchbase", m.Labels["db_system"])
	}

	// Per-node metrics: two nodes × three metrics each.
	node1 := "10.0.0.1:8091"
	node2 := "10.0.0.2:8091"

	if v := mustGet(t, ms, "db.couchbase.node.mem_used_bytes", "cb_node", node1).Value; v != 123456 {
		t.Fatalf("node1 mem_used_bytes = %v, want 123456", v)
	}
	if v := mustGet(t, ms, "db.couchbase.node.cpu_utilization", "cb_node", node1).Value; v != 12.5 {
		t.Fatalf("node1 cpu_utilization = %v, want 12.5", v)
	}
	if v := mustGet(t, ms, "db.couchbase.node.cmd_get_total", "cb_node", node1).Value; v != 5000 {
		t.Fatalf("node1 cmd_get_total = %v, want 5000", v)
	}
	if v := mustGet(t, ms, "db.couchbase.node.mem_used_bytes", "cb_node", node2).Value; v != 234567 {
		t.Fatalf("node2 mem_used_bytes = %v, want 234567", v)
	}
	if v := mustGet(t, ms, "db.couchbase.node.cpu_utilization", "cb_node", node2).Value; v != 7.25 {
		t.Fatalf("node2 cpu_utilization = %v, want 7.25", v)
	}
	if v := mustGet(t, ms, "db.couchbase.node.cmd_get_total", "cb_node", node2).Value; v != 3000 {
		t.Fatalf("node2 cmd_get_total = %v, want 3000", v)
	}

	// cmd_get_total is a counter; the other node metrics are gauges.
	if m := mustGet(t, ms, "db.couchbase.node.cmd_get_total", "cb_node", node1); m.Type != collector.MetricTypeCounter {
		t.Fatalf("cmd_get_total type = %q, want counter", m.Type)
	}
	if m := mustGet(t, ms, "db.couchbase.node.mem_used_bytes", "cb_node", node1); m.Type != collector.MetricTypeGauge {
		t.Fatalf("mem_used_bytes type = %q, want gauge", m.Type)
	}
	if m := mustGet(t, ms, "db.couchbase.node.cpu_utilization", "cb_node", node1); m.Type != collector.MetricTypeGauge {
		t.Fatalf("cpu_utilization type = %q, want gauge", m.Type)
	}

	// No bucket metrics should be present when Buckets is empty.
	for _, m := range ms {
		if m.Labels["cb_bucket"] != "" {
			t.Fatalf("did not expect bucket metrics, got %s", m.Name)
		}
	}
}

// --- bucket-level happy path -------------------------------------------

func TestBucketMetricsEmitted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/pools/default", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(poolsJSON))
	})
	mux.HandleFunc("/pools/default/buckets/default", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bucketDefaultJSON))
	})
	mux.HandleFunc("/pools/default/buckets/travel-data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bucketTravelJSON))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newCBCollector(t, []config.CouchbaseInstance{{
		Name:    "cb1",
		URL:     srv.URL,
		Buckets: []string{"default", "travel-data"},
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// state must be 1 — the cluster scrape still succeeded.
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}

	// default bucket values.
	if v := mustGet(t, ms, "db.couchbase.bucket.ops_per_sec", "cb_bucket", "default").Value; v != 150.5 {
		t.Fatalf("default ops_per_sec = %v, want 150.5", v)
	}
	if v := mustGet(t, ms, "db.couchbase.bucket.disk_used_bytes", "cb_bucket", "default").Value; v != 1048576 {
		t.Fatalf("default disk_used_bytes = %v, want 1048576", v)
	}
	if v := mustGet(t, ms, "db.couchbase.bucket.mem_used_bytes", "cb_bucket", "default").Value; v != 524288 {
		t.Fatalf("default mem_used_bytes = %v, want 524288", v)
	}
	if v := mustGet(t, ms, "db.couchbase.bucket.item_count", "cb_bucket", "default").Value; v != 10000 {
		t.Fatalf("default item_count = %v, want 10000", v)
	}

	// travel-data bucket values.
	if v := mustGet(t, ms, "db.couchbase.bucket.ops_per_sec", "cb_bucket", "travel-data").Value; v != 42 {
		t.Fatalf("travel-data ops_per_sec = %v, want 42", v)
	}
	if v := mustGet(t, ms, "db.couchbase.bucket.disk_used_bytes", "cb_bucket", "travel-data").Value; v != 2097152 {
		t.Fatalf("travel-data disk_used_bytes = %v, want 2097152", v)
	}
	if v := mustGet(t, ms, "db.couchbase.bucket.item_count", "cb_bucket", "travel-data").Value; v != 2500 {
		t.Fatalf("travel-data item_count = %v, want 2500", v)
	}

	// All bucket metrics are gauges.
	for _, name := range []string{
		"db.couchbase.bucket.ops_per_sec",
		"db.couchbase.bucket.disk_used_bytes",
		"db.couchbase.bucket.mem_used_bytes",
		"db.couchbase.bucket.item_count",
	} {
		if m := mustGet(t, ms, name, "cb_bucket", "default"); m.Type != collector.MetricTypeGauge {
			t.Fatalf("%s type = %q, want gauge", name, m.Type)
		}
	}
}

// --- failure modes -------------------------------------------------------

func TestUnauthorizedReturnsStateZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newCBCollector(t, []config.CouchbaseInstance{{
		Name: "cb1", URL: srv.URL, Buckets: []string{"default"},
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on 401", state)
	}
	// Only the state metric should be emitted on failure.
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on failure, got %d", len(ms))
	}
}

func TestMalformedPoolsJSONReturnsStateZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	c := newCBCollector(t, []config.CouchbaseInstance{{
		Name: "cb1", URL: srv.URL, Buckets: []string{"default"},
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on malformed JSON", state)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on failure, got %d", len(ms))
	}
}

// --- modes ---------------------------------------------------------------

func TestEmptyBucketsSkipsBucketFetch(t *testing.T) {
	// A bucket handler that would fail the test if hit.
	mux := http.NewServeMux()
	mux.HandleFunc("/pools/default", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(poolsJSON))
	})
	mux.HandleFunc("/pools/default/buckets/", func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("bucket endpoint should not be hit when Buckets is empty: %s", r.URL.Path)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newCBCollector(t, []config.CouchbaseInstance{{
		Name:    "cb1",
		URL:     srv.URL,
		Buckets: nil,
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// state=1, cluster metrics emitted.
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	if v := mustGet(t, ms, "db.couchbase.cluster.node_count").Value; v != 2 {
		t.Fatalf("node_count = %v, want 2", v)
	}

	// No bucket metrics present.
	for _, m := range ms {
		if m.Labels["cb_bucket"] != "" {
			t.Fatalf("did not expect bucket metrics, got %s", m.Name)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	const user, pass = "admin", "secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/pools/default":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(poolsJSON))
		case "/pools/default/buckets/default":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(bucketDefaultJSON))
		}
	}))
	defer srv.Close()

	// Wrong credentials -> 401 -> state=0.
	bad := newCBCollector(t, []config.CouchbaseInstance{{
		Name: "cb1", URL: srv.URL, Username: "wrong", Password: "nope",
		Buckets: []string{"default"},
	}})
	ms, err := bad.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on auth failure", state)
	}

	// Correct credentials -> state=1.
	good := newCBCollector(t, []config.CouchbaseInstance{{
		Name: "cb1", URL: srv.URL, Username: user, Password: pass,
		Buckets: []string{"default"},
	}})
	ms, err = good.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 on auth success", state)
	}
	// Bucket metric should be present.
	if v := mustGet(t, ms, "db.couchbase.bucket.item_count", "cb_bucket", "default").Value; v != 10000 {
		t.Fatalf("default item_count = %v, want 10000", v)
	}
}

func TestDefaultTimeoutApplied(t *testing.T) {
	// Instance with Timeout=0 must still work via the default timeout.
	srv := newPoolsServer(t)
	c := newCBCollector(t, []config.CouchbaseInstance{{
		Name: "cb1", URL: srv.URL, Timeout: 0,
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 with default timeout", state)
	}
}

func TestBucketScrapeFailureKeepsClusterMetrics(t *testing.T) {
	// /pools/default succeeds; the bucket endpoint fails. Cluster metrics
	// survive and no bucket metrics are emitted.
	mux := http.NewServeMux()
	mux.HandleFunc("/pools/default", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(poolsJSON))
	})
	mux.HandleFunc("/pools/default/buckets/default", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newCBCollector(t, []config.CouchbaseInstance{{
		Name: "cb1", URL: srv.URL, Buckets: []string{"default"},
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "db.couchbase.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 when pools succeeds", state)
	}
	if v := mustGet(t, ms, "db.couchbase.cluster.node_count").Value; v != 2 {
		t.Fatalf("node_count = %v, want 2", v)
	}
	for _, m := range ms {
		if m.Labels["cb_bucket"] != "" {
			t.Fatalf("did not expect bucket metrics on bucket failure, got %s", m.Name)
		}
	}
}
