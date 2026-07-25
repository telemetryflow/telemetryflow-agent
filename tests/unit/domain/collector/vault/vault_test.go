// External black-box unit tests for the Vault collector.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package vault_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/vault"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// --- fixtures -------------------------------------------------------------

// happyProm exercises gauges, counters, and a labeled counter.
const happyProm = `# HELP vault_token_count Number of tokens
# TYPE vault_token_count gauge
vault_token_count 50
# HELP vault_audit_log_request_total Number of audit log requests
# TYPE vault_audit_log_request_total counter
vault_audit_log_request_total 100
# HELP vault_core_handle_request_count Number of handled requests
# TYPE vault_core_handle_request_count counter
vault_core_handle_request_count{method="read"} 1234
vault_core_handle_request_count{method="write"} 567
# HELP vault_runtime_alloc_bytes Allocated bytes
# TYPE vault_runtime_alloc_bytes gauge
vault_runtime_alloc_bytes 8.912345e+07
# HELP vault_runtime_sys_bytes Sys bytes
# TYPE vault_runtime_sys_bytes gauge
vault_runtime_sys_bytes 10485760
# HELP vault_runtime_num_goroutines Number of goroutines
# TYPE vault_runtime_num_goroutines gauge
vault_runtime_num_goroutines 42
`

// histogramProm exercises a histogram family (bucket + sum + count).
const histogramProm = `# HELP vault_raft_commit_time Time in ms to commit a raft entry
# TYPE vault_raft_commit_time histogram
vault_raft_commit_time_bucket{le="5"} 100
vault_raft_commit_time_bucket{le="10"} 150
vault_raft_commit_time_bucket{le="+Inf"} 200
vault_raft_commit_time_sum 1234.5
vault_raft_commit_time_count 200
`

// newVaultCollector constructs a collector with sane defaults and ensures it
// is stopped during test cleanup.
func newVaultCollector(t *testing.T, instances []config.VaultInstance) *vault.VaultCollector {
	t.Helper()
	c := vault.NewVaultCollector(config.VaultCollectorConfig{
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

// newPromServer returns an httptest server that responds to the Vault metrics
// path with the given canned body and status code.
func newPromServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
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
	c := vault.NewVaultCollector(config.VaultCollectorConfig{}, zap.NewNop())
	const wantName = "vault"
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
	var _ collector.Collector = (*vault.VaultCollector)(nil)
}

func TestCollectNoInstances(t *testing.T) {
	c := newVaultCollector(t, nil)
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if ms != nil {
		t.Fatalf("expected nil metrics, got %d", len(ms))
	}
}

// --- happy path ----------------------------------------------------------

func TestHappyPathMetricsForwarded(t *testing.T) {
	srv := newPromServer(t, http.StatusOK, happyProm)
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// state must be 1 on a successful scrape.
	if state := mustGet(t, ms, "vault.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}

	// The five distinct source metrics are forwarded (one of them has two
	// labeled samples, so 7 samples total + state marker = 8 metrics).
	cases := map[string]float64{
		"vault.token_count":             50,
		"vault.audit_log_request_total": 100,
		"vault.runtime_alloc_bytes":     8.912345e+07,
		"vault.runtime_sys_bytes":       10485760,
		"vault.runtime_num_goroutines":  42,
	}
	for name, want := range cases {
		if got := mustGet(t, ms, name).Value; got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}

	// Labeled counter: both method variants present with forwarded values.
	if got := mustGet(t, ms, "vault.core_handle_request_count", "method", "read").Value; got != 1234 {
		t.Fatalf("handle_request_count read = %v, want 1234", got)
	}
	if got := mustGet(t, ms, "vault.core_handle_request_count", "method", "write").Value; got != 567 {
		t.Fatalf("handle_request_count write = %v, want 567", got)
	}

	// Types preserved by TYPE declarations.
	if m := mustGet(t, ms, "vault.token_count"); m.Type != collector.MetricTypeGauge {
		t.Fatalf("token_count type = %q, want gauge", m.Type)
	}
	if m := mustGet(t, ms, "vault.audit_log_request_total"); m.Type != collector.MetricTypeCounter {
		t.Fatalf("audit_log_request_total type = %q, want counter", m.Type)
	}
	if m := mustGet(t, ms, "vault.core_handle_request_count"); m.Type != collector.MetricTypeCounter {
		t.Fatalf("core_handle_request_count type = %q, want counter", m.Type)
	}

	// HELP text is carried through.
	if m := mustGet(t, ms, "vault.token_count"); m.Description != "Number of tokens" {
		t.Fatalf("token_count help = %q, want %q", m.Description, "Number of tokens")
	}

	// Base labels attached.
	m := mustGet(t, ms, "vault.token_count")
	if m.Labels["vault_instance"] != "v1" {
		t.Fatalf("vault_instance = %q, want v1", m.Labels["vault_instance"])
	}
	if m.Labels["db_system"] != "vault" {
		t.Fatalf("db_system = %q, want vault", m.Labels["db_system"])
	}

	// Sanity: exactly 7 samples + 1 state marker.
	if len(ms) != 8 {
		t.Fatalf("expected 8 metrics (7 samples + state), got %d", len(ms))
	}
}

func TestHostLabelDerivedFromURL(t *testing.T) {
	srv := newPromServer(t, http.StatusOK, happyProm)
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	m := mustGet(t, ms, "vault.token_count")
	if m.Labels["vault_host"] == "" || m.Labels["vault_host"] == srv.URL {
		t.Fatalf("vault_host should be derived host:port, got %q", m.Labels["vault_host"])
	}
	// httptest.Server.URL is http://127.0.0.1:<port>; host label must contain it.
	if !contains(m.Labels["vault_host"], "127.0.0.1") {
		t.Fatalf("vault_host = %q, want it to contain 127.0.0.1", m.Labels["vault_host"])
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- histogram -----------------------------------------------------------

func TestHistogramMetricsEmitted(t *testing.T) {
	srv := newPromServer(t, http.StatusOK, histogramProm)
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	if state := mustGet(t, ms, "vault.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}

	// bucket: each le variant emitted with histogram type.
	for _, le := range []string{"5", "10", "+Inf"} {
		m := mustGet(t, ms, "vault.raft_commit_time_bucket", "le", le)
		if m.Type != collector.MetricTypeHistogram {
			t.Fatalf("bucket le=%s type = %q, want histogram", le, m.Type)
		}
	}
	if got := mustGet(t, ms, "vault.raft_commit_time_bucket", "le", "5").Value; got != 100 {
		t.Fatalf("bucket le=5 = %v, want 100", got)
	}
	if got := mustGet(t, ms, "vault.raft_commit_time_bucket", "le", "+Inf").Value; got != 200 {
		t.Fatalf("bucket le=+Inf = %v, want 200", got)
	}

	// sum + count emitted with histogram type.
	if got := mustGet(t, ms, "vault.raft_commit_time_sum").Value; got != 1234.5 {
		t.Fatalf("sum = %v, want 1234.5", got)
	}
	if got := mustGet(t, ms, "vault.raft_commit_time_count").Value; got != 200 {
		t.Fatalf("count = %v, want 200", got)
	}
	if m := mustGet(t, ms, "vault.raft_commit_time_sum"); m.Type != collector.MetricTypeHistogram {
		t.Fatalf("sum type = %q, want histogram", m.Type)
	}
	if m := mustGet(t, ms, "vault.raft_commit_time_count"); m.Type != collector.MetricTypeHistogram {
		t.Fatalf("count type = %q, want histogram", m.Type)
	}

	// 3 buckets + sum + count + state = 6 metrics.
	if len(ms) != 6 {
		t.Fatalf("expected 6 metrics, got %d", len(ms))
	}
}

// --- failure modes -------------------------------------------------------

func TestUnauthorizedReturnsStateZero(t *testing.T) {
	srv := newPromServer(t, http.StatusUnauthorized, "")
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on 401", state)
	}
	// Only the state metric should be emitted on failure.
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on failure, got %d", len(ms))
	}
}

func TestEmptyResponseReturnsStateZero(t *testing.T) {
	srv := newPromServer(t, http.StatusOK, "")
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on empty body", state)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on empty body, got %d", len(ms))
	}
}

func TestMalformedTextReturnsStateZero(t *testing.T) {
	// No valid samples (no TYPE, malformed lines): parser yields zero metrics.
	srv := newPromServer(t, http.StatusOK, "this is not prometheus text\n%%%garbage\n{broken")
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on malformed text", state)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on malformed text, got %d", len(ms))
	}
}

// --- auth & headers ------------------------------------------------------

func TestTokenAuth(t *testing.T) {
	const token = "s.tOkenSecret123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(happyProm))
	}))
	defer srv.Close()

	// Missing token -> 401 -> state=0.
	bad := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := bad.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on missing token", state)
	}

	// Correct token -> state=1.
	good := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL, Token: token}})
	ms, err = good.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 with correct token", state)
	}
}

func TestNamespaceHeaderForwarded(t *testing.T) {
	const ns = "secret/team-a"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Namespace"); got != ns {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(happyProm))
	}))
	defer srv.Close()

	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL, Namespace: ns}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 when namespace header accepted", state)
	}
}

func TestMetricsPathAndFormatDefault(t *testing.T) {
	// Verify the collector hits /v1/sys/metrics?format=prometheus by default.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/metrics" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("format") != "prometheus" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(happyProm))
	}))
	defer srv.Close()

	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 on default path", state)
	}
}

func TestDefaultTimeoutApplied(t *testing.T) {
	// Instance with Timeout=0 must still work via the default timeout.
	srv := newPromServer(t, http.StatusOK, happyProm)
	c := newVaultCollector(t, []config.VaultInstance{{
		Name: "v1", URL: srv.URL, Timeout: 0,
	}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 with default timeout", state)
	}
}

func TestEscapedLabelValues(t *testing.T) {
	// Label values with escaped characters (\\n, \") must decode correctly.
	const body = `# HELP vault_route_request_count Request count
# TYPE vault_route_request_count counter
vault_route_request_count{path="secret/data/foo",op="\"read\""} 7
`
	srv := newPromServer(t, http.StatusOK, body)
	c := newVaultCollector(t, []config.VaultInstance{{Name: "v1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "vault.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	m, ok := findMetric(ms, "vault.route_request_count", "path", "secret/data/foo")
	if !ok {
		t.Fatalf("route_request_count with path label not found")
	}
	if got := m.Labels["op"]; got != `"read"` {
		t.Fatalf("escaped op label = %q, want %q", got, `"read"`)
	}
	if m.Value != 7 {
		t.Fatalf("value = %v, want 7", m.Value)
	}
}
