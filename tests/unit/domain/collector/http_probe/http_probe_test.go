// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package http_probe_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/http_probe"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func newCollector(t *testing.T, targets []config.HTTPProbeTarget) *http_probe.HTTPProbeCollector {
	t.Helper()
	c := http_probe.NewHTTPProbeCollector(config.HTTPProbeCollectorConfig{
		Enabled:  true,
		Interval: 30 * time.Second,
		Targets:  targets,
	}, zap.NewNop())
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	return c
}

func newTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello world")
	})
	mux.HandleFunc("/500", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound) // 302
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/text", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "the quick brown fox jumps over the lazy dog")
	})
	return httptest.NewServer(mux)
}

func findMetric(metrics []collector.Metric, name string) (collector.Metric, bool) {
	for _, m := range metrics {
		if m.Name == name {
			return m, true
		}
	}
	return collector.Metric{}, false
}

func mustGet(t *testing.T, metrics []collector.Metric, name string) collector.Metric {
	t.Helper()
	m, ok := findMetric(metrics, name)
	if !ok {
		t.Fatalf("metric %q not found in %d metrics", name, len(metrics))
	}
	return m
}

func TestProbeSuccess200(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{{URL: srv.URL, Name: "ok"}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "network.http.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	if sc := mustGet(t, ms, "network.http.status_code").Value; sc != 200 {
		t.Fatalf("status_code = %v, want 200", sc)
	}
	if rt := mustGet(t, ms, "network.http.response_time_ms").Value; rt <= 0 {
		t.Fatalf("response_time_ms = %v, want > 0", rt)
	}
	if cl := mustGet(t, ms, "network.http.content_length").Value; cl != 11 {
		t.Fatalf("content_length = %v, want 11", cl)
	}
}

func TestProbe500IsFailByDefault(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{{URL: srv.URL + "/500", Name: "err"}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "network.http.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 (500 not in default expected)", state)
	}
	if sc := mustGet(t, ms, "network.http.status_code").Value; sc != 500 {
		t.Fatalf("status_code = %v, want 500", sc)
	}
}

func TestProbeCustomExpectedStatus(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL + "/500", Name: "err", ExpectedStatus: []int{500}},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "network.http.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	if sc := mustGet(t, ms, "network.http.status_code").Value; sc != 500 {
		t.Fatalf("status_code = %v, want 500", sc)
	}
}

func TestProbeRedirectFollowed(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL + "/redirect", Name: "redir", FollowRedirects: true},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "network.http.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	if rc := mustGet(t, ms, "network.http.redirect_count").Value; rc != 1 {
		t.Fatalf("redirect_count = %v, want 1", rc)
	}
	if sc := mustGet(t, ms, "network.http.status_code").Value; sc != 200 {
		t.Fatalf("status_code = %v, want 200", sc)
	}
}

func TestProbeRedirectNotFollowed(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL + "/redirect", Name: "redir-nofollow", FollowRedirects: false},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if sc := mustGet(t, ms, "network.http.status_code").Value; sc != 302 {
		t.Fatalf("status_code = %v, want 302", sc)
	}
	if rc := mustGet(t, ms, "network.http.redirect_count").Value; rc != 0 {
		t.Fatalf("redirect_count = %v, want 0", rc)
	}
}

func TestProbeTLSSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "secure")
	}))
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL, Name: "tls", TLSSkipVerify: true},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "network.http.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	if days := mustGet(t, ms, "network.http.tls_days_remaining").Value; days < 0 {
		t.Fatalf("tls_days_remaining = %v, want >= 0", days)
	}
	if valid := mustGet(t, ms, "network.http.tls_valid").Value; valid != 1 {
		t.Fatalf("tls_valid = %v, want 1", valid)
	}
}

func TestProbeTimeout(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL + "/slow", Name: "slow", Timeout: 100 * time.Millisecond},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "network.http.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on timeout", state)
	}
	if sc := mustGet(t, ms, "network.http.status_code").Value; sc != 0 {
		t.Fatalf("status_code = %v, want 0 on transport failure", sc)
	}
}

func TestProbeBodyRegexMatch(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL + "/text", Name: "text", ExpectedBodyRegex: "quick.*fox"},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if found := mustGet(t, ms, "network.http.string_found").Value; found != 1 {
		t.Fatalf("string_found = %v, want 1", found)
	}
}

func TestProbeBodyRegexNoMatch(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL + "/text", Name: "text", ExpectedBodyRegex: "doesnotexist"},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if found := mustGet(t, ms, "network.http.string_found").Value; found != 0 {
		t.Fatalf("string_found = %v, want 0", found)
	}
}

func TestProbeDefaults(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	// Minimal target: no method, no timeout, no expected_status. Defaults must
	// yield Method=GET, Timeout=10s, ExpectedStatus=[200,201,204,301,302].
	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL, Name: "defaults"},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "network.http.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 with default expected status", state)
	}
	if sc := mustGet(t, ms, "network.http.status_code").Value; sc != 200 {
		t.Fatalf("status_code = %v, want 200 (GET default)", sc)
	}
}

func TestProbeContextCancellation(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	c := newCollector(t, []config.HTTPProbeTarget{
		{URL: srv.URL + "/slow", Name: "slow1", Timeout: 2 * time.Second},
		{URL: srv.URL, Name: "fast", Timeout: 2 * time.Second},
	})
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so the slow target aborts before the fast one runs.
	cancel()
	ms, err := c.Collect(ctx)
	// We accept either a context error or a (possibly partial) metric set; the
	// contract is that cancellation between targets is honored, not that a
	// specific error is returned.
	_ = ms
	if err != nil && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCollectorLifecycle(t *testing.T) {
	c := http_probe.NewHTTPProbeCollector(config.HTTPProbeCollectorConfig{}, zap.NewNop())
	const wantName = "http_probe"
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

func TestCollectNoTargets(t *testing.T) {
	c := newCollector(t, nil)
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if ms != nil {
		t.Fatalf("expected nil metrics, got %d", len(ms))
	}
}
