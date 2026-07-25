// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package haproxy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/haproxy"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// sampleCSV matches the field layout documented in the HAProxy stats CSV spec.
// Columns: pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,
//
//	dreq,dresp,ereq,econ,eresp,wretr,status,weight,act,bck,
//	hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx
const sampleCSV = `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,status,weight,act,bck,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx
myapp,FRONTEND,,,1,2,1000,1234,56789,98765,0,0,0,0,0,0,OPEN,1,1,0,0,100,0,0,0
myapp,BACKEND,0,0,1,1,,1000,56789,98765,0,0,0,1,0,0,UP,1,1,0,0,100,0,0,0
myapp,server1,0,0,1,1,1000,500,12345,54321,0,0,0,0,0,0,UP,100,1,0,0,90,5,3,2
myapp,server2,0,0,0,1,1000,250,11111,22222,0,0,0,0,1,0,DOWN,0,0,0,0,0,0,0,250
`

func newCollector(t *testing.T, instances []config.HAProxyInstance) *haproxy.HAProxyCollector {
	t.Helper()
	c := haproxy.NewHAProxyCollector(config.HAProxyCollectorConfig{
		Enabled:   true,
		Interval:  30 * time.Second,
		Instances: instances,
	}, zap.NewNop())
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	return c
}

func findMetricWithLabels(metrics []collector.Metric, name string, want map[string]string) (collector.Metric, bool) {
	for _, m := range metrics {
		if m.Name != name {
			continue
		}
		match := true
		for k, v := range want {
			if m.Labels[k] != v {
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

func mustGet(t *testing.T, metrics []collector.Metric, name string, want map[string]string) collector.Metric {
	t.Helper()
	m, ok := findMetricWithLabels(metrics, name, want)
	if !ok {
		t.Fatalf("metric %q with labels %v not found in %d metrics", name, want, len(metrics))
	}
	return m
}

func TestCollectHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(sampleCSV))
	}))
	defer srv.Close()

	c := newCollector(t, []config.HAProxyInstance{{Name: "local", URL: srv.URL + "/stats;csv"}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// Frontend row: status OPEN -> 1, sessions_current=1, sessions_max=2.
	feLabels := map[string]string{"pxname": "myapp", "svname": "FRONTEND", "type": "frontend"}
	if v := mustGet(t, ms, "proxy.haproxy.status", feLabels).Value; v != 1 {
		t.Fatalf("frontend status = %v, want 1 (OPEN)", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.sessions_current", feLabels).Value; v != 1 {
		t.Fatalf("frontend sessions_current = %v, want 1", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.sessions_max", feLabels).Value; v != 2 {
		t.Fatalf("frontend sessions_max = %v, want 2", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.sessions_total", feLabels).Value; v != 1234 {
		t.Fatalf("frontend sessions_total = %v, want 1234", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.bytes_in_total", feLabels).Value; v != 56789 {
		t.Fatalf("frontend bytes_in_total = %v, want 56789", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.bytes_out_total", feLabels).Value; v != 98765 {
		t.Fatalf("frontend bytes_out_total = %v, want 98765", v)
	}

	// Backend row: active_servers=1, backup_servers=0, status UP -> 1.
	beLabels := map[string]string{"pxname": "myapp", "svname": "BACKEND", "type": "backend"}
	if v := mustGet(t, ms, "proxy.haproxy.active_servers", beLabels).Value; v != 1 {
		t.Fatalf("backend active_servers = %v, want 1", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.backup_servers", beLabels).Value; v != 0 {
		t.Fatalf("backend backup_servers = %v, want 0", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.connection_errors_total", beLabels).Value; v != 1 {
		t.Fatalf("backend connection_errors_total = %v, want 1", v)
	}

	// Server1: status UP -> 1, bytes_in_total=12345, weight=100.
	s1Labels := map[string]string{"pxname": "myapp", "svname": "server1", "type": "server"}
	if v := mustGet(t, ms, "proxy.haproxy.status", s1Labels).Value; v != 1 {
		t.Fatalf("server1 status = %v, want 1 (UP)", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.bytes_in_total", s1Labels).Value; v != 12345 {
		t.Fatalf("server1 bytes_in_total = %v, want 12345", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.server_weight", s1Labels).Value; v != 100 {
		t.Fatalf("server1 weight = %v, want 100", v)
	}

	// Server1 HTTP responses: code=2xx -> 90.
	hrsp2xx := mustGet(t, ms, "proxy.haproxy.http_responses_total",
		map[string]string{"svname": "server1", "code": "2xx"})
	if v := hrsp2xx.Value; v != 90 {
		t.Fatalf("server1 http_responses_total{2xx} = %v, want 90", v)
	}
	hrsp5xx := mustGet(t, ms, "proxy.haproxy.http_responses_total",
		map[string]string{"svname": "server1", "code": "5xx"})
	if v := hrsp5xx.Value; v != 2 {
		t.Fatalf("server1 http_responses_total{5xx} = %v, want 2", v)
	}

	// Server2: status DOWN -> 0, response_errors_total=1.
	s2Labels := map[string]string{"pxname": "myapp", "svname": "server2", "type": "server"}
	if v := mustGet(t, ms, "proxy.haproxy.status", s2Labels).Value; v != 0 {
		t.Fatalf("server2 status = %v, want 0 (DOWN)", v)
	}
	if v := mustGet(t, ms, "proxy.haproxy.response_errors_total", s2Labels).Value; v != 1 {
		t.Fatalf("server2 response_errors_total = %v, want 1", v)
	}

	// Servers must NOT carry active_servers (backend-only metric).
	if _, ok := findMetricWithLabels(ms, "proxy.haproxy.active_servers", s1Labels); ok {
		t.Fatal("server row must not emit active_servers")
	}

	// Instance labels are attached to every metric.
	if v := mustGet(t, ms, "proxy.haproxy.status", s1Labels).Labels["haproxy_instance"]; v != "local" {
		t.Fatalf("haproxy_instance label = %q, want local", v)
	}
}

func TestCollectUnauthorizedReturnsStatusZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newCollector(t, []config.HAProxyInstance{{Name: "local", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 failure metric, got %d", len(ms))
	}
	m := ms[0]
	if m.Name != "proxy.haproxy.status" {
		t.Fatalf("metric name = %q, want proxy.haproxy.status", m.Name)
	}
	if m.Value != 0 {
		t.Fatalf("status = %v, want 0 on 401", m.Value)
	}
	if m.Labels["haproxy_instance"] != "local" {
		t.Fatalf("haproxy_instance = %q, want local", m.Labels["haproxy_instance"])
	}
}

func TestCollectEmptyBodyReturnsStatusZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(""))
	}))
	defer srv.Close()

	c := newCollector(t, []config.HAProxyInstance{{Name: "local", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(ms) != 1 || ms[0].Name != "proxy.haproxy.status" || ms[0].Value != 0 {
		t.Fatalf("expected single status=0 on empty body, got %+v", ms)
	}
}

func TestCollectMalformedCSVReturnsStatusZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unterminated quoted field forces encoding/csv to error.
		_, _ = w.Write([]byte("# pxname,svname\n\"unterminated,"))
	}))
	defer srv.Close()

	c := newCollector(t, []config.HAProxyInstance{{Name: "local", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(ms) != 1 || ms[0].Name != "proxy.haproxy.status" || ms[0].Value != 0 {
		t.Fatalf("expected single status=0 on malformed csv, got %+v", ms)
	}
}

func TestCollectBasicAuth(t *testing.T) {
	const user, pass = "admin", "s3cr3t"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(sampleCSV))
	}))
	defer srv.Close()

	c := newCollector(t, []config.HAProxyInstance{
		{Name: "local", URL: srv.URL, Username: user, Password: pass},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// Auth succeeded -> we get per-row metrics, not the single failure metric.
	if len(ms) <= 1 {
		t.Fatalf("expected multiple metrics after successful auth, got %d", len(ms))
	}
	feLabels := map[string]string{"pxname": "myapp", "svname": "FRONTEND", "type": "frontend"}
	if v := mustGet(t, ms, "proxy.haproxy.status", feLabels).Value; v != 1 {
		t.Fatalf("frontend status = %v, want 1 (OPEN) after auth", v)
	}
}

func TestCollectBasicAuthWrongCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newCollector(t, []config.HAProxyInstance{
		{Name: "local", URL: srv.URL, Username: "admin", Password: "wrong"},
	})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(ms) != 1 || ms[0].Value != 0 {
		t.Fatalf("expected single status=0 on bad auth, got %+v", ms)
	}
}

func TestCollectNoInstances(t *testing.T) {
	c := newCollector(t, nil)
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if ms != nil {
		t.Fatalf("expected nil metrics, got %d", len(ms))
	}
}

func TestCollectorLifecycle(t *testing.T) {
	c := haproxy.NewHAProxyCollector(config.HAProxyCollectorConfig{}, zap.NewNop())
	const wantName = "haproxy"
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

func TestStatusValueMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csv := "# pxname,svname,status\n" +
			"a,UP,UP\n" +
			"b,DOWN,DOWN\n" +
			"c,MAINT,MAINT\n" +
			"d,DRAIN,DRAIN\n" +
			"e,OPEN,OPEN\n"
		_, _ = w.Write([]byte(csv))
	}))
	defer srv.Close()

	c := newCollector(t, []config.HAProxyInstance{{Name: "local", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	wantStatus := map[string]float64{"UP": 1, "OPEN": 1, "DOWN": 0, "MAINT": 0, "DRAIN": 0}
	for status, want := range wantStatus {
		m, ok := findMetricWithLabels(ms, "proxy.haproxy.status",
			map[string]string{"svname": status})
		if !ok {
			t.Fatalf("status metric for %q not found", status)
		}
		if m.Value != want {
			t.Fatalf("status %q = %v, want %v", status, m.Value, want)
		}
	}
}
