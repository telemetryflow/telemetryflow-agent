// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package apache_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/apache"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const happyBody = "Total Accesses: 1234\n" +
	"Total kBytes: 5678\n" +
	"CPULoad: .5\n" +
	"Uptime: 3600\n" +
	"ReqPerSec: .342778\n" +
	"BytesPerSec: 1616.06\n" +
	"BytesPerReq: 4715.85\n" +
	"BusyWorkers: 1\n" +
	"IdleWorkers: 4\n" +
	"Scoreboard: _W____S..\n"

func newCollector(t *testing.T, instances []config.ApacheInstance) *apache.ApacheCollector {
	t.Helper()
	c := apache.NewApacheCollector(config.ApacheCollectorConfig{
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

func mustGet(t *testing.T, metrics []collector.Metric, name string) collector.Metric {
	t.Helper()
	for _, m := range metrics {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("metric %q not found in %d metrics", name, len(metrics))
	return collector.Metric{}
}

func TestHappyPathEmitsAllMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(happyBody))
	}))
	defer srv.Close()

	c := newCollector(t, []config.ApacheInstance{{Name: "ap1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	if state := mustGet(t, ms, "web.apache.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1", state)
	}
	if v := mustGet(t, ms, "web.apache.requests_total").Value; v != 1234 {
		t.Fatalf("requests_total = %v, want 1234", v)
	}
	if v := mustGet(t, ms, "web.apache.bytes_served_total").Value; v != 5678*1024 {
		t.Fatalf("bytes_served_total = %v, want %v", v, 5678*1024)
	}
	if v := mustGet(t, ms, "web.apache.cpu_load").Value; v != 0.5 {
		t.Fatalf("cpu_load = %v, want 0.5", v)
	}
	if v := mustGet(t, ms, "web.apache.uptime_seconds").Value; v != 3600 {
		t.Fatalf("uptime_seconds = %v, want 3600", v)
	}
	if v := mustGet(t, ms, "web.apache.requests_per_second").Value; v != 0.342778 {
		t.Fatalf("requests_per_second = %v, want 0.342778", v)
	}
	if v := mustGet(t, ms, "web.apache.bytes_per_second").Value; v != 1616.06 {
		t.Fatalf("bytes_per_second = %v, want 1616.06", v)
	}
	if v := mustGet(t, ms, "web.apache.bytes_per_request").Value; v != 4715.85 {
		t.Fatalf("bytes_per_request = %v, want 4715.85", v)
	}
	if v := mustGet(t, ms, "web.apache.workers_busy").Value; v != 1 {
		t.Fatalf("workers_busy = %v, want 1", v)
	}
	if v := mustGet(t, ms, "web.apache.workers_idle").Value; v != 4 {
		t.Fatalf("workers_idle = %v, want 4", v)
	}

	// Counter typing for the two cumulative metrics.
	for _, m := range ms {
		if m.Name == "web.apache.requests_total" || m.Name == "web.apache.bytes_served_total" {
			if m.Type != collector.MetricTypeCounter {
				t.Fatalf("%s type = %q, want counter", m.Name, m.Type)
			}
		}
	}

	// Labels propagated.
	m := mustGet(t, ms, "web.apache.uptime_seconds")
	if m.Labels["apache_instance"] != "ap1" {
		t.Fatalf("apache_instance label = %q, want ap1", m.Labels["apache_instance"])
	}
	if m.Labels["apache_host"] == "" {
		t.Fatal("apache_host label should be set")
	}
	if m.Labels["apache_port"] == "" {
		t.Fatal("apache_port label should be set")
	}
}

func Test404ReturnsStateZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newCollector(t, []config.ApacheInstance{{Name: "ap1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "web.apache.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on 404", state)
	}
	// Only the state metric should be emitted on failure.
	if len(ms) != 1 {
		t.Fatalf("expected 1 metric on failure, got %d", len(ms))
	}
}

func TestMalformedBodyReturnsStateZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 500)))
	}))
	defer srv.Close()

	c := newCollector(t, []config.ApacheInstance{{Name: "ap1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "web.apache.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on malformed body", state)
	}
}

func TestScoreboardParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(happyBody))
	}))
	defer srv.Close()

	c := newCollector(t, []config.ApacheInstance{{Name: "ap1", URL: srv.URL}})
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// happyBody Scoreboard "_W____S.." -> waiting:5, sending:1, starting:1, open_slot:2.
	cases := map[string]float64{
		"web.apache.scoreboard_waiting":   5,
		"web.apache.scoreboard_sending":   1,
		"web.apache.scoreboard_starting":  1,
		"web.apache.scoreboard_open_slot": 2,
		"web.apache.scoreboard_logging":   0,
	}
	for name, want := range cases {
		got := mustGet(t, ms, name).Value
		if got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
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
		_, _ = w.Write([]byte(happyBody))
	}))
	defer srv.Close()

	// Wrong credentials -> 401 -> state=0.
	bad := newCollector(t, []config.ApacheInstance{{Name: "ap1", URL: srv.URL, Username: "x", Password: "y"}})
	ms, err := bad.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "web.apache.state").Value; state != 0 {
		t.Fatalf("state = %v, want 0 on auth failure", state)
	}

	// Correct credentials -> state=1.
	good := newCollector(t, []config.ApacheInstance{{Name: "ap1", URL: srv.URL, Username: user, Password: pass}})
	ms, err = good.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if state := mustGet(t, ms, "web.apache.state").Value; state != 1 {
		t.Fatalf("state = %v, want 1 on auth success", state)
	}
}

func TestCollectorLifecycle(t *testing.T) {
	c := apache.NewApacheCollector(config.ApacheCollectorConfig{}, zap.NewNop())
	const wantName = "apache"
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
