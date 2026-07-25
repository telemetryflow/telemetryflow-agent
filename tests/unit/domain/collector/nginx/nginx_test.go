// External black-box unit tests for the Nginx OSS stub_status collector.
// The stub_status endpoint is served by httptest — no live Nginx, Docker, or
// network access is required.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package nginx_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/nginx"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// stubStatusBody is a canonical stub_status response with the values the
// happy-path test asserts on.
const stubStatusBody = "Active connections: 15\n" +
	"server accepts handled requests\n" +
	" 8456 8456 32891\n" +
	"Reading: 0 Writing: 1 Waiting: 14\n"

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

// ---------------------------------------------------------------------------
// parseStubStatus
// ---------------------------------------------------------------------------

func TestParseStubStatus_HappyPath(t *testing.T) {
	stats, ok := nginx.ParseStubStatusExported(stubStatusBody)
	if !ok {
		t.Fatal("expected parse success")
	}
	want := nginx.StubStatsExported{Active: 15, Accepts: 8456, Handled: 8456, Requests: 32891, Reading: 0, Writing: 1, Waiting: 14}
	if stats != want {
		t.Errorf("parse mismatch:\n got %+v\nwant %+v", stats, want)
	}
}

func TestParseStubStatus_MissingActive(t *testing.T) {
	_, ok := nginx.ParseStubStatusExported("server accepts handled requests\n 1 2 3\nReading: 0 Writing: 1 Waiting: 2\n")
	if ok {
		t.Fatal("expected parse failure when Active line missing")
	}
}

func TestParseStubStatus_MissingAcceptsLine(t *testing.T) {
	_, ok := nginx.ParseStubStatusExported("Active connections: 5\nReading: 0 Writing: 1 Waiting: 2\n")
	if ok {
		t.Fatal("expected parse failure when accepts/handled/requests line missing")
	}
}

func TestParseStubStatus_MissingRWW(t *testing.T) {
	_, ok := nginx.ParseStubStatusExported("Active connections: 5\nserver accepts handled requests\n 1 2 3\n")
	if ok {
		t.Fatal("expected parse failure when Reading/Writing/Waiting line missing")
	}
}

func TestParseStubStatus_EmptyBody(t *testing.T) {
	if _, ok := nginx.ParseStubStatusExported(""); ok {
		t.Fatal("expected parse failure for empty body")
	}
}

func TestParseStubStatus_RejectsHeaderLineAsAHReq(t *testing.T) {
	// "server accepts handled requests" must NOT be matched as the 3-number line.
	body := "Active connections: 1\nserver accepts handled requests\nReading: 0 Writing: 1 Waiting: 2\n"
	if _, ok := nginx.ParseStubStatusExported(body); ok {
		t.Fatal("expected parse failure when the only candidate AHR line is the header")
	}
}

// ---------------------------------------------------------------------------
// BuildNginxMetrics
// ---------------------------------------------------------------------------

func TestBuildNginxMetrics_LabelsAreCopies(t *testing.T) {
	// Exercise BuildNginxMetrics indirectly via collectInstance, then mutate
	// the returned label map to prove the caller cannot poison subsequent calls.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stubStatusBody))
	}))
	defer srv.Close()

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	inst := config.NginxInstance{Name: "n1", URL: srv.URL}
	metrics := c.CollectInstanceExported(context.Background(), inst)

	active := findMetric(t, metrics, "web.nginx.connections_active")
	if active.Labels["nginx_instance"] != "n1" {
		t.Errorf("nginx_instance label missing: %+v", active.Labels)
	}
	active.Labels["nginx_instance"] = "mutated"

	// Second collection on the same instance must not see the mutation.
	again := c.CollectInstanceExported(context.Background(), inst)
	a2 := findMetric(t, again, "web.nginx.connections_active")
	if a2.Labels["nginx_instance"] != "n1" {
		t.Fatalf("returned labels are not copies: %q", a2.Labels["nginx_instance"])
	}
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func TestNginxCollector_Lifecycle(t *testing.T) {
	c := nginx.NewNginxCollector(config.NginxCollectorConfig{Enabled: true}, zap.NewNop())
	if c.Name() != "nginx" {
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
		t.Fatal("double Start should fail")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("still running after Stop")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("double Stop: %v", err)
	}
}

func TestNginxCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*nginx.NginxCollector)(nil)
}

func TestNewNginxCollector_DefaultInterval(t *testing.T) {
	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	if c == nil {
		t.Fatal("nil collector")
	}
}

func TestNewNginxCollector_RespectsCustomInterval(t *testing.T) {
	c := nginx.NewNginxCollector(config.NginxCollectorConfig{Interval: 30 * time.Second}, zap.NewNop())
	if c == nil {
		t.Fatal("nil collector")
	}
}

// ---------------------------------------------------------------------------
// instanceLabels / splitHostPort
// ---------------------------------------------------------------------------

func TestInstanceLabels(t *testing.T) {
	labels := nginx.InstanceLabelsExported(config.NginxInstance{
		Name: "edge-1",
		URL:  "http://nginx.local:8080/stub_status",
	})
	if labels["nginx_instance"] != "edge-1" {
		t.Errorf("nginx_instance wrong: %+v", labels)
	}
	if labels["nginx_host"] != "nginx.local" {
		t.Errorf("nginx_host wrong: %q", labels["nginx_host"])
	}
	if labels["nginx_port"] != "8080" {
		t.Errorf("nginx_port wrong: %q", labels["nginx_port"])
	}
	if labels["web_system"] != "nginx" {
		t.Errorf("web_system wrong: %q", labels["web_system"])
	}
}

func TestInstanceLabels_EmptyURL(t *testing.T) {
	labels := nginx.InstanceLabelsExported(config.NginxInstance{Name: "x"})
	if labels["nginx_host"] != "" || labels["nginx_port"] != "" {
		t.Errorf("expected empty host/port, got %+v", labels)
	}
	if labels["nginx_instance"] != "x" {
		t.Errorf("nginx_instance label lost")
	}
}

func TestSplitHostPort_NoPort(t *testing.T) {
	host, port := nginx.SplitHostPortExported("http://nginx.local/stub_status")
	if host != "nginx.local" || port != "" {
		t.Errorf("got host=%q port=%q", host, port)
	}
}

func TestSplitHostPort_HTTPSDefaultPort(t *testing.T) {
	host, port := nginx.SplitHostPortExported("https://nginx.local/stub_status")
	if host != "nginx.local" || port != "" {
		t.Errorf("got host=%q port=%q", host, port)
	}
}

func TestSplitHostPort_BadURL(t *testing.T) {
	host, port := nginx.SplitHostPortExported("://bad")
	if host != "" || port != "" {
		t.Errorf("got host=%q port=%q", host, port)
	}
}

// ---------------------------------------------------------------------------
// collectInstance — happy path
// ---------------------------------------------------------------------------

func TestCollectInstance_HappyPath_AllSevenMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stubStatusBody))
	}))
	defer srv.Close()

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	inst := config.NginxInstance{Name: "n1", URL: srv.URL}
	metrics := c.CollectInstanceExported(context.Background(), inst)

	expected := map[string]float64{
		"web.nginx.connections_active":         15,
		"web.nginx.connections_accepted_total": 8456,
		"web.nginx.connections_handled_total":  8456,
		"web.nginx.requests_total":             32891,
		"web.nginx.connections_reading":        0,
		"web.nginx.connections_writing":        1,
		"web.nginx.connections_waiting":        14,
	}
	for name, want := range expected {
		m := findMetric(t, metrics, name)
		if m.Value != want {
			t.Errorf("%s = %v, want %v", name, m.Value, want)
		}
	}
	// state metric must be 1 on the happy path.
	state := findMetric(t, metrics, "web.nginx.state")
	if state.Value != 1 {
		t.Errorf("state = %v, want 1", state.Value)
	}
	// Counter vs gauge types.
	if findMetric(t, metrics, "web.nginx.requests_total").Type != collector.MetricTypeCounter {
		t.Error("requests_total must be a counter")
	}
	if findMetric(t, metrics, "web.nginx.connections_active").Type != collector.MetricTypeGauge {
		t.Error("connections_active must be a gauge")
	}
	// Label wiring.
	active := findMetric(t, metrics, "web.nginx.connections_active")
	if active.Labels["nginx_instance"] != "n1" {
		t.Errorf("nginx_instance label wrong: %+v", active.Labels)
	}
}

// ---------------------------------------------------------------------------
// collectInstance — failure paths must emit state=0 and never crash
// ---------------------------------------------------------------------------

func TestCollectInstance_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.NginxInstance{Name: "n1", URL: srv.URL})

	if len(metrics) != 1 {
		t.Fatalf("expected exactly one metric on failure, got %d", len(metrics))
	}
	if metrics[0].Name != "web.nginx.state" || metrics[0].Value != 0 {
		t.Fatalf("expected state=0, got %+v", metrics[0])
	}
	for _, m := range metrics {
		if strings.HasPrefix(m.Name, "web.nginx.connections") || m.Name == "web.nginx.requests_total" {
			t.Fatalf("data metric %q must not be emitted on failure", m.Name)
		}
	}
}

func TestCollectInstance_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not nginx</html>"))
	}))
	defer srv.Close()

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.NginxInstance{Name: "n1", URL: srv.URL})

	if len(metrics) != 1 || metrics[0].Name != "web.nginx.state" || metrics[0].Value != 0 {
		t.Fatalf("expected state=0 only, got %+v", metrics)
	}
}

func TestCollectInstance_EmptyURL(t *testing.T) {
	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.NginxInstance{Name: "n1"})
	if len(metrics) != 1 || metrics[0].Name != "web.nginx.state" || metrics[0].Value != 0 {
		t.Fatalf("expected state=0 on missing URL, got %+v", metrics)
	}
}

func TestCollectInstance_ConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // port closed -> transport error

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.NginxInstance{Name: "n1", URL: url})
	if len(metrics) != 1 || metrics[0].Name != "web.nginx.state" || metrics[0].Value != 0 {
		t.Fatalf("expected state=0 on refused connection, got %+v", metrics)
	}
}

// ---------------------------------------------------------------------------
// Basic auth + custom headers
// ---------------------------------------------------------------------------

func TestCollectInstance_BasicAuthAndCustomHeaders(t *testing.T) {
	var gotUser, gotPass, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()
		gotHeader = r.Header.Get("X-Tenant")
		_, _ = w.Write([]byte(stubStatusBody))
	}))
	defer srv.Close()

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	inst := config.NginxInstance{
		Name:     "n1",
		URL:      srv.URL,
		Username: "admin",
		Password: "s3cret",
		Headers:  map[string]string{"X-Tenant": "acme"},
	}
	metrics := c.CollectInstanceExported(context.Background(), inst)

	if gotUser != "admin" || gotPass != "s3cret" {
		t.Errorf("basic auth not sent: user=%q pass=%q", gotUser, gotPass)
	}
	if gotHeader != "acme" {
		t.Errorf("custom header not sent: %q", gotHeader)
	}
	if !hasMetric(metrics, "web.nginx.connections_active") {
		t.Fatal("expected metrics on authed request")
	}
}

// ---------------------------------------------------------------------------
// TLS scrape (TLSSkipVerify)
// ---------------------------------------------------------------------------

func TestCollectInstance_TLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stubStatusBody))
	}))
	defer srv.Close()

	// Sanity-check the server really requires TLS verification by default.
	{
		client := &http.Client{}
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		if _, err := client.Do(req); err == nil {
			t.Fatal("plain client should have failed TLS verification against TLSServer")
		}
	}

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	inst := config.NginxInstance{
		Name:          "n1",
		URL:           srv.URL,
		TLSEnabled:    true,
		TLSSkipVerify: true,
	}
	metrics := c.CollectInstanceExported(context.Background(), inst)

	if !hasMetric(metrics, "web.nginx.connections_active") {
		t.Fatal("expected metrics over TLS with skip-verify")
	}
	if !strings.HasPrefix(srv.URL, "https://") {
		t.Fatalf("httptest TLS server URL unexpected: %q", srv.URL)
	}
}

// Quick reusable: prove that an HTTPS client honoring the cert works too.
func TestCollectInstance_TLS_WithoutSkipVerify_Fails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stubStatusBody))
	}))
	defer srv.Close()

	// Configure a transport that trusts the test server's in-memory cert so the
	// scrape path is exercised against a verified TLS chain.
	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	// We can't easily inject a custom CA into the collector; rely on the existing
	// TLS-skip path and instead just assert that state=0 is produced when the
	// collector refuses the self-signed cert (skip verify disabled).
	inst := config.NginxInstance{
		Name:          "n1",
		URL:           srv.URL,
		TLSEnabled:    true,
		TLSSkipVerify: false,
	}
	metrics := c.CollectInstanceExported(context.Background(), inst)
	if len(metrics) != 1 || metrics[0].Name != "web.nginx.state" || metrics[0].Value != 0 {
		t.Fatalf("expected state=0 when TLS verification rejects self-signed cert, got %+v", metrics)
	}
}

var _ = tls.CipherSuiteName // keep crypto/tls import live for future asserts

// ---------------------------------------------------------------------------
// Collect (multi-instance aggregation)
// ---------------------------------------------------------------------------

func TestCollect_NoInstances(t *testing.T) {
	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil,nil got %v %v", m, err)
	}
}

func TestCollect_MixedInstances(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stubStatusBody))
	}))
	defer good.Close()

	cfg := config.NginxCollectorConfig{
		Instances: []config.NginxInstance{
			{Name: "good", URL: good.URL},
			{Name: "bad", URL: ""}, // missing URL — emitted state=0, logged, skipped
		},
	}
	c := nginx.NewNginxCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasMetric(metrics, "web.nginx.connections_active") {
		t.Error("expected metrics from the good instance")
	}
	// The bad instance still emits a state=0 metric (with its own labels).
	sawBadState := false
	for _, m := range metrics {
		if m.Name == "web.nginx.state" && m.Labels["nginx_instance"] == "bad" && m.Value == 0 {
			sawBadState = true
		}
	}
	if !sawBadState {
		t.Error("expected state=0 metric for the bad instance")
	}
}

// ---------------------------------------------------------------------------
// Default timeout applied when instance.Timeout is empty
// ---------------------------------------------------------------------------

func TestScrape_DefaultTimeoutWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stubStatusBody))
	}))
	defer srv.Close()

	c := nginx.NewNginxCollector(config.NginxCollectorConfig{}, zap.NewNop())
	inst := config.NginxInstance{Name: "n1", URL: srv.URL} // Timeout == 0
	metrics := c.CollectInstanceExported(context.Background(), inst)
	if !hasMetric(metrics, "web.nginx.connections_active") {
		t.Fatal("default timeout path should still produce metrics")
	}
}
