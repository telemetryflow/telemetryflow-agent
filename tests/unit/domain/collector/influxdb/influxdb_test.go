// External black-box unit tests for the InfluxDB collector. Unexported symbols
// (httpClient / pingVersion / getDebugVars / collectInstance) are reached
// through forwarding wrappers in internal/collector/influxdb/exports.go. The
// InfluxDB /ping and /debug/vars endpoints are served by httptest — no live
// services, Docker, or network access are required.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package influxdb_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/influxdb"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const debugVarsPayload = `{
  "cmdline": ["influxd"],
  "memstats": {"Alloc": 1048576, "Sys": 8388608, "NumGC": 5},
  "httpd": {"req": 100, "reqDurationNs": 5000},
  "query": {"requests": 50, "slowQueries": 0},
  "write": {"pointsWrittenReq": 1000},
  "shard": {"pointsWrittenOK": 1000, "writeFail": 0},
  "subscriber": {"pointsWritten": 1000},
  "gc": {"count": 5}
}`

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

func newServer(t *testing.T, pingHandler, varsHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", pingHandler)
	mux.HandleFunc("/debug/vars", varsHandler)
	return httptest.NewServer(mux)
}

func defaultPingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Influxdb-Version", "2.7.0")
		w.WriteHeader(http.StatusNoContent)
	}
}

func defaultVarsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(debugVarsPayload))
	}
}

// ---------------------------------------------------------------------------
// BuildInfluxDBMetrics
// ---------------------------------------------------------------------------

func TestBuildInfluxDBMetrics_HappyPath(t *testing.T) {
	labels := map[string]string{"influxdb_instance": "i1", "db_system": "influxdb"}
	metrics, err := influxdb.BuildInfluxDBMetrics(labels, []byte(debugVarsPayload))
	if err != nil {
		t.Fatalf("BuildInfluxDBMetrics: %v", err)
	}
	// Selected memstats fields.
	alloc := findMetric(t, metrics, "db.influxdb.mem.alloc_bytes")
	if alloc.Value != 1048576 || alloc.Type != collector.MetricTypeGauge {
		t.Errorf("alloc_bytes wrong: %+v", alloc)
	}
	sys := findMetric(t, metrics, "db.influxdb.mem.sys_bytes")
	if sys.Value != 8388608 || sys.Type != collector.MetricTypeGauge {
		t.Errorf("sys_bytes wrong: %+v", sys)
	}
	numGC := findMetric(t, metrics, "db.influxdb.mem.num_gc")
	if numGC.Value != 5 || numGC.Type != collector.MetricTypeCounter {
		t.Errorf("num_gc wrong: %+v", numGC)
	}
	// Subsystem fields with snake_case names.
	req := findMetric(t, metrics, "db.influxdb.httpd.req")
	if req.Value != 100 {
		t.Errorf("httpd.req wrong: %v", req.Value)
	}
	reqDur := findMetric(t, metrics, "db.influxdb.httpd.req_duration_ns")
	if reqDur.Value != 5000 {
		t.Errorf("httpd.req_duration_ns wrong: %v", reqDur.Value)
	}
	slowQueries := findMetric(t, metrics, "db.influxdb.query.slow_queries")
	if slowQueries.Value != 0 {
		t.Errorf("query.slow_queries wrong: %v", slowQueries.Value)
	}
	shardFail := findMetric(t, metrics, "db.influxdb.shard.write_fail")
	if shardFail.Value != 0 {
		t.Errorf("shard.write_fail wrong: %v", shardFail.Value)
	}
	shardOK := findMetric(t, metrics, "db.influxdb.shard.points_written_ok")
	if shardOK.Value != 1000 {
		t.Errorf("shard.points_written_ok wrong: %v", shardOK.Value)
	}
	gcCount := findMetric(t, metrics, "db.influxdb.gc.count")
	if gcCount.Value != 5 {
		t.Errorf("gc.count wrong: %v", gcCount.Value)
	}
	// cmdline must not produce metrics.
	if hasMetric(metrics, "db.influxdb.cmdline") {
		t.Error("cmdline should not produce metrics")
	}
	// Labels must be deep-copied.
	alloc.Labels["influxdb_instance"] = "mutated"
	if labels["influxdb_instance"] != "i1" {
		t.Error("source labels mutated")
	}
}

func TestBuildInfluxDBMetrics_EmptyJSON(t *testing.T) {
	metrics, err := influxdb.BuildInfluxDBMetrics(map[string]string{}, []byte(`{}`))
	if err != nil {
		t.Fatalf("empty JSON should not error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for empty JSON, got %d", len(metrics))
	}
}

func TestBuildInfluxDBMetrics_MalformedJSON(t *testing.T) {
	_, err := influxdb.BuildInfluxDBMetrics(map[string]string{}, []byte(`{not-json`))
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestBuildInfluxDBMetrics_SkipsNonNumeric(t *testing.T) {
	payload := `{"build": {"version": "2.7.0", "commit": "abc"}, "httpd": {"req": 1}}`
	metrics, err := influxdb.BuildInfluxDBMetrics(map[string]string{}, []byte(payload))
	if err != nil {
		t.Fatalf("BuildInfluxDBMetrics: %v", err)
	}
	if !hasMetric(metrics, "db.influxdb.httpd.req") {
		t.Error("missing httpd.req")
	}
	if hasMetric(metrics, "db.influxdb.build.version") {
		t.Error("string field should be skipped")
	}
}

// ---------------------------------------------------------------------------
// Constructor / lifecycle
// ---------------------------------------------------------------------------

func TestNewInfluxDBCollector_DefaultInterval(t *testing.T) {
	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	if c == nil || c.Name() != "influxdb" {
		t.Fatalf("collector not constructed properly")
	}
}

func TestNewInfluxDBCollector_RespectsCustomInterval(t *testing.T) {
	_ = influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{Interval: 30 * time.Second}, zap.NewNop())
}

func TestInfluxDBCollector_Lifecycle(t *testing.T) {
	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{Enabled: true}, zap.NewNop())
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

func TestInfluxDBCollector_SatisfiesInterface(t *testing.T) {
	var _ collector.Collector = (*influxdb.InfluxDBCollector)(nil)
}

// ---------------------------------------------------------------------------
// Client: pingVersion / getDebugVars
// ---------------------------------------------------------------------------

func TestPingVersion_Success(t *testing.T) {
	srv := newServer(t, defaultPingHandler(), defaultVarsHandler())
	defer srv.Close()
	client := influxdb.NewClientExported(config.InfluxDBInstance{URL: srv.URL})
	if v := client.PingVersion(context.Background()); v != "2.7.0" {
		t.Errorf("version=%q want 2.7.0", v)
	}
}

func TestPingVersion_MissingHeader(t *testing.T) {
	srv := newServer(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
		defaultVarsHandler(),
	)
	defer srv.Close()
	client := influxdb.NewClientExported(config.InfluxDBInstance{URL: srv.URL})
	if v := client.PingVersion(context.Background()); v != "unknown" {
		t.Errorf("version=%q want unknown", v)
	}
}

func TestPingVersion_RequestError(t *testing.T) {
	client := influxdb.NewClientExported(config.InfluxDBInstance{URL: "http://127.0.0.1:0"})
	if v := client.PingVersion(context.Background()); v != "unknown" {
		t.Errorf("version=%q want unknown", v)
	}
}

func TestGetDebugVars_BuildRequestError(t *testing.T) {
	client := influxdb.NewClientExported(config.InfluxDBInstance{URL: "http://exa\x7fmple"})
	if _, _, err := client.GetDebugVars(context.Background()); err == nil {
		t.Fatal("expected build-request error")
	}
}

// ---------------------------------------------------------------------------
// Collect / collectInstance
// ---------------------------------------------------------------------------

func TestCollectInstance_HappyPath(t *testing.T) {
	srv := newServer(t, defaultPingHandler(), defaultVarsHandler())
	defer srv.Close()

	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	inst := config.InfluxDBInstance{Name: "i1", URL: srv.URL}
	metrics := c.CollectInstanceExported(context.Background(), inst)

	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 1 {
		t.Errorf("state should be 1, got %v", state.Value)
	}
	if state.Labels["influxdb_version"] != "2.7.0" {
		t.Errorf("version label wrong: %v", state.Labels["influxdb_version"])
	}
	if state.Labels["influxdb_instance"] != "i1" {
		t.Errorf("instance label wrong: %v", state.Labels["influxdb_instance"])
	}
	if state.Labels["influxdb_host"] == "" {
		t.Error("host label missing")
	}
	if state.Labels["db_system"] != "influxdb" {
		t.Errorf("db_system label wrong: %v", state.Labels["db_system"])
	}
	if !hasMetric(metrics, "db.influxdb.httpd.req") {
		t.Error("missing subsystem metric")
	}
	if !hasMetric(metrics, "db.influxdb.mem.alloc_bytes") {
		t.Error("missing memstats metric")
	}
}

func TestCollectInstance_EmptyJSON(t *testing.T) {
	srv := newServer(t, defaultPingHandler(), func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	defer srv.Close()

	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.InfluxDBInstance{Name: "i1", URL: srv.URL})
	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 1 {
		t.Errorf("state should be 1 for empty JSON, got %v", state.Value)
	}
}

func TestCollectInstance_401(t *testing.T) {
	unauth := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := newServer(t, unauth, unauth)
	defer srv.Close()

	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.InfluxDBInstance{Name: "i1", URL: srv.URL})
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (state=0), got %d", len(metrics))
	}
	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 0 {
		t.Errorf("state should be 0 for 401, got %v", state.Value)
	}
	if state.Labels["influxdb_version"] != "unknown" {
		t.Errorf("version should be unknown on 401, got %v", state.Labels["influxdb_version"])
	}
}

func TestCollectInstance_MalformedJSON(t *testing.T) {
	srv := newServer(t, defaultPingHandler(), func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	})
	defer srv.Close()

	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.InfluxDBInstance{Name: "i1", URL: srv.URL})
	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 0 {
		t.Errorf("state should be 0 for malformed JSON, got %v", state.Value)
	}
}

func TestCollectInstance_ConnectionError(t *testing.T) {
	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	// Port 1 is reserved and refuses connections on most systems.
	metrics := c.CollectInstanceExported(context.Background(),
		config.InfluxDBInstance{Name: "i1", URL: "http://127.0.0.1:1"})
	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 0 {
		t.Errorf("state should be 0 on connection error, got %v", state.Value)
	}
}

func TestCollectInstance_EmptyURL(t *testing.T) {
	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.InfluxDBInstance{Name: "i1"})
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for empty URL, got %d", len(metrics))
	}
}

// ---------------------------------------------------------------------------
// Auth: basic auth (v1) and token auth (v2)
// ---------------------------------------------------------------------------

func TestCollectInstance_BasicAuth(t *testing.T) {
	var sawAuth string
	ping := func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("X-Influxdb-Version", "1.8.0")
		w.WriteHeader(http.StatusNoContent)
	}
	vars := func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"httpd": {"req": 1}}`))
	}
	srv := newServer(t, ping, vars)
	defer srv.Close()

	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	inst := config.InfluxDBInstance{
		Name: "i1", URL: srv.URL,
		Username: "admin", Password: "secret",
	}
	metrics := c.CollectInstanceExported(context.Background(), inst)
	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 1 {
		t.Errorf("state should be 1, got %v", state.Value)
	}
	if !strings.HasPrefix(sawAuth, "Basic ") {
		t.Errorf("expected Basic auth header, got %q", sawAuth)
	}
}

func TestCollectInstance_TokenAuth(t *testing.T) {
	var sawAuth string
	ping := func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("X-Influxdb-Version", "2.7.0")
		w.WriteHeader(http.StatusNoContent)
	}
	vars := func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"httpd": {"req": 1}}`))
	}
	srv := newServer(t, ping, vars)
	defer srv.Close()

	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	inst := config.InfluxDBInstance{
		Name: "i1", URL: srv.URL,
		Token: "mytoken123",
	}
	metrics := c.CollectInstanceExported(context.Background(), inst)
	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 1 {
		t.Errorf("state should be 1, got %v", state.Value)
	}
	if sawAuth != "Token mytoken123" {
		t.Errorf("expected Token auth header, got %q", sawAuth)
	}
}

func TestCollectInstance_AuthRequired_401WithoutCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/ping":
			w.Header().Set("X-Influxdb-Version", "2.7.0")
			w.WriteHeader(http.StatusNoContent)
		case "/debug/vars":
			_, _ = w.Write([]byte(`{"httpd": {"req": 1}}`))
		}
	}))
	defer srv.Close()

	// Without creds: 401 -> state=0
	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	metrics := c.CollectInstanceExported(context.Background(), config.InfluxDBInstance{Name: "i1", URL: srv.URL})
	state := findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 0 {
		t.Errorf("state should be 0 without creds, got %v", state.Value)
	}

	// With token: succeeds
	metrics = c.CollectInstanceExported(context.Background(),
		config.InfluxDBInstance{Name: "i1", URL: srv.URL, Token: "t"})
	state = findMetric(t, metrics, "db.influxdb.state")
	if state.Value != 1 {
		t.Errorf("state should be 1 with token, got %v", state.Value)
	}
}

// ---------------------------------------------------------------------------
// Collect (multi-instance)
// ---------------------------------------------------------------------------

func TestCollect_NoInstances(t *testing.T) {
	c := influxdb.NewInfluxDBCollector(config.InfluxDBCollectorConfig{}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil,nil got %v %v", m, err)
	}
}

func TestCollect_MixedInstances(t *testing.T) {
	srv := newServer(t, defaultPingHandler(), defaultVarsHandler())
	defer srv.Close()

	cfg := config.InfluxDBCollectorConfig{
		Instances: []config.InfluxDBInstance{
			{Name: "good", URL: srv.URL},
			{Name: "bad", URL: ""}, // skipped
		},
	}
	c := influxdb.NewInfluxDBCollector(cfg, zap.NewNop())
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasMetric(metrics, "db.influxdb.state") {
		t.Error("expected state metric from good instance")
	}
	for _, m := range metrics {
		if m.Labels["influxdb_instance"] == "bad" {
			t.Error("bad instance should have been skipped")
		}
	}
}
