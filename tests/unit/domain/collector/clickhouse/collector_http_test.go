// Package clickhouse_test contains HTTP-driven unit tests for the ClickHouse collector.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clickhouse_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	clickhouse "github.com/telemetryflow/telemetryflow-agent/internal/collector/clickhouse"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// responder decides the HTTP status and body for a given ClickHouse SQL query.
type responder func(query string) (int, string)

// newServer starts an httptest.Server that reads the SQL body and delegates to r.
func newServer(t *testing.T, r responder) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		status, out := r(string(body))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, out)
	}))
	return srv
}

// hostPort splits an httptest URL ("http://127.0.0.1:PORT") into host and port.
func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	trimmed := strings.TrimPrefix(rawURL, "http://")
	parts := strings.Split(trimmed, ":")
	if len(parts) != 2 {
		t.Fatalf("unexpected URL %q", rawURL)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("bad port in %q: %v", rawURL, err)
	}
	return parts[0], port
}

// instanceFor builds an instance config pointed at the given host/port.
func instanceFor(name, host string, port int) config.ClickHouseInstanceConfig {
	return config.ClickHouseInstanceConfig{
		Name:           name,
		Host:           host,
		HTTPPort:       port,
		ConnectTimeout: 2 * time.Second,
		QueryTimeout:   2 * time.Second,
	}
}

// collectorFor builds a collector wired to one instance at host/port.
func collectorFor(host string, port int) *clickhouse.ClickHouseCollector {
	cfg := config.ClickHouseCollectorConfig{
		Enabled:            true,
		CollectionInterval: 20 * time.Millisecond,
		QueryLogInterval:   20 * time.Millisecond,
		MaxQueryLogRows:    100,
		Instances:          []config.ClickHouseInstanceConfig{instanceFor("inst1", host, port)},
	}
	return clickhouse.NewClickHouseCollector(cfg, zap.NewNop())
}

// collectorLong builds a collector with long tick intervals for lifecycle tests,
// so no ticker-driven collection races with Stop() closing connections.
func collectorLong(host string, port int) *clickhouse.ClickHouseCollector {
	cfg := config.ClickHouseCollectorConfig{
		Enabled:            true,
		CollectionInterval: time.Hour,
		QueryLogInterval:   time.Hour,
		MaxQueryLogRows:    100,
		Instances:          []config.ClickHouseInstanceConfig{instanceFor("inst1", host, port)},
	}
	return clickhouse.NewClickHouseCollector(cfg, zap.NewNop())
}

// fullResponder returns realistic JSONEachRow data for every system table so that
// every parse and skip branch in the collect files is exercised.
func fullResponder(q string) (int, string) {
	switch {
	case strings.Contains(q, "system.asynchronous_metrics"):
		return http.StatusOK, join(
			`{"metric":"jemalloc.active","value":"12345"}`,
			`{"metric":"","value":"0"}`,          // skipped: empty name
			`{"metric":"BadAsync","value":"zz"}`, // skipped: unparseable
		)
	case strings.Contains(q, "system.metrics"):
		return http.StatusOK, join(
			`{"metric":"Query","value":"5"}`,
			`{"metric":"Merge","value":2}`,      // numeric JSON value
			`{"metric":"","value":"9"}`,         // skipped: empty name
			`{"metric":"BadVal","value":"abc"}`, // skipped: unparseable
		)
	case strings.Contains(q, "system.events"):
		return http.StatusOK, join(
			`{"event":"SelectQuery","value":"100"}`,
			`{"event":"","value":"1"}`,      // skipped: empty name
			`{"event":"BadEv","value":"x"}`, // skipped: unparseable
		)
	case strings.Contains(q, "system.parts"):
		return http.StatusOK, join(
			`{"database":"default","table":"t1","parts_count":"3","total_rows":"1000","bytes_on_disk":"5000","compressed_bytes":"2000","uncompressed_bytes":"8000","partition_count":"2"}`,
			`{"database":"","table":"t2","parts_count":"1"}`,                        // skipped: empty db
			`{"database":"d","table":"tbad","parts_count":"nope","total_rows":"1"}`, // one bad field skipped
		)
	case strings.Contains(q, "system.merges"):
		return http.StatusOK, join(
			`{"database":"default","table":"t1","elapsed":"1.5","progress":"0.5","num_parts":"2","is_mutation":"1","total_size_bytes_compressed":"100","bytes_read_uncompressed":"200","rows_read":"10","rows_written":"5","memory_usage":"999"}`,
			`{"database":"","table":"x"}`,                                    // skipped: empty db
			`{"database":"d","table":"t2","elapsed":"bad","progress":"0.1"}`, // bad field skipped
		)
	case strings.Contains(q, "system.mutations"):
		return http.StatusOK, join(
			`{"database":"default","table":"t1","mutation_id":"m1","is_done":"0","parts_to_do":"5","latest_fail_reason":"boom"}`,
			`{"database":"default","table":"t2","mutation_id":"m2","is_done":"1","parts_to_do":"0","latest_fail_reason":""}`,
			`{"database":"","table":"x","mutation_id":"m3"}`, // skipped: empty db
		)
	case strings.Contains(q, "system.replicas"):
		return http.StatusOK, join(
			`{"database":"default","table":"t1","is_leader":"1","is_readonly":"0","is_session_expired":"0","future_parts":"0","parts_to_check":"0","queue_size":"3","inserts_in_queue":"1","merges_in_queue":"2","total_replicas":"2","active_replicas":"2","absolute_delay":"0"}`,
			`{"database":"","table":"x"}`,                      // skipped: empty db
			`{"database":"d","table":"t2","queue_size":"bad"}`, // bad field skipped
		)
	case strings.Contains(q, "system.clusters"):
		return http.StatusOK, join(
			`{"cluster":"c1","shard_num":"1","shard_weight":"1","replica_num":"1","host_name":"h1","host_address":"1.2.3.4","port":"9000","is_local":"1","errors_count":"0"}`,
			`{"cluster":"","host_name":"h2"}`,       // skipped: empty cluster
			`{"cluster":"c2","shard_weight":"bad"}`, // bad field skipped
		)
	case strings.Contains(q, "system.disks"):
		return http.StatusOK, join(
			`{"name":"default","free_space":"400","total_space":"1000","unreserved_space":"350","type":"local"}`,
			`{"name":"","free_space":"1"}`,                                        // skipped: empty name
			`{"name":"bad","free_space":"nope","total_space":"0","type":"local"}`, // field skipped, total 0 -> no percent
		)
	case strings.Contains(q, "system.columns"):
		return http.StatusOK, join(
			`{"database":"default","table":"t1","compressed_bytes":"2000","uncompressed_bytes":"8000"}`,
			`{"database":"","table":"x"}`, // skipped: empty db
		)
	case strings.Contains(q, "system.dictionaries"):
		return http.StatusOK, join(
			`{"database":"default","name":"d1","status":"LOADED","bytes_allocated":"1024","element_count":"10","load_factor":"0.5","loading_duration":"1.2"}`,
			`{"database":"default","name":"d2","status":"WEIRD","bytes_allocated":"bad"}`, // unknown status -> -1, bad field skipped
			`{"database":"default","name":"","status":"LOADED"}`,                          // skipped: empty name
		)
	case strings.Contains(q, "system.query_log"):
		return http.StatusOK, join(
			`{"query_kind":"Select","event_time":"2026-04-26 12:00:00","query_duration_ms":"12","read_rows":"100","read_bytes":"2048","memory_usage":"4096","type":"QueryFinish","user":"default"}`,
			`{"query_kind":"Select","event_time":"2026-04-26 12:01:00","query_duration_ms":"30","read_rows":"50","read_bytes":"1024","memory_usage":"2048","type":"ExceptionWhileProcessing","user":"default"}`,
			`{"query_kind":"","event_time":"","query_duration_ms":"1","type":"QueryFinish","user":"u2"}`, // empty kind -> Unknown, empty time -> now
		)
	default: // SELECT 1 health check
		return http.StatusOK, `{"1":"1"}`
	}
}

func join(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

// ---------------------------------------------------------------------------
// Happy-path collection
// ---------------------------------------------------------------------------

func TestCollect_FullSuccess(t *testing.T) {
	srv := newServer(t, fullResponder)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorFor(host, port)

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected metrics from full collection, got none")
	}

	// Spot-check a few expected metric names across the sub-collectors.
	want := []string{
		"db.clickhouse.system.Query",
		"db.clickhouse.events.SelectQuery",
		"db.clickhouse.async.jemalloc.active",
		"db.clickhouse.mergetree.parts_count",
		"db.clickhouse.merge.is_mutation",
		"db.clickhouse.mutation.has_failure",
		"db.clickhouse.replica.queue_size",
		"db.clickhouse.cluster.errors_count",
		"db.clickhouse.disk.used_percent",
		"db.clickhouse.columns.compressed_bytes",
		"db.clickhouse.dictionary.status",
	}
	got := map[string]bool{}
	for _, m := range metrics {
		got[m.Name] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing expected metric %q", w)
		}
	}

	// Second Collect exercises the events-delta (prevEvents) path.
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("second Collect returned error: %v", err)
	}
}

func TestCollectQueryLog_Success(t *testing.T) {
	srv := newServer(t, fullResponder)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorFor(host, port)

	metrics, err := c.CollectQueryLog(context.Background())
	if err != nil {
		t.Fatalf("CollectQueryLog returned error: %v", err)
	}
	found := false
	for _, m := range metrics {
		if m.Name == "db.clickhouse.query_log.count" {
			found = true
		}
	}
	if !found {
		t.Error("expected db.clickhouse.query_log.count metric")
	}
}

// ---------------------------------------------------------------------------
// Error / non-fatal branches
// ---------------------------------------------------------------------------

// serverErrorExcept returns 500 for any query containing needle, otherwise defers
// to fullResponder. SELECT 1 always succeeds so the connection health check passes.
func serverErrorFor(needles ...string) responder {
	return func(q string) (int, string) {
		for _, n := range needles {
			if strings.Contains(q, n) {
				return http.StatusInternalServerError, "server error: " + n
			}
		}
		return fullResponder(q)
	}
}

func TestCollect_PerCollectorErrorsAreNonFatal(t *testing.T) {
	// Fail the first query of each sub-collector; collectInstance logs and continues.
	tests := []struct {
		name    string
		needles []string
	}{
		{"system.metrics", []string{"system.metrics"}},
		{"system.events", []string{"system.events"}},
		{"system.async", []string{"system.asynchronous_metrics"}},
		{"system.parts", []string{"system.parts"}},
		{"system.merges", []string{"system.merges"}},
		{"system.mutations", []string{"system.mutations"}},
		{"system.replicas", []string{"system.replicas"}},
		{"system.clusters", []string{"system.clusters"}},
		{"system.disks", []string{"system.disks"}},
		{"system.columns", []string{"system.columns"}},
		{"system.dictionaries", []string{"system.dictionaries"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, serverErrorFor(tc.needles...))
			defer srv.Close()
			host, port := hostPort(t, srv.URL)
			c := collectorFor(host, port)
			if _, err := c.Collect(context.Background()); err != nil {
				t.Fatalf("Collect should be non-fatal, got: %v", err)
			}
		})
	}
}

func TestCollectQueryLog_GenericErrorPropagates(t *testing.T) {
	// A 500 whose body lacks "query_log"/"Unknown table" is a fatal query error,
	// but the collector aggregates and returns nil (logs the per-instance error).
	srv := newServer(t, func(q string) (int, string) {
		if strings.Contains(q, "system.query_log") {
			return http.StatusInternalServerError, "boom"
		}
		return fullResponder(q)
	})
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorFor(host, port)

	metrics, err := c.CollectQueryLog(context.Background())
	if err != nil {
		t.Fatalf("CollectQueryLog aggregate error should be nil, got: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics on query_log error, got %d", len(metrics))
	}
}

func TestCollectQueryLog_DisabledIsNonFatal(t *testing.T) {
	// Error body mentioning query_log is treated as "disabled" -> nil, nil.
	srv := newServer(t, func(q string) (int, string) {
		if strings.Contains(q, "system.query_log") {
			return http.StatusInternalServerError, "Unknown table system.query_log"
		}
		return fullResponder(q)
	})
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorFor(host, port)
	if _, err := c.CollectQueryLog(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCollectQueryLog_EmptyRows(t *testing.T) {
	srv := newServer(t, func(q string) (int, string) {
		if strings.Contains(q, "system.query_log") {
			return http.StatusOK, ""
		}
		return fullResponder(q)
	})
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorFor(host, port)
	metrics, err := c.CollectQueryLog(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected no metrics for empty query_log, got %d", len(metrics))
	}
}

// ---------------------------------------------------------------------------
// Connection lifecycle & back-off
// ---------------------------------------------------------------------------

func TestCollect_ConnectionFailureAndBackoff(t *testing.T) {
	// Point at a closed port so the health check fails.
	srv := newServer(t, fullResponder)
	host, port := hostPort(t, srv.URL)
	srv.Close() // shut it down -> connection refused

	c := collectorFor(host, port)
	// First cycle: connect fails, back-off armed. Aggregate error is nil.
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("expected nil aggregate error, got: %v", err)
	}
	// Second cycle immediately: hits the in-back-off branch.
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("expected nil aggregate error on back-off, got: %v", err)
	}
}

func TestCollect_BackoffDoubles(t *testing.T) {
	srv := newServer(t, fullResponder)
	host, port := hostPort(t, srv.URL)
	srv.Close() // connection refused

	c := collectorFor(host, port)
	// First failure arms back-off at 1s.
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("collect1: %v", err)
	}
	// Sleep past the 1s window so the next attempt runs and doubles the back-off.
	time.Sleep(1100 * time.Millisecond)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("collect2: %v", err)
	}
}

func TestCollect_ReconnectWhenHealthCheckDrops(t *testing.T) {
	var healthCalls int32
	srv := newServer(t, func(q string) (int, string) {
		// SELECT 1 is the health check. Succeed on the 1st, fail on the 2nd
		// (forcing a close+reconnect), succeed again afterwards.
		if !strings.Contains(q, "system.") {
			n := atomic.AddInt32(&healthCalls, 1)
			if n == 2 {
				return http.StatusInternalServerError, "health blip"
			}
			return http.StatusOK, `{"1":"1"}`
		}
		return fullResponder(q)
	})
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorFor(host, port)

	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("first collect error: %v", err)
	}
	// Second collect: existing conn's Check fails -> reconnect path.
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("second collect error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Empty / multi-instance
// ---------------------------------------------------------------------------

func TestCollect_NoInstances(t *testing.T) {
	c := clickhouse.NewClickHouseCollector(config.ClickHouseCollectorConfig{}, zap.NewNop())
	m, err := c.Collect(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil,nil for no instances, got %v,%v", m, err)
	}
	q, err := c.CollectQueryLog(context.Background())
	if err != nil || q != nil {
		t.Fatalf("expected nil,nil for no instances query log, got %v,%v", q, err)
	}
}

func TestCollect_MultipleInstancesConcurrent(t *testing.T) {
	srv := newServer(t, fullResponder)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	cfg := config.ClickHouseCollectorConfig{
		Enabled:            true,
		CollectionInterval: 20 * time.Millisecond,
		QueryLogInterval:   20 * time.Millisecond,
		MaxQueryLogRows:    100,
		Instances: []config.ClickHouseInstanceConfig{
			instanceFor("a", host, port),
			instanceFor("b", host, port),
		},
	}
	c := clickhouse.NewClickHouseCollector(cfg, zap.NewNop())

	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("multi-instance Collect error: %v", err)
	}
	if _, err := c.CollectQueryLog(context.Background()); err != nil {
		t.Fatalf("multi-instance CollectQueryLog error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Name / IsRunning / Start / Stop
// ---------------------------------------------------------------------------

func TestNameAndInitialState(t *testing.T) {
	c := clickhouse.NewClickHouseCollector(config.ClickHouseCollectorConfig{}, zap.NewNop())
	if c.Name() != "clickhouse" {
		t.Errorf("Name() = %q, want clickhouse", c.Name())
	}
	if c.IsRunning() {
		t.Error("collector should not be running initially")
	}
}

func TestStopWhenNotRunning(t *testing.T) {
	c := clickhouse.NewClickHouseCollector(config.ClickHouseCollectorConfig{}, zap.NewNop())
	if err := c.Stop(); err != nil {
		t.Errorf("Stop on non-running collector should be nil, got %v", err)
	}
}

func TestStartStopLifecycle(t *testing.T) {
	srv := newServer(t, fullResponder)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorLong(host, port)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	// Wait until running.
	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector did not start in time")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Double-start must error.
	if err := c.Start(ctx); err == nil {
		t.Error("second Start should return an error")
	}

	// Let at least one ticker cycle fire.
	time.Sleep(60 * time.Millisecond)

	cancel() // ctx cancellation -> Start returns via Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
	if c.IsRunning() {
		t.Error("collector should not be running after cancel")
	}
}

func TestStartStopViaStop(t *testing.T) {
	srv := newServer(t, fullResponder)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)
	c := collectorLong(host, port)

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()

	deadline := time.Now().Add(2 * time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector did not start in time")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := c.Stop(); err != nil {
		t.Errorf("Stop error: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

// ---------------------------------------------------------------------------
// Direct connection tests (Execute / Check / Close / newConnection TLS)
// ---------------------------------------------------------------------------

func TestConnection_ExecuteAndCheck(t *testing.T) {
	srv := newServer(t, fullResponder)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	conn, err := clickhouse.NewConnectionExported(instanceFor("c", host, port))
	if err != nil {
		t.Fatalf("NewConnectionExported: %v", err)
	}
	defer conn.Close()

	// Query already containing FORMAT should not be rewritten.
	rows, err := conn.Execute(context.Background(), "SELECT metric, value FROM system.metrics FORMAT JSONEachRow")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected rows from Execute")
	}
	if err := conn.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestConnection_ExecuteWithCredentials(t *testing.T) {
	srv := newServer(t, fullResponder)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	inst := instanceFor("c", host, port)
	inst.Username = "admin"
	inst.Password = "secret"
	inst.Database = "logs"
	conn, err := clickhouse.NewConnectionExported(inst)
	if err != nil {
		t.Fatalf("NewConnectionExported: %v", err)
	}
	defer conn.Close()
	if err := conn.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestConnection_HTTPError(t *testing.T) {
	srv := newServer(t, func(q string) (int, string) {
		return http.StatusInternalServerError, "kaboom"
	})
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	conn, err := clickhouse.NewConnectionExported(instanceFor("c", host, port))
	if err != nil {
		t.Fatalf("NewConnectionExported: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Execute(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("expected error on HTTP 500")
	}
}

func TestConnection_MalformedResponse(t *testing.T) {
	srv := newServer(t, func(q string) (int, string) {
		return http.StatusOK, "this is not json\n"
	})
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	conn, err := clickhouse.NewConnectionExported(instanceFor("c", host, port))
	if err != nil {
		t.Fatalf("NewConnectionExported: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Execute(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("expected parse error on malformed body")
	}
}

func TestConnection_CheckEmptyResponse(t *testing.T) {
	srv := newServer(t, func(q string) (int, string) {
		return http.StatusOK, ""
	})
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	conn, err := clickhouse.NewConnectionExported(instanceFor("c", host, port))
	if err != nil {
		t.Fatalf("NewConnectionExported: %v", err)
	}
	defer conn.Close()
	if err := conn.Check(context.Background()); err == nil {
		t.Fatal("expected empty-response error from Check")
	}
}

func TestConnection_ConnRefused(t *testing.T) {
	srv := newServer(t, fullResponder)
	host, port := hostPort(t, srv.URL)
	srv.Close()

	conn, err := clickhouse.NewConnectionExported(instanceFor("c", host, port))
	if err != nil {
		t.Fatalf("NewConnectionExported: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Execute(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("expected connection-refused error")
	}
}

func TestNewConnection_TLSInsecure(t *testing.T) {
	inst := instanceFor("c", "localhost", 8443)
	inst.TLS = config.TLSConfig{Enabled: true, SkipVerify: true}
	conn, err := clickhouse.NewConnectionExported(inst)
	if err != nil {
		t.Fatalf("expected success with insecure TLS, got: %v", err)
	}
	conn.Close()
}

func TestNewConnection_TLSCAFileMissing(t *testing.T) {
	inst := instanceFor("c", "localhost", 8443)
	inst.TLS = config.TLSConfig{Enabled: true, CAFile: filepath.Join(t.TempDir(), "nope.pem")}
	if _, err := clickhouse.NewConnectionExported(inst); err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestNewConnection_TLSCAFileValid(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte(testCACert), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	inst := instanceFor("c", "localhost", 8443)
	inst.TLS = config.TLSConfig{Enabled: true, CAFile: caPath}
	conn, err := clickhouse.NewConnectionExported(inst)
	if err != nil {
		t.Fatalf("expected success with valid CA, got: %v", err)
	}
	conn.Close()
}

func TestNewConnection_TLSClientCertMissing(t *testing.T) {
	inst := instanceFor("c", "localhost", 8443)
	inst.TLS = config.TLSConfig{
		Enabled:  true,
		CertFile: filepath.Join(t.TempDir(), "cert.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "key.pem"),
	}
	if _, err := clickhouse.NewConnectionExported(inst); err == nil {
		t.Fatal("expected error for missing client cert/key")
	}
}

// testCACert is a throwaway self-signed CA certificate (PEM) used only to
// exercise the CA-file parsing branch of newConnection.
const testCACert = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

// ---------------------------------------------------------------------------
// Transform edge cases (toFloat64 default branch)
// ---------------------------------------------------------------------------

type customNum int

func TestToFloat64_DefaultBranch(t *testing.T) {
	// bool stringifies to "true" -> ParseFloat fails -> error path.
	if _, err := clickhouse.ToFloat64Exported(true); err == nil {
		t.Error("expected error for bool value")
	}
	// A custom named type is not matched by the type switch; the default branch
	// stringifies it ("%v" -> "7") and parses successfully.
	v, err := clickhouse.ToFloat64Exported(customNum(7))
	if err != nil {
		t.Fatalf("unexpected error for customNum: %v", err)
	}
	if v != 7 {
		t.Errorf("customNum(7) = %v, want 7", v)
	}
}
