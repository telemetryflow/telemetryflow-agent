// Package cadvisor_test contains unit tests for the corresponding collector module.
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

package cadvisor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/cadvisor"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

const sampleMetrics = `# HELP container_cpu_usage_seconds_total Cumulative cpu time consumed
# TYPE container_cpu_usage_seconds_total counter
container_cpu_usage_seconds_total{container="web",cpu="cpu0"} 12.5
# HELP machine_memory_bytes Amount of memory installed on the machine
# TYPE machine_memory_bytes gauge
machine_memory_bytes 1.6777216e+07
# HELP go_goroutines Number of goroutines (should be filtered out)
# TYPE go_goroutines gauge
go_goroutines 42
`

func newTestCollector(t *testing.T, cfg config.CAdvisorCollectorConfig) *cadvisor.CAdvisorCollector {
	t.Helper()
	// Point bearer token path to a non-existent file by default so auto-detect
	// does not accidentally pick up a real ServiceAccount token in the env.
	if cfg.BearerTokenPath == "" {
		cfg.BearerTokenPath = filepath.Join(t.TempDir(), "no-token")
	}
	return cadvisor.NewCAdvisorCollector(cfg, zap.NewNop())
}

func TestNewCAdvisorCollector_Defaults(t *testing.T) {
	c := newTestCollector(t, config.CAdvisorCollectorConfig{})
	if c.Name() != "cadvisor" {
		t.Errorf("Name() = %q, want cadvisor", c.Name())
	}
	if c.IsRunning() {
		t.Error("collector should not be running before Start")
	}
}

func TestNewCAdvisorCollector_CustomAndInsecure(t *testing.T) {
	c := newTestCollector(t, config.CAdvisorCollectorConfig{
		Interval:           30 * time.Second,
		Endpoint:           "https://node:10250",
		MetricsPath:        "/metrics/cadvisor",
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
	})
	if c == nil {
		t.Fatal("expected collector")
	}
}

func TestNewCAdvisorCollector_BearerToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("  secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	c := cadvisor.NewCAdvisorCollector(config.CAdvisorCollectorConfig{
		Endpoint:        srv.URL,
		BearerTokenPath: tokenPath,
	}, zap.NewNop())

	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization header = %q, want Bearer secret-token", gotAuth)
	}
}

func TestCollect_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	c := newTestCollector(t, config.CAdvisorCollectorConfig{
		Endpoint: srv.URL + "/", // trailing slash exercises TrimRight
		Labels:   map[string]string{"env": "test"},
	})
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	// container_cpu_usage_seconds_total + machine_memory_bytes = 2, go_goroutines filtered
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
	for _, m := range metrics {
		if m.Labels["env"] != "test" {
			t.Errorf("custom label env missing on %s", m.Name)
		}
	}
}

func TestCollect_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c := newTestCollector(t, config.CAdvisorCollectorConfig{Endpoint: srv.URL})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("expected error on non-200 status")
	}
}

func TestCollect_MalformedMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is { not valid prometheus\n"))
	}))
	defer srv.Close()

	c := newTestCollector(t, config.CAdvisorCollectorConfig{Endpoint: srv.URL})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("expected parse error on malformed metrics")
	}
}

func TestCollect_ConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so the endpoint refuses connections

	c := newTestCollector(t, config.CAdvisorCollectorConfig{Endpoint: url})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("expected scrape error on connection refused")
	}
}

func TestCollect_BadRequestURL(t *testing.T) {
	// A control character in the endpoint makes http.NewRequestWithContext fail.
	c := newTestCollector(t, config.CAdvisorCollectorConfig{Endpoint: "http://\x7f invalid"})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("expected request-creation error")
	}
}

func TestLifecycle_ContextCancel(t *testing.T) {
	c := newTestCollector(t, config.CAdvisorCollectorConfig{})
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	waitRunning(t, c, true)
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Start returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
	waitRunning(t, c, false)
}

func TestLifecycle_Stop(t *testing.T) {
	c := newTestCollector(t, config.CAdvisorCollectorConfig{})

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()
	waitRunning(t, c, true)

	// Second Start while running returns nil immediately.
	if err := c.Start(context.Background()); err != nil {
		t.Errorf("second Start returned %v, want nil", err)
	}

	if err := c.Stop(); err != nil {
		t.Errorf("Stop returned %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned %v after Stop, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}

	// Stop when not running is a no-op.
	if err := c.Stop(); err != nil {
		t.Errorf("Stop on stopped collector returned %v", err)
	}
}

func TestConvertFamilies_AllTypes(t *testing.T) {
	c := &cadvisor.CAdvisorCollector{}
	c.SetConfig(config.CAdvisorCollectorConfig{Labels: map[string]string{"team": "infra"}})
	c.SetLogger(zap.NewNop())

	families := map[string]*dto.MetricFamily{
		"container_untyped": {
			Type:   dto.MetricType_UNTYPED.Enum(),
			Metric: []*dto.Metric{{Untyped: &dto.Untyped{Value: float64Ptr(7)}}},
		},
		"container_summary": {
			Type: dto.MetricType_SUMMARY.Enum(),
			Metric: []*dto.Metric{{Summary: &dto.Summary{
				SampleSum:   float64Ptr(50),
				SampleCount: uint64Ptr(5),
			}}},
		},
		"container_histogram": {
			Type: dto.MetricType_HISTOGRAM.Enum(),
			Metric: []*dto.Metric{{Histogram: &dto.Histogram{
				SampleSum:   float64Ptr(100),
				SampleCount: uint64Ptr(10),
				Bucket: []*dto.Bucket{
					{UpperBound: float64Ptr(0.5), CumulativeCount: uint64Ptr(3)},
					{UpperBound: float64Ptr(1), CumulativeCount: uint64Ptr(10)},
				},
			}}},
		},
	}

	metrics := c.ConvertFamiliesExported(families)

	byName := map[string]int{}
	for _, m := range metrics {
		byName[m.Name]++
		if m.Labels["team"] != "infra" {
			t.Errorf("team label missing on %s", m.Name)
		}
	}
	if byName["container_untyped"] != 1 {
		t.Errorf("untyped count = %d, want 1", byName["container_untyped"])
	}
	if byName["container_summary_sum"] != 1 || byName["container_summary_count"] != 1 {
		t.Errorf("summary sum/count missing: %v", byName)
	}
	if byName["container_histogram_sum"] != 1 || byName["container_histogram_count"] != 1 {
		t.Errorf("histogram sum/count missing: %v", byName)
	}
	if byName["container_histogram_bucket"] != 2 {
		t.Errorf("histogram bucket count = %d, want 2", byName["container_histogram_bucket"])
	}
}

func TestConvertFamilies_NilPayloads(t *testing.T) {
	c := &cadvisor.CAdvisorCollector{}
	c.SetConfig(config.CAdvisorCollectorConfig{})
	c.SetLogger(zap.NewNop())

	// Metrics whose typed payloads are nil should be skipped without panic.
	families := map[string]*dto.MetricFamily{
		"container_c": {Type: dto.MetricType_COUNTER.Enum(), Metric: []*dto.Metric{{}}},
		"container_g": {Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{{}}},
		"container_u": {Type: dto.MetricType_UNTYPED.Enum(), Metric: []*dto.Metric{{}}},
		"container_s": {Type: dto.MetricType_SUMMARY.Enum(), Metric: []*dto.Metric{{}}},
		"container_h": {Type: dto.MetricType_HISTOGRAM.Enum(), Metric: []*dto.Metric{{}}},
	}
	if metrics := c.ConvertFamiliesExported(families); len(metrics) != 0 {
		t.Errorf("expected 0 metrics from nil payloads, got %d", len(metrics))
	}
}

func waitRunning(t *testing.T, c *cadvisor.CAdvisorCollector, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.IsRunning() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("collector IsRunning did not reach %v", want)
}

func uint64Ptr(u uint64) *uint64 { return &u }
