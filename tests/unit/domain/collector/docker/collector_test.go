// Package docker_test contains unit tests for the corresponding collector module.
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

package docker_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	containertypes "github.com/moby/moby/api/types/container"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/collector/docker"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// mockEngine emulates the Docker Engine API over a unix socket so the collector
// can be exercised end-to-end without a live daemon.
type mockEngine struct {
	socketPath string
	server     *http.Server

	// handlers keyed by URL path suffix
	listStatus  int
	listBody    string
	statsStatus int
	statsBody   string
}

// startMockEngine spins up an HTTP server bound to a unix socket in the test's
// temp dir and returns the engine plus a cleanup registered with t.Cleanup.
func startMockEngine(t *testing.T, e *mockEngine) *mockEngine {
	t.Helper()

	if e.listStatus == 0 {
		e.listStatus = http.StatusOK
	}
	if e.statsStatus == 0 {
		e.statsStatus = http.StatusOK
	}

	e.socketPath = filepath.Join(shortTempDir(t), "d.sock")

	ln, err := net.Listen("unix", e.socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("API-Version", "1.51")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			w.WriteHeader(e.listStatus)
			_, _ = w.Write([]byte(e.listBody))
		case strings.HasSuffix(r.URL.Path, "/stats"):
			w.WriteHeader(e.statsStatus)
			_, _ = w.Write([]byte(e.statsBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	e.server = &http.Server{Handler: mux}
	go func() { _ = e.server.Serve(ln) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = e.server.Shutdown(ctx)
	})

	return e
}

// shortTempDir creates a temp dir under /tmp with a short path so that unix
// socket paths stay within the OS sun_path limit (104 bytes on macOS).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tfd")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func fullCollectorConfig(socket string) config.DockerCollectorConfig {
	return config.DockerCollectorConfig{
		SocketPath:     socket,
		Interval:       50 * time.Millisecond,
		CollectCPU:     true,
		CollectMemory:  true,
		CollectNetwork: true,
		CollectDiskIO:  true,
		CollectPIDs:    true,
		IncludeStopped: true,
	}
}

func containerSummaries() []containertypes.Summary {
	return []containertypes.Summary{
		{
			ID:    "0123456789abcdef0123456789abcdef",
			Names: []string{"/web-app"},
			Image: "nginx:latest",
			State: "running",
		},
		{ID: "exited1", Names: []string{"/old"}, Image: "busybox", State: "exited"},
		{ID: "dead1", Names: []string{"/zombie"}, Image: "busybox", State: "dead"},
		{ID: "paused1", Names: []string{"/frozen"}, Image: "redis", State: "paused"},
		{ID: "restart1", Names: []string{"/flapping"}, Image: "redis", State: "restarting"},
	}
}

func newFullStats() containertypes.StatsResponse {
	return containertypes.StatsResponse{
		CPUStats: containertypes.CPUStats{
			CPUUsage: containertypes.CPUUsage{
				TotalUsage:        2000000000,
				PercpuUsage:       []uint64{500000000, 500000000},
				UsageInUsermode:   1500000000,
				UsageInKernelmode: 500000000,
			},
			SystemUsage: 10000000000,
			OnlineCPUs:  2,
			ThrottlingData: containertypes.ThrottlingData{
				ThrottledPeriods: 3,
				ThrottledTime:    5000,
			},
		},
		PreCPUStats: containertypes.CPUStats{
			CPUUsage:    containertypes.CPUUsage{TotalUsage: 1000000000},
			SystemUsage: 8000000000,
		},
		MemoryStats: containertypes.MemoryStats{
			Usage:    536870912,
			MaxUsage: 600000000,
			Limit:    1073741824,
			Stats:    map[string]uint64{"inactive_file": 100000000, "rss": 300000000, "cache": 100000000},
		},
		Networks: map[string]containertypes.NetworkStats{
			"eth0": {RxBytes: 1000, TxBytes: 2000},
		},
		BlkioStats: containertypes.BlkioStats{
			IoServiceBytesRecursive: []containertypes.BlkioStatEntry{{Op: "Read", Value: 100}},
			IoServicedRecursive:     []containertypes.BlkioStatEntry{{Op: "Write", Value: 5}},
		},
		PidsStats: containertypes.PidsStats{Current: 42},
	}
}

func newCollectorOrFatal(t *testing.T, cfg config.DockerCollectorConfig) *docker.DockerCollector {
	t.Helper()
	c, err := docker.NewDockerCollector(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewDockerCollector: %v", err)
	}
	t.Cleanup(func() { _ = c.Stop() })
	return c
}

func TestNewDockerCollector_UnreachableDaemon(t *testing.T) {
	// Interval=0 exercises the default-interval branch; a bogus socket path
	// forces a deterministic ping failure with no live daemon.
	cfg := config.DockerCollectorConfig{
		SocketPath: filepath.Join(shortTempDir(t), "nope.sock"),
		Interval:   0,
	}
	c, err := docker.NewDockerCollector(cfg, zap.NewNop())
	if err == nil {
		if c != nil {
			_ = c.Stop()
		}
		t.Fatal("expected error for unreachable daemon, got nil")
	}
	if !strings.Contains(err.Error(), "daemon unreachable") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewDockerCollector_Success(t *testing.T) {
	e := startMockEngine(t, &mockEngine{})
	c := newCollectorOrFatal(t, fullCollectorConfig(e.socketPath))

	if c.Name() != "docker" {
		t.Errorf("Name() = %q, want docker", c.Name())
	}
	if c.IsRunning() {
		t.Error("collector should not be running before Start")
	}
}

func TestCollect_HappyPath(t *testing.T) {
	e := startMockEngine(t, &mockEngine{
		listBody:  mustJSON(t, containerSummaries()),
		statsBody: mustJSON(t, newFullStats()),
	})
	c := newCollectorOrFatal(t, fullCollectorConfig(e.socketPath))

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byName := func(name string) *collector.Metric {
		for i := range metrics {
			if metrics[i].Name == name {
				return &metrics[i]
			}
		}
		return nil
	}

	// State summary: 1 running, 2 stopped (exited+dead), 1 paused, 1 restarting, 5 total.
	if m := byName("container.state.running"); m == nil || m.Value != 1 {
		t.Errorf("state.running wrong: %+v", m)
	}
	if m := byName("container.state.stopped"); m == nil || m.Value != 2 {
		t.Errorf("state.stopped wrong: %+v", m)
	}
	if m := byName("container.state.paused"); m == nil || m.Value != 1 {
		t.Errorf("state.paused wrong: %+v", m)
	}
	if m := byName("container.state.restarting"); m == nil || m.Value != 1 {
		t.Errorf("state.restarting wrong: %+v", m)
	}
	if m := byName("container.state.total"); m == nil || m.Value != 5 {
		t.Errorf("state.total wrong: %+v", m)
	}

	// Per-container stats only for the single running container.
	pids := byName("container.pids.current")
	if pids == nil || pids.Value != 42 {
		t.Errorf("pids.current wrong: %+v", pids)
	}
	// Short-ID truncation to 12 chars.
	if pids.Labels["container_id"] != "0123456789ab" {
		t.Errorf("short id = %q, want 0123456789ab", pids.Labels["container_id"])
	}
	if byName("container.cpu.usage_total") == nil {
		t.Error("missing cpu metrics")
	}
	if byName("container.memory.usage") == nil {
		t.Error("missing memory metrics")
	}
	if byName("container.network.rx_bytes") == nil {
		t.Error("missing network metrics")
	}
	if byName("container.diskio.read_bytes") == nil {
		t.Error("missing diskio metrics")
	}
}

func TestCollect_ExcludedContainerSkipped(t *testing.T) {
	e := startMockEngine(t, &mockEngine{
		listBody:  mustJSON(t, containerSummaries()),
		statsBody: mustJSON(t, newFullStats()),
	})
	cfg := fullCollectorConfig(e.socketPath)
	cfg.ExcludeContainers = []string{"web-.*"}
	c := newCollectorOrFatal(t, cfg)

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for i := range metrics {
		if metrics[i].Name == "container.pids.current" {
			t.Fatal("excluded container should not produce per-container stats")
		}
	}
}

func TestCollect_ListError(t *testing.T) {
	e := startMockEngine(t, &mockEngine{
		listStatus: http.StatusInternalServerError,
		listBody:   `{"message":"boom"}`,
	})
	c := newCollectorOrFatal(t, fullCollectorConfig(e.socketPath))

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error from container list failure")
	}
	if !strings.Contains(err.Error(), "container list") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCollect_StatsError_Continues(t *testing.T) {
	// Running container present, but the stats endpoint fails: Collect should
	// log and continue, still returning the state-summary metrics.
	e := startMockEngine(t, &mockEngine{
		listBody:    mustJSON(t, containerSummaries()),
		statsStatus: http.StatusInternalServerError,
		statsBody:   `{"message":"nope"}`,
	})
	c := newCollectorOrFatal(t, fullCollectorConfig(e.socketPath))

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should not fail on per-container stats error: %v", err)
	}
	for i := range metrics {
		if metrics[i].Name == "container.pids.current" {
			t.Fatal("no per-container stats expected when stats endpoint errors")
		}
	}
	if len(metrics) == 0 {
		t.Fatal("expected state-summary metrics")
	}
}

func TestCollect_StatsDecodeError_Continues(t *testing.T) {
	e := startMockEngine(t, &mockEngine{
		listBody:  mustJSON(t, containerSummaries()),
		statsBody: `{not-valid-json`,
	})
	c := newCollectorOrFatal(t, fullCollectorConfig(e.socketPath))

	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect should not fail on decode error: %v", err)
	}
	for i := range metrics {
		if metrics[i].Name == "container.pids.current" {
			t.Fatal("no per-container stats expected on decode error")
		}
	}
}

func TestLifecycle_StartStop(t *testing.T) {
	e := startMockEngine(t, &mockEngine{})
	c := newCollectorOrFatal(t, fullCollectorConfig(e.socketPath))

	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()

	// Wait for running state.
	deadline := time.Now().Add(time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector did not start")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Starting again while running is a no-op returning nil.
	if err := c.Start(context.Background()); err != nil {
		t.Errorf("second Start returned error: %v", err)
	}

	if err := c.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned %v, want nil after Stop", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not return after Stop")
	}

	if c.IsRunning() {
		t.Error("collector still running after Stop")
	}

	// Stop when already stopped is a no-op.
	if err := c.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestLifecycle_ContextCancel(t *testing.T) {
	e := startMockEngine(t, &mockEngine{})
	c := newCollectorOrFatal(t, fullCollectorConfig(e.socketPath))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	deadline := time.Now().Add(time.Second)
	for !c.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("collector did not start")
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Start returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}
