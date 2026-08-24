// Collector integration tests: drive the poll -> compute -> POST path with a
// fake poller and an httptest ingestion server. No live SNMP device or backend.
//
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Licensed under the Apache License, Version 2.0.
package ifmib_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector/snmp/ifmib"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type fakePoller struct {
	readings []ifmib.InterfaceReading
}

func (f *fakePoller) Poll(ctx context.Context) ([]ifmib.InterfaceReading, error) {
	return f.readings, nil
}

// captureServer records POST requests to the ingestion path.
type captureServer struct {
	mu       sync.Mutex
	paths    []string
	auth     []string
	batches  [][]ifmib.InterfaceSample
	respCode int
}

func (c *captureServer) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Samples []ifmib.InterfaceSample `json:"samples"`
	}
	_ = json.Unmarshal(body, &req)

	c.mu.Lock()
	c.paths = append(c.paths, r.URL.Path)
	c.auth = append(c.auth, r.Header.Get("X-API-Key-ID"))
	c.batches = append(c.batches, req.Samples)
	c.mu.Unlock()

	code := c.respCode
	if code == 0 {
		code = http.StatusNoContent
	}
	w.WriteHeader(code)
}

func newTestCollector(t *testing.T, srvURL string, readings []ifmib.InterfaceReading) *ifmib.Collector {
	t.Helper()
	cfg := config.SNMPInterfaceCollectorConfig{
		Enabled:         true,
		BackendEndpoint: srvURL,
		APIKeyID:        "tfk_test",
		APIKeySecret:    "tfs_test",
		Devices: []config.SNMPInterfaceDevice{
			{DeviceID: "dev-uuid-1", DeviceName: "core-sw", Host: "10.0.0.1", Community: "public"},
		},
	}
	c := ifmib.NewCollector(cfg, nil)
	c.SetPollerFactory(func(_ config.SNMPInterfaceDevice) ifmib.Poller {
		return &fakePoller{readings: readings}
	})
	return c
}

func TestCollect_FirstCycleUtilizationZeroAndPosts(t *testing.T) {
	cap := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	readings := []ifmib.InterfaceReading{
		{IfIndex: 1, IfName: "Gi0/1", IfSpeedBps: 1_000_000_000, InOctets: 1_000_000, OutOctets: 2_000_000, Is64Bit: true, InErrors: 1, OperStatus: "up"},
	}
	c := newTestCollector(t, srv.URL, readings)

	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect cycle 1 error: %v", err)
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.paths) != 1 {
		t.Fatalf("expected 1 POST, got %d", len(cap.paths))
	}
	if cap.paths[0] != "/api/v2/monitoring/network-map/snmp/interface-metrics" {
		t.Errorf("unexpected path %q", cap.paths[0])
	}
	if cap.auth[0] != "tfk_test" {
		t.Errorf("missing API key header, got %q", cap.auth[0])
	}
	s := cap.batches[0]
	if len(s) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(s))
	}
	if s[0].InUtilizationPct != 0 || s[0].OutUtilizationPct != 0 {
		t.Errorf("first-cycle utilization should be 0, got in=%.4f out=%.4f", s[0].InUtilizationPct, s[0].OutUtilizationPct)
	}
	if s[0].DeviceID != "dev-uuid-1" || s[0].IfName != "Gi0/1" || s[0].OperStatus != "up" {
		t.Errorf("sample passthrough mismatch: %+v", s[0])
	}
	if s[0].Timestamp == "" {
		t.Error("timestamp must be set")
	}
}

func TestCollect_SecondCycleComputesUtilization(t *testing.T) {
	cap := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	// Cycle 1 baseline.
	c := newTestCollector(t, srv.URL, []ifmib.InterfaceReading{
		{IfIndex: 1, IfName: "Gi0/1", IfSpeedBps: 1_000_000_000, InOctets: 1_000_000, OutOctets: 2_000_000, Is64Bit: true, OperStatus: "up"},
	})
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("cycle 1 error: %v", err)
	}

	// Cycle 2: identical counters -> zero delta -> utilization stays 0 regardless
	// of elapsed interval (deterministic; exact non-zero math is covered by the
	// pure Utilization unit tests).
	c.SetPollerFactory(func(_ config.SNMPInterfaceDevice) ifmib.Poller {
		return &fakePoller{readings: []ifmib.InterfaceReading{
			{IfIndex: 1, IfName: "Gi0/1", IfSpeedBps: 1_000_000_000, InOctets: 1_000_000, OutOctets: 2_000_000, Is64Bit: true, OperStatus: "up"},
		}}
	})
	time.Sleep(2 * time.Millisecond)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("cycle 2 error: %v", err)
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.batches) != 2 {
		t.Fatalf("expected 2 POSTs, got %d", len(cap.batches))
	}
	s := cap.batches[1][0]
	if s.InUtilizationPct != 0 || s.OutUtilizationPct != 0 {
		t.Errorf("zero-delta utilization should be 0, got in=%.6f out=%.6f", s.InUtilizationPct, s.OutUtilizationPct)
	}
	if s.InUtilizationPct < 0 || s.InUtilizationPct > 100 {
		t.Errorf("utilization out of clamp range: %.6f", s.InUtilizationPct)
	}
}

func TestCollect_NoDevices(t *testing.T) {
	c := ifmib.NewCollector(config.SNMPInterfaceCollectorConfig{Enabled: true}, nil)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("expected nil error with no devices, got %v", err)
	}
}

func TestStartStopLifecycle(t *testing.T) {
	c := ifmib.NewCollector(config.SNMPInterfaceCollectorConfig{Enabled: true}, nil)
	if c.IsRunning() {
		t.Fatal("should not be running before Start")
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !c.IsRunning() {
		t.Fatal("should be running after Start")
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("double Start should error")
	}
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}
	if c.IsRunning() {
		t.Fatal("should not be running after Stop")
	}
}
